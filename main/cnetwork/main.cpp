#include <FL/Fl.H>
#include <FL/Fl_Window.H>
#include <FL/Fl_Box.H>
#include <FL/Fl_Browser.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Secret_Input.H> // Needed for password input
#include <FL/Fl_Return_Button.H>
#include <FL/fl_ask.H> // For fl_input, fl_alert, fl_message, fl_password

#include <iostream>
#include <string>
#include <vector>
#include <cstdio>   // For popen, pclose, fgets
#include <cstdlib>  // For system, exit
#include <fstream>  // For file operations
#include <sstream>  // For string streams
#include <unistd.h> // For geteuid, usleep, pipe, fork, dup2, close, execlp, write
#include <sys/stat.h> // For stat, chmod
#include <algorithm> // for std::find, std::sort
#include <sys/wait.h> // For waitpid
#include <fcntl.h>    // May be needed for pipe flags on some systems, good practice

// --- Configuration ---
const char* WPA_SUPPLICANT_CONF = "/etc/wpa_supplicant/wpa_supplicant.conf";
const char* WPA_SUPPLICANT_SERVICE = "wpa_supplicant"; // Adjust if your service name is different (e.g., on systemd)
const char* DHCP_CLIENT_CMD = "dhcpcd -q -b"; // Quiet, background
const char* DHCP_RELEASE_CMD = "dhcpcd -x";   // Release lease and exit

// --- Globals (Keep minimal) ---
Fl_Window *win = nullptr;
Fl_Box *ethernet_status_box = nullptr;
Fl_Button *enable_eth_button = nullptr;
Fl_Button *disable_eth_button = nullptr;
Fl_Browser *wifi_browser = nullptr;
Fl_Button *rescan_button = nullptr;

std::string ethernet_interface;
std::string wifi_interface;
bool ethernet_connected_dhcp = false; // Track DHCP state explicitly

struct WifiNetwork {
    std::string ssid;
    std::string auth; // "PSK", "NONE", "EAP", etc.
    bool connected = false;
};
std::vector<WifiNetwork> scanned_networks;

// --- Helper Functions ---
// Execute a command and capture its output
std::string executeCommand(const std::string& cmd) {
    std::string result = "";
    char buffer[128];
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        std::cerr << "Error: popen failed for command: " << cmd << std::endl;
        return "";
    }
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    pclose(pipe); // We don't strictly need the exit status here often
    // Trim trailing newline if present
    if (!result.empty() && result.back() == '\n') {
        result.pop_back();
    }
    return result;
}

// Execute a command and return its exit status
int executeCommandStatus(const std::string& cmd) {
    int status = system(cmd.c_str());
     // system() returns -1 on error (fork/exec failure), or shell status
     if (status == -1) {
          perror(("system() failed for command: " + cmd).c_str());
          return -1; // Indicate system() error
     }
    return WEXITSTATUS(status); // Return the actual exit code of the command
}


// Check if a file or directory exists
bool pathExists(const std::string& path) {
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);
}

// Check if an interface is wireless
bool isWifiInterface(const std::string& iface) {
    return pathExists("/sys/class/net/" + iface + "/phy80211");
}

// Get operational state of an interface
std::string getInterfaceOperstate(const std::string& iface) {
    if (iface.empty()) return "unknown";
    std::ifstream state_file("/sys/class/net/" + iface + "/operstate");
    std::string state = "unknown";
    if (state_file.is_open()) {
        std::getline(state_file, state);
        state_file.close();
    }
    // Treat 'lowerlayerdown' as effectively down for our purpose
    if (state == "lowerlayerdown") {
        state = "down";
    }
    return state;
}

// Get currently connected Wifi SSID (if any)
std::string getConnectedSSID(const std::string& iface) {
    if (iface.empty()) return ""; // Avoid running command with empty interface
    std::string cmd = "iw dev " + iface + " link";
    std::string output = executeCommand(cmd);
    size_t ssid_pos = output.find("SSID: ");
    if (ssid_pos != std::string::npos) {
        size_t newline_pos = output.find('\n', ssid_pos);
        if (newline_pos != std::string::npos) {
            return output.substr(ssid_pos + 6, newline_pos - (ssid_pos + 6));
        } else {
             return output.substr(ssid_pos + 6);
        }
    }
    return ""; // Not connected or unable to determine
}


// --- Core Logic Functions ---

void findInterfaces() {
    ethernet_interface.clear();
    wifi_interface.clear();
    ethernet_connected_dhcp = false; // Reset state
    std::string cmd = "ls /sys/class/net";
    std::string output = executeCommand(cmd);
    std::stringstream ss(output);
    std::string iface;

    while (ss >> iface) {
        // More robust filtering of virtual/unwanted interfaces
        if (iface == "lo" ||
            iface.find("docker") != std::string::npos ||
            iface.find("veth") != std::string::npos ||
            iface.find("virbr") != std::string::npos ||
            iface.find("br-") != std::string::npos ||
            iface.find("bond") != std::string::npos ||
            iface.find("dummy") != std::string::npos ||
            iface.find("tun") != std::string::npos ||
            iface.find("tap") != std::string::npos) {
            continue;
        }
        // Check if interface sysfs entry exists before checking operstate
        std::string state_file_path = "/sys/class/net/" + iface + "/operstate";
        if (!pathExists(state_file_path)) continue; // Skip interfaces without operstate


        if (isWifiInterface(iface)) {
            if (wifi_interface.empty()) { // Take the first one found
                wifi_interface = iface;
            }
        } else {
             // Check if it has a carrier (cable plugged in physically, though link might be down)
             // This helps prioritize wired interfaces that are physically present.
             std::string carrier_path = "/sys/class/net/" + iface + "/carrier";
             bool has_carrier = false;
             std::ifstream carrier_file(carrier_path);
             if (carrier_file.is_open()) {
                 int carrier_val = 0;
                 carrier_file >> carrier_val;
                 if (carrier_val == 1) has_carrier = true;
                 carrier_file.close();
             }

             // Prefer the first interface found, but maybe prioritize one with carrier if multiple exist?
             // For simplicity, stick with the first non-wifi interface found.
            if (ethernet_interface.empty()) {
                 ethernet_interface = iface;
            }
        }
    }
    std::cout << "Detected Ethernet: " << (ethernet_interface.empty() ? "None" : ethernet_interface) << std::endl;
    std::cout << "Detected Wi-Fi: " << (wifi_interface.empty() ? "None" : wifi_interface) << std::endl;
}

// Function to check if DHCP client is running for a specific interface
bool isDhcpRunning(const std::string& iface) {
    if (iface.empty()) return false;
    // Use -x to match the exact command name 'dhcpcd'
    // Use -f to match the full command line containing the interface name
    std::string cmd = "pgrep -xf \"dhcpcd.*" + iface + "\"";
    // Use executeCommandStatus to check if pgrep found anything (exit code 0)
    return (executeCommandStatus(cmd) == 0);
}


void updateEthernetStatus(bool run_dhcp_if_up = false) {
    if (!ethernet_status_box || !enable_eth_button || !disable_eth_button) return;

    // Default button states (disabled if no interface)
    enable_eth_button->deactivate();
    disable_eth_button->deactivate();

    if (ethernet_interface.empty()) {
        ethernet_status_box->copy_label("Ethernet: No Wired Interface Found");
        ethernet_status_box->redraw_label();
        return;
    }

    std::string state = getInterfaceOperstate(ethernet_interface);
    std::string label_text;
    bool is_up = (state == "up"); // Only consider 'up' as truly up

    // Check if DHCP client is actually running for this interface, regardless of our tracked state
    bool dhcp_actually_running = isDhcpRunning(ethernet_interface);

    // Synchronize our internal state `ethernet_connected_dhcp` with reality
    if (dhcp_actually_running && !ethernet_connected_dhcp) {
         std::cout << "Detected running DHCP client for " << ethernet_interface << " (external?). Updating state." << std::endl;
         ethernet_connected_dhcp = true;
    } else if (!dhcp_actually_running && ethernet_connected_dhcp) {
         std::cout << "DHCP client for " << ethernet_interface << " is not running. Updating state." << std::endl;
         ethernet_connected_dhcp = false;
    }

    if (is_up) {
        if (run_dhcp_if_up && !ethernet_connected_dhcp) {
             std::cout << "Ethernet interface " << ethernet_interface << " is up. Running DHCP..." << std::endl;
             std::string dhcp_cmd = std::string(DHCP_CLIENT_CMD) + " " + ethernet_interface;
             int dhcp_exit_code = executeCommandStatus(dhcp_cmd);
             usleep(1500000); // Wait 1.5 seconds for DHCP to potentially succeed/fail
             ethernet_connected_dhcp = isDhcpRunning(ethernet_interface); // Re-check if it started

             if (ethernet_connected_dhcp) {
                 label_text = "Ethernet (" + ethernet_interface + "): Connected (DHCP)";
             } else {
                 label_text = "Ethernet (" + ethernet_interface + "): Up (DHCP Failed)";
                 std::cerr << "DHCP command for " << ethernet_interface << " exited with code " << dhcp_exit_code << " and client did not stay running." << std::endl;
             }
        } else if (ethernet_connected_dhcp) {
              // Check IP address for confirmation
              std::string ip_cmd = "ip -4 addr show dev " + ethernet_interface + " scope global | grep inet";
              std::string ip_out = executeCommand(ip_cmd);
              if (!ip_out.empty()) {
                   label_text = "Ethernet (" + ethernet_interface + "): Connected (DHCP)";
              } else {
                  label_text = "Ethernet (" + ethernet_interface + "): Up (DHCP Running, No IP?)";
                  std::cout << "Warning: DHCP client running for " << ethernet_interface << " but no global IP found." << std::endl;
              }
        } else {
            // Just 'up' but no DHCP attempt or previous success tracked
            label_text = "Ethernet (" + ethernet_interface + "): Up (No IP Address)";
        }
        // If up (regardless of DHCP), enable disable button, disable enable button
        enable_eth_button->deactivate();
        disable_eth_button->activate();
    } else { // state is likely "down", "unknown", or "lowerlayerdown"
         label_text = "Ethernet (" + ethernet_interface + "): Down / Disconnected";
         // If DHCP was running or we thought it was, try to release it when going down
         if (ethernet_connected_dhcp || dhcp_actually_running) {
             std::cout << "Ethernet interface is down/disconnected. Releasing DHCP..." << std::endl;
             std::string release_cmd = std::string(DHCP_RELEASE_CMD) + " " + ethernet_interface;
             executeCommandStatus(release_cmd); // Ignore status, best effort
         }
         ethernet_connected_dhcp = false; // Cannot be connected if down
         enable_eth_button->activate();
         disable_eth_button->deactivate();
    }

    ethernet_status_box->copy_label(label_text.c_str());
    ethernet_status_box->redraw_label();
    enable_eth_button->redraw();
    disable_eth_button->redraw();
}

// --- Scan and Connect Wifi Functions ---
void scanWifiNetworks() {
    if (wifi_interface.empty() || !wifi_browser) {
         std::cout << "No Wi-Fi interface or browser widget." << std::endl;
         if (wifi_browser) {
             wifi_browser->clear();
             wifi_browser->add("No Wi-Fi interface detected.");
             wifi_browser->redraw();
         }
        return;
    }

    wifi_browser->clear();
    scanned_networks.clear();
    wifi_browser->add("Scanning...");
    wifi_browser->redraw();
    Fl::check(); // Allow UI update

    std::cout << "Scanning Wi-Fi on " << wifi_interface << "..." << std::endl;

    // Ensure interface is up for scanning
    std::string up_cmd = "ip link set dev " + wifi_interface + " up";
    int ret_up = executeCommandStatus(up_cmd);
     if (ret_up != 0) {
         // Don't print error if it was already up (exit code 2 often means 'RTNETLINK answers: File exists')
         if (ret_up != 2) {
             std::cerr << "Warning: Failed to bring up " << wifi_interface << " for scanning (exit code " << ret_up << "). It might already be up or there's an issue." << std::endl;
         }
     } else {
        usleep(500000); // Small delay only if 'up' command succeeded
     }


    std::string scan_cmd = "iw dev " + wifi_interface + " scan";
    std::string scan_output = executeCommand(scan_cmd);

    std::string connected_ssid = getConnectedSSID(wifi_interface);
    std::cout << "Currently connected to: '" << connected_ssid << "'" << std::endl;

    wifi_browser->clear(); // Clear "Scanning..." message

    std::stringstream ss(scan_output);
    std::string line;
    WifiNetwork current_network;
    current_network.connected = false; // Ensure reset before loop

    while (std::getline(ss, line)) {
         // Trim leading/trailing whitespace for more robust parsing
         line.erase(0, line.find_first_not_of(" \t\n\r\f\v"));
         line.erase(line.find_last_not_of(" \t\n\r\f\v") + 1);
         if (line.empty()) continue; // Skip empty lines

        if (line.rfind("BSS ", 0) == 0) { // Start of a new network block
            // Before starting a new network, save the previous one if valid
            if (!current_network.ssid.empty() && current_network.ssid != "[Hidden Network]") {
                current_network.connected = (!connected_ssid.empty() && current_network.ssid == connected_ssid);
                // Avoid adding duplicates (simple check based on SSID)
                bool found = false;
                for(const auto& net : scanned_networks) {
                    if (net.ssid == current_network.ssid) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                     scanned_networks.push_back(current_network);
                }
            }
            // Reset for the new network found
            current_network = WifiNetwork(); // Use default constructor
            current_network.auth = "NONE"; // Default assumption
            current_network.connected = false;
        } else if (line.rfind("SSID: ", 0) == 0) {
            current_network.ssid = line.substr(6); // Get text after "SSID: "
            // Handle SSIDs that are hidden (empty or contain null bytes)
            if (current_network.ssid.empty() || current_network.ssid.find('\0') != std::string::npos) {
                 current_network.ssid = "[Hidden Network]";
            }
        } else if (line.rfind("capability:", 0) != std::string::npos && line.find("Privacy") != std::string::npos) {
            // A simple check for Privacy capability often indicates WEP/WPA
            if (current_network.auth == "NONE") { // Don't override if we already found PSK etc.
               current_network.auth = "WEP/WPA?"; // Mark as potentially secured
            }
        } else if (line.rfind("RSN:", 0) != std::string::npos || line.rfind("WPA:", 0) != std::string::npos) {
            // More specific check for RSN (WPA2/WPA3) or WPA information blocks
             if (line.find("Auth suites: PSK") != std::string::npos) {
                  current_network.auth = "PSK";
             } else if (line.find("Auth suites: SAE") != std::string::npos) { // WPA3 Personal
                  current_network.auth = "SAE"; // Treat similarly to PSK for connection logic
             } else if (line.find("Auth suites: 802.1x") != std::string::npos) {
                 current_network.auth = "EAP"; // Enterprise
             } else {
                 // Found RSN/WPA block but couldn't parse auth suite? Still likely secured.
                 if (current_network.auth == "NONE" || current_network.auth == "WEP/WPA?") {
                     current_network.auth = "WPA/WPA2/WPA3"; // More generic secured marker
                 }
             }
        } else if (line.rfind("Authentication suites (",0) != std::string::npos){ // Alternative format seen in some `iw` versions
             if (line.find("PSK") != std::string::npos) {
                 if(current_network.auth != "SAE") current_network.auth = "PSK"; // Don't downgrade SAE
            } else if (line.find("SAE") != std::string::npos) {
                 current_network.auth = "SAE";
            } else if (line.find("802.1x") != std::string::npos) {
                 current_network.auth = "EAP"; // Enterprise
            }
        }
    }
    // Add the last network found in the loop
    if (!current_network.ssid.empty() && current_network.ssid != "[Hidden Network]") {
         current_network.connected = (!connected_ssid.empty() && current_network.ssid == connected_ssid);
         // Avoid adding duplicates
        bool found = false;
        for(const auto& net : scanned_networks) {
            if (net.ssid == current_network.ssid) {
                found = true;
                break;
            }
        }
        if (!found) {
            scanned_networks.push_back(current_network);
        }
    }

    if (scanned_networks.empty()) {
        wifi_browser->add("No networks found");
    } else {
        // Sort networks alphabetically by SSID
        std::sort(scanned_networks.begin(), scanned_networks.end(), [](const WifiNetwork& a, const WifiNetwork& b) {
            // Put connected network first, then sort alphabetically
            if (a.connected != b.connected) return a.connected; // true comes before false
            return a.ssid < b.ssid;
        });

        for (const auto& net : scanned_networks) {
            std::string entry = net.ssid;
            if (net.connected) {
                entry += " [Connected]";
            }
            if (net.auth == "PSK") {
                 entry += " (WPA/PSK)";
            } else if (net.auth == "SAE") {
                 entry += " (WPA3/SAE)";
            } else if (net.auth == "NONE") {
                 entry += " (Open)";
            } else if (net.auth == "EAP") {
                 entry += " (WPA/EAP)";
            } else if (net.auth != "NONE") { // Handle WEP/WPA?, WPA/WPA2/WPA3 etc.
                entry += " (" + net.auth + ")";
            }
             wifi_browser->add(entry.c_str());
        }
    }
    wifi_browser->redraw();
}

// Function to reload wpa_supplicant config, preferring wpa_cli
bool reloadWpaSupplicantConfig() {
    std::cout << "Reloading wpa_supplicant configuration for interface " << wifi_interface << "..." << std::endl;
    // Use wpa_cli to reload configuration - safer than restarting the whole service
    std::string reconfigure_cmd = "wpa_cli -i " + wifi_interface + " reconfigure";
    std::cout << "Executing: " << reconfigure_cmd << std::endl;
    int ret_code = executeCommandStatus(reconfigure_cmd);

    if (ret_code == 0) {
        std::cout << "wpa_cli reconfigure successful." << std::endl;
        usleep(500000); // 0.5 seconds wait
        return true;
    } else {
        std::cerr << "wpa_cli reconfigure failed with status " << ret_code << "." << std::endl;
        std::cerr << "Falling back to service restart (less preferable)..." << std::endl;

        // Fallback: Attempt service restart
        std::string restart_cmd;
        if (pathExists("/bin/systemctl")) {
            // Try interface-specific first, then generic
             restart_cmd = "systemctl restart wpa_supplicant@"+wifi_interface+".service";
             std::cout << "Attempting systemd restart: " << restart_cmd << std::endl;
             ret_code = executeCommandStatus(restart_cmd);
             if (ret_code != 0) {
                 std::cout << "Interface-specific service failed, trying generic..." << std::endl;
                 restart_cmd = "systemctl restart wpa_supplicant.service";
                 std::cout << "Attempting systemd restart: " << restart_cmd << std::endl;
                 ret_code = executeCommandStatus(restart_cmd);
             }
        } else if (pathExists("/sbin/rc-service")) {
            restart_cmd = "rc-service " + std::string(WPA_SUPPLICANT_SERVICE) + " restart";
            std::cout << "Attempting OpenRC restart: " << restart_cmd << std::endl;
            ret_code = executeCommandStatus(restart_cmd);
        } else {
            std::cerr << "Error: Cannot determine init system (systemd or OpenRC) and wpa_cli failed." << std::endl;
            return false; // No reliable way to restart found
        }

        if (ret_code == 0) {
            std::cout << "Service restart command executed successfully." << std::endl;
            usleep(1500000); // Wait longer after service restart
            return true;
        } else {
            std::cerr << "Warning: Service restart command failed with status " << ret_code << std::endl;
            return false;
        }
    }
}


void connectToWifi(const WifiNetwork& net, const std::string& psk = "") {
     std::cout << "Attempting to connect to SSID: " << net.ssid << " with auth: " << net.auth << std::endl;

    if (wifi_interface.empty()) {
        fl_alert("Cannot connect: No Wi-Fi interface detected.");
        return;
    }
     if (net.ssid == "[Hidden Network]") {
        fl_alert("Cannot automatically connect to hidden networks detected during scan.");
        return;
    }

    // --- Ensure wpa_supplicant configuration file exists and has basic permissions ---
    bool config_created = false;
    if (!pathExists(WPA_SUPPLICANT_CONF)) {
        std::cout << WPA_SUPPLICANT_CONF << " not found. Creating basic config." << std::endl;
        size_t last_slash = std::string(WPA_SUPPLICANT_CONF).find_last_of('/');
        if(last_slash != std::string::npos) {
            std::string dir_path = std::string(WPA_SUPPLICANT_CONF).substr(0, last_slash);
            if (!pathExists(dir_path)) {
                 std::string mkdir_cmd = "mkdir -p " + dir_path;
                 std::cout << "Creating directory: " << dir_path << std::endl;
                  if (executeCommandStatus(mkdir_cmd) != 0) {
                     std::cerr << "Error: Failed to create directory " << dir_path << std::endl;
                     fl_alert("Error creating configuration directory.");
                     return;
                  }
            }
        }
        std::ofstream basic_conf(WPA_SUPPLICANT_CONF);
        if (basic_conf.is_open()) {
            basic_conf << "ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=wheel\n"; // Adjust GROUP if needed (e.g., netdev)
            basic_conf << "update_config=1\n";
            basic_conf.close();
            if (chmod(WPA_SUPPLICANT_CONF, S_IRUSR | S_IWUSR) != 0) { // 0600
                 perror("chmod failed for new config");
                 std::cerr << "Warning: Could not set permissions on " << WPA_SUPPLICANT_CONF << std::endl;
            }
            std::cout << "Created basic " << WPA_SUPPLICANT_CONF << std::endl;
            config_created = true;
        } else {
            std::cerr << "Error: Could not create basic " << WPA_SUPPLICANT_CONF << std::endl;
             fl_alert("Error: Could not create required configuration file %s.", WPA_SUPPLICANT_CONF);
             return;
        }
    }

    // Ensure correct permissions on existing file (0600 is best practice)
    if (!config_created) {
        if (chmod(WPA_SUPPLICANT_CONF, S_IRUSR | S_IWUSR) != 0) { // 0600
             // Don't print perror if it's just EPERM (we might not own the file)
             if (errno != EPERM) {
                  perror("chmod failed for existing config");
             }
             std::cerr << "Warning: Could not set permissions on " << WPA_SUPPLICANT_CONF << ". Proceeding anyway." << std::endl;
        }
    }


    // --- Generate the network block using wpa_passphrase (safer) or manually ---
    std::string config_entry;
    // Handle PSK (WPA/WPA2) and SAE (WPA3 Personal) which both require a password
    if (net.auth == "PSK" || net.auth == "SAE" || net.auth == "WPA/PSK" || net.auth == "WPA/WPA2" || net.auth == "WPA/WPA2/WPA3" || net.auth == "WEP/WPA?") {
        if (psk.empty()) {
            fl_alert("Password required for %s (%s)", net.ssid.c_str(), net.auth.c_str());
            return;
        }
        // Use wpa_passphrase to securely generate the PSK/passphrase field
        std::string escaped_ssid = net.ssid;
        std::string escaped_psk = psk;
        // Basic escaping for shell: quote wrapping handles most cases, but escape internal quotes/backslashes
        size_t pos = 0;
        while ((pos = escaped_ssid.find_first_of("\\\"", pos)) != std::string::npos) { escaped_ssid.insert(pos, "\\"); pos += 2; }
        pos = 0;
        while ((pos = escaped_psk.find_first_of("\\\"", pos)) != std::string::npos) { escaped_psk.insert(pos, "\\"); pos += 2; }

        std::string cmd = "wpa_passphrase \"" + escaped_ssid + "\" \"" + escaped_psk + "\"";
        std::string passphrase_output = executeCommand(cmd);

        // Parse the output of wpa_passphrase
        std::stringstream ss_pass(passphrase_output);
        std::string line;
        bool in_block = false;
        while (std::getline(ss_pass, line)) {
            line.erase(0, line.find_first_not_of(" \t")); // Trim leading space
            if (line.find("network={") != std::string::npos) in_block = true;
            if (in_block) {
                // Skip comments unless it's the #psk= line which we want to keep
                if (line.rfind("#", 0) == 0 && line.find("#psk=") == std::string::npos) continue;
                // Add key_mgmt=WPA-PSK or key_mgmt=SAE if needed and not present
                if (line.find("}") != std::string::npos) {
                    if (config_entry.find("key_mgmt=") == std::string::npos) {
                        if (net.auth == "SAE") {
                           config_entry += "\tkey_mgmt=SAE\n";
                           // SAE often requires proto=RSN and pairwise=CCMP group=CCMP
                           if (config_entry.find("proto=") == std::string::npos) config_entry += "\tproto=RSN\n";
                           if (config_entry.find("pairwise=") == std::string::npos) config_entry += "\tpairwise=CCMP\n";
                           if (config_entry.find("group=") == std::string::npos) config_entry += "\tgroup=CCMP\n";
                           // Also ieee80211w=2 (required for SAE)
                           if (config_entry.find("ieee80211w=") == std::string::npos) config_entry += "\tieee80211w=2\n";
                        } else { // Assume PSK otherwise
                            config_entry += "\tkey_mgmt=WPA-PSK\n"; // Default to WPA-PSK if unsure
                        }
                    }
                     if (config_entry.find("ssid=") == std::string::npos) { // Ensure SSID is present
                         config_entry += "\tssid=\"" + net.ssid + "\"\n";
                     }
                    config_entry += line + "\n"; // Add the closing brace
                    break; // Block finished
                }
                config_entry += line + "\n";
            }
        }

        // Basic validation of the generated block
        if(config_entry.empty() || (config_entry.find("psk=") == std::string::npos && config_entry.find("passphrase=") == std::string::npos)){
             std::cerr << "Error generating PSK/SAE config block from wpa_passphrase for " << net.ssid << std::endl;
             std::cerr << "wpa_passphrase output was:\n" << passphrase_output << std::endl;
             fl_alert("Error generating secure config for %s. Check system logs.", net.ssid.c_str());
             return;
         }

    } else if (net.auth == "NONE" || net.auth == "Open") { // Open networks
         config_entry = "network={\n";
         config_entry += "\tssid=\"" + net.ssid + "\"\n";
         config_entry += "\tkey_mgmt=NONE\n";
         // Optional: priority=N
         config_entry += "}\n";
    } else if (net.auth == "EAP" || net.auth == "WPA/EAP") {
        fl_alert("Enterprise (EAP/802.1x) networks require manual configuration in %s.", WPA_SUPPLICANT_CONF);
        return;
    } else {
        fl_alert("Unsupported authentication method '%s' for %s", net.auth.c_str(), net.ssid.c_str());
        return;
    }

     std::cout << "Generated/Using config block:\n" << config_entry << std::endl;

    // --- Update wpa_supplicant.conf (Robust replace/append logic) ---
    std::string temp_conf_path = std::string(WPA_SUPPLICANT_CONF) + ".tmp";
    std::ifstream infile(WPA_SUPPLICANT_CONF);
    std::ofstream outfile(temp_conf_path);

    if (!infile.is_open()) {
         std::cerr << "Error: Cannot open " << WPA_SUPPLICANT_CONF << " for reading." << std::endl;
         fl_alert("Error reading configuration file.");
         if (outfile.is_open()) { outfile.close(); remove(temp_conf_path.c_str()); }
         return;
    }
     if (!outfile.is_open()) {
         std::cerr << "Error: Cannot open temporary file " << temp_conf_path << " for writing." << std::endl;
         fl_alert("Error creating temporary configuration file.");
         infile.close();
         return;
     }

    std::string line;
    bool network_block_processed = false;
    bool in_a_network_block = false;
    int brace_level = 0;
    std::stringstream current_block_ss; // To hold the block being examined/copied

    // Process the config file line by line
    while (std::getline(infile, line)) {
        size_t first_char = line.find_first_not_of(" \t");
        std::string trimmed_line = (first_char == std::string::npos) ? "" : line.substr(first_char);

        if (!in_a_network_block && trimmed_line.rfind("network={", 0) == 0) {
            // Start of a new block
            in_a_network_block = true;
            brace_level = 1;
            current_block_ss.str(""); // Clear stream for this block
            current_block_ss << line << "\n";
        } else if (in_a_network_block) {
            current_block_ss << line << "\n";
            // Track braces carefully
            for (char c : line) {
                if (c == '{') brace_level++;
                else if (c == '}') brace_level--;
            }

            if (brace_level <= 0) { // End of the current network block
                in_a_network_block = false;
                std::string block_content = current_block_ss.str();
                 std::string ssid_to_find = "ssid=\"" + net.ssid + "\""; // Exact match needed

                // Check if this block is the one we want to replace (only replace once)
                if (!network_block_processed && block_content.find(ssid_to_find) != std::string::npos) {
                     outfile << config_entry; // Write the NEW block instead of the old one
                     network_block_processed = true;
                     std::cout << "Replaced existing block for SSID: " << net.ssid << std::endl;
                } else {
                    // This is a different network block, keep it.
                    outfile << block_content;
                }
                current_block_ss.str(""); // Clear stream
                if (brace_level < 0) {
                     std::cerr << "Warning: Mismatched braces detected (level=" << brace_level << ") in " << WPA_SUPPLICANT_CONF << ". Correcting level to 0." << std::endl;
                     brace_level = 0; // Reset for safety
                }
            }
        } else {
            // Line is outside any network block (header or comments between blocks), write it directly.
            outfile << line << "\n";
        }
    }
    infile.close(); // Done reading

     // If EOF was reached while inside a block (malformed file)
     if (in_a_network_block) {
         std::cerr << "Warning: EOF reached inside a network block (level=" << brace_level <<"). Writing remaining buffer." << std::endl;
         std::string block_content = current_block_ss.str();
         std::string ssid_to_find = "ssid=\"" + net.ssid + "\"";
         if (!network_block_processed && block_content.find(ssid_to_find) != std::string::npos) {
             outfile << config_entry; // Replace incomplete target block
             network_block_processed = true;
             std::cout << "Replaced existing (incomplete) block for SSID: " << net.ssid << std::endl;
         } else {
             outfile << block_content; // Write the incomplete non-target block
         }
     }

    // If the target network block was never found and replaced, append the new block.
    if (!network_block_processed) {
        outfile << "\n" << config_entry; // Add a newline for separation
        std::cout << "Appended new block for SSID: " << net.ssid << std::endl;
    }

    outfile.close(); // Done writing the temporary file

    // --- Replace original config with temporary file ---
    // Optional: Create backup before replacing
    // std::string backup_path = std::string(WPA_SUPPLICANT_CONF) + ".bak." + std::to_string(time(0));
    // rename(WPA_SUPPLICANT_CONF, backup_path.c_str());

    std::cout << "Replacing " << WPA_SUPPLICANT_CONF << " with new configuration." << std::endl;
    if (rename(temp_conf_path.c_str(), WPA_SUPPLICANT_CONF) != 0) {
        perror("Error renaming temporary config file");
        std::cerr << "Error: Failed to update " << WPA_SUPPLICANT_CONF << std::endl;
        fl_alert("Error updating configuration file. Check permissions and disk space.");
        remove(temp_conf_path.c_str()); // Clean up temp file on failure
        return;
    }
    // Ensure permissions are correct after replacing
    if (chmod(WPA_SUPPLICANT_CONF, S_IRUSR | S_IWUSR) != 0) { // 0600
         if (errno != EPERM) { perror("chmod failed for final config"); }
         std::cerr << "Warning: Could not set final permissions on " << WPA_SUPPLICANT_CONF << std::endl;
    }

    // --- Reload Config and Wait for Association ---
    if (!reloadWpaSupplicantConfig()) {
        std::cerr << "Error: Failed to reload wpa_supplicant configuration after update." << std::endl;
        fl_alert("Failed to reload Wi-Fi configuration. Connection attempt may fail. Try rescanning or restarting the application.");
        // Don't necessarily exit, maybe it will still connect
    }

    std::cout << "Waiting for association with " << net.ssid << " (up to 15 seconds)..." << std::endl;
    bool associated = false;
    for (int i = 0; i < 30; ++i) { // Check every 0.5 seconds for 15 seconds
        if (getConnectedSSID(wifi_interface) == net.ssid) {
            associated = true;
            std::cout << "Associated with " << net.ssid << "." << std::endl;
            break;
        }
        usleep(500000); // 0.5 seconds
        Fl::check(); // Keep UI responsive
    }

    if (!associated) {
         std::cerr << "Warning: Failed to associate with " << net.ssid << " within timeout." << std::endl;
         std::string status_cmd = "wpa_cli -i " + wifi_interface + " status";
         std::string wpa_status = executeCommand(status_cmd);
         std::cerr << "Current wpa_supplicant status:\n" << wpa_status << std::endl;
         // Check for common failure reasons in status
         std::string failure_reason = "Unknown reason.";
         if (wpa_status.find("reason=WRONG_KEY") != std::string::npos) failure_reason = "Incorrect password.";
         else if (wpa_status.find("CTRL-EVENT-SSID-TEMP-DISABLED") != std::string::npos) failure_reason = "Connection temporarily disabled (e.g., too many failed attempts).";
         else if (wpa_status.find("wpa_state=DISCONNECTED") != std::string::npos) failure_reason = "Disconnected.";


         fl_alert("Failed to associate with %s.\n%s\nCheck password, signal, and system logs (e.g., journalctl -u wpa_supplicant).", net.ssid.c_str(), failure_reason.c_str());
         scanWifiNetworks(); // Refresh list
         return;
    }

    // --- Run DHCP ---
    std::cout << "Releasing old DHCP lease (if any) for " << wifi_interface << "..." << std::endl;
    std::string release_cmd = std::string(DHCP_RELEASE_CMD) + " " + wifi_interface;
    executeCommandStatus(release_cmd); // Ignore status, best effort
    usleep(200000); // Small pause

    std::cout << "Running DHCP for " << wifi_interface << "..." << std::endl;
    std::string dhcp_cmd = std::string(DHCP_CLIENT_CMD) + " " + wifi_interface;
    int dhcp_ret_code = executeCommandStatus(dhcp_cmd);
    usleep(2500000); // Wait 2.5 seconds for DHCP

    if (isDhcpRunning(wifi_interface)) {
         std::cout << "DHCP client started successfully." << std::endl;
          std::string ip_cmd = "ip -4 addr show dev " + wifi_interface + " scope global | grep inet";
          std::string ip_out = executeCommand(ip_cmd);
          if (!ip_out.empty()) {
               // Extract IP for display
               std::stringstream ip_ss(ip_out);
               std::string segment;
               std::string ip_addr_str = "IP Assigned";
               if(ip_ss >> segment >> ip_addr_str) { // second word is usually the IP/CIDR
                    ip_addr_str = "IP: " + ip_addr_str;
               }
               std::cout << ip_addr_str << std::endl;
               fl_message("Connected to %s\n%s", net.ssid.c_str(), ip_addr_str.c_str());
          } else {
              std::cout << "Warning: DHCP client running, but couldn't confirm global IP address acquisition." << std::endl;
              fl_message("Connected to %s\n(DHCP running, check IP manually).", net.ssid.c_str());
          }
    } else {
         std::cerr << "DHCP failed for " << wifi_interface << " after connecting to " << net.ssid << " (dhcpcd exit code: " << dhcp_ret_code << ")" << std::endl;
         fl_alert("Connected to %s but DHCP failed.\nCheck DHCP server or client logs.", net.ssid.c_str());
    }

    // Refresh UI
    scanWifiNetworks();
    updateEthernetStatus();
}


// --- FLTK Callbacks ---

void enableEthCb(Fl_Widget*, void*) {
    if (ethernet_interface.empty()) return;
    std::cout << "Enabling Ethernet: " << ethernet_interface << std::endl;
    std::string cmd = "ip link set dev " + ethernet_interface + " up";
    executeCommandStatus(cmd);
    usleep(1000000); // Give it a second to potentially establish link
    updateEthernetStatus(true); // Update status and try DHCP if link is up
}

void disableEthCb(Fl_Widget*, void*) {
    if (ethernet_interface.empty()) return;
    std::cout << "Disabling Ethernet: " << ethernet_interface << std::endl;
    // Release DHCP lease first
    if (ethernet_connected_dhcp || isDhcpRunning(ethernet_interface)) {
        std::string release_cmd = std::string(DHCP_RELEASE_CMD) + " " + ethernet_interface;
        std::cout << "Releasing DHCP for " << ethernet_interface << "..." << std::endl;
        executeCommandStatus(release_cmd);
        usleep(200000);
    }
    // Then take the interface down
    std::string cmd = "ip link set dev " + ethernet_interface + " down";
    executeCommandStatus(cmd);
    usleep(100000);
    ethernet_connected_dhcp = false; // Mark as not connected logically
    updateEthernetStatus(false); // Update status without running DHCP
}

void rescanButtonCb(Fl_Widget*, void*) {
    scanWifiNetworks();
    updateEthernetStatus(); // Also refresh ethernet status
}

void wifiBrowserCb(Fl_Widget* w, void*) {
    Fl_Browser* browser = (Fl_Browser*)w;
    int selected_line = browser->value(); // Get selected line index (1-based)
    if (selected_line <= 0 || selected_line > (int)scanned_networks.size()) {
        return; // No valid selection or out of bounds
    }

    const WifiNetwork& selected_net = scanned_networks[selected_line - 1]; // 0-based index

     std::cout << "Selected network: " << selected_net.ssid << ", Auth: " << selected_net.auth << std::endl;

     if (selected_net.connected) {
         std::cout << "Already connected to " << selected_net.ssid << std::endl;
         int choice = fl_choice("Already connected to '%s'.\nDisconnect?", "Cancel", "Disconnect", nullptr, selected_net.ssid.c_str());
         if (choice == 1) { // Disconnect
             std::cout << "Disconnecting from " << selected_net.ssid << "..." << std::endl;
             // Release DHCP
             std::string release_cmd = std::string(DHCP_RELEASE_CMD) + " " + wifi_interface;
             executeCommandStatus(release_cmd);
             usleep(200000);
             // Use wpa_cli to disconnect (more graceful)
             std::string disconnect_cmd = "wpa_cli -i " + wifi_interface + " disconnect";
             executeCommandStatus(disconnect_cmd);
             // Optional: Disable network in wpa_supplicant? Maybe too aggressive.
             // std::string disable_cmd = "wpa_cli -i " + wifi_interface + " disable_network X"; // Need network ID 'X'
             usleep(500000);
             scanWifiNetworks(); // Refresh list
             updateEthernetStatus();
         }
         return;
     }

    // Handle password requirements for PSK and SAE
    if (selected_net.auth == "PSK" || selected_net.auth == "SAE" || selected_net.auth == "WPA/PSK" || selected_net.auth == "WPA/WPA2" || selected_net.auth == "WPA/WPA2/WPA3" || selected_net.auth == "WEP/WPA?") {
        const char* psk = fl_password("Enter password for\n%s (%s):", "", selected_net.ssid.c_str(), selected_net.auth.c_str());
        if (psk != nullptr) {
             // Basic PSK length check (WPA/WPA2/WPA3 needs 8-63 ASCII chars, or 64 hex)
             size_t len = strlen(psk);
             bool length_ok = (len >= 8 && len <= 63) || len == 64; // 64 allows hex key

             if(len > 0) {
                 if (!length_ok && selected_net.auth != "WEP/WPA?") { // WEP has different lengths, skip check
                     fl_alert("Warning: Password length (%zu) is unusual for %s (expected 8-63 chars or 64 hex). Trying anyway.", len, selected_net.auth.c_str());
                 }
                 connectToWifi(selected_net, std::string(psk));
             } else {
                 std::cout << "Password entry empty, connection aborted." << std::endl;
             }
        } else {
            std::cout << "Password entry cancelled." << std::endl;
        }
    } else if (selected_net.auth == "NONE" || selected_net.auth == "Open") {
        int choice = fl_choice("Connect to open (unsecured) network\n'%s'?", "Cancel", "Connect", nullptr, selected_net.ssid.c_str());
        if (choice == 1) {
             connectToWifi(selected_net);
        } else {
            std::cout << "Connection to open network cancelled." << std::endl;
        }
    } else if (selected_net.auth == "EAP" || selected_net.auth == "WPA/EAP") {
         fl_alert("Enterprise (EAP/802.1x) networks require manual configuration in %s.", WPA_SUPPLICANT_CONF);
    }
    else {
         fl_alert("Connection logic for auth type '%s' not implemented or network is unsupported.", selected_net.auth.c_str());
    }
}

// --- Main ---

int main(int argc, char **argv) {
    // --- Root Check and Sudo Prompt ---
    if (geteuid() != 0) {
        Fl::get_system_colors(); // Initialize colors early

        Fl_Window *pass_win = new Fl_Window(300, 130, "Root Password Required");
        pass_win->begin();
        Fl_Box label(10, 10, 280, 25, "Root privileges required. Enter password:");
        label.align(FL_ALIGN_WRAP);
        Fl_Secret_Input pass_input(10, 40, 280, 25, "Password:");
        pass_input.take_focus();
        Fl_Return_Button ok_btn(110, 80, 80, 30, "OK");
        pass_win->end();

        ok_btn.callback([](Fl_Widget*, void* data) {
            Fl_Window* w = (Fl_Window*)data;
            w->hide(); // Just hide, don't delete here
        }, pass_win);

        pass_win->set_modal();
        pass_win->show();

        // Local event loop for password window
        while (pass_win->shown()) {
            Fl::wait();
        }

        std::string password = pass_input.value();

        // *** FIX: Do NOT explicitly delete pass_win here ***
        // delete pass_win;
        // pass_win = nullptr;
        Fl::flush(); // Process hide events

        if (password.empty()) {
             fl_alert("Password cannot be empty. Exiting.");
             return 1;
        }

        // --- Use sudo -S ---
        int pipefd[2];
        pid_t pid;
        int status;

        if (pipe(pipefd) == -1) {
            perror("pipe");
             fl_alert("Failed to create pipe for sudo. Exiting.");
             return 1;
        }

        pid = fork();
        if (pid == -1) {
            perror("fork");
             close(pipefd[0]); close(pipefd[1]);
             fl_alert("Failed to fork process for sudo. Exiting.");
             return 1;
        }

        if (pid == 0) { // Child: exec sudo
            close(pipefd[1]); // Close write end
            if (dup2(pipefd[0], STDIN_FILENO) == -1) {
                perror("dup2 failed in child");
                close(pipefd[0]); exit(1);
            }
            close(pipefd[0]); // Close original fd

            std::vector<const char*> sudo_args;
            sudo_args.push_back("sudo");
            sudo_args.push_back("-S"); // Read password from stdin
            sudo_args.push_back(argv[0]); // Program itself
            for (int i = 1; i < argc; ++i) { sudo_args.push_back(argv[i]); }
            sudo_args.push_back(nullptr);

            execvp("sudo", const_cast<char* const*>(sudo_args.data()));
            // If execvp returns, it failed
            fprintf(stderr, "Failed to execute sudo. Ensure sudo is installed and in PATH.\n");
            perror("execvp sudo");
            exit(127); // Standard exit code for command not found/exec failure

        } else { // Parent: write password, wait
            close(pipefd[0]); // Close read end

            std::string pass_with_nl = password + "\n";
            ssize_t bytes_written = write(pipefd[1], pass_with_nl.c_str(), pass_with_nl.size());
            close(pipefd[1]); // Close write end (sends EOF to sudo)

            if (bytes_written != (ssize_t)pass_with_nl.size()) {
                 perror("write to pipe failed");
                 // Wait for child anyway
            }

            waitpid(pid, &status, 0);

            if (WIFEXITED(status)) {
                if (WEXITSTATUS(status) == 0) {
                    // Sudo successful, the child (now root) is running. Parent exits.
                    exit(0);
                } else {
                    // Sudo failed (wrong password, command failure, etc.)
                    fl_alert("Authentication failed or sudo error (Code: %d).\nPlease check password/sudo setup.", WEXITSTATUS(status));
                    return 1;
                }
            } else {
                // Sudo terminated abnormally (signal)
                fl_alert("Sudo process terminated unexpectedly. Exiting.");
                return 1;
            }
        }
    } // End of non-root block

    // --- If we reach here, we are running as root ---
    std::cout << "Running with root privileges." << std::endl;

    // --- Initial Setup (as root) ---
    findInterfaces();

    // --- Create Main GUI ---
    Fl::args(argc, argv); // Process FLTK args for the main app
    Fl::get_system_colors();
    Fl::visual(FL_DOUBLE | FL_INDEX);

    win = new Fl_Window(450, 450, "Chrona Network Manager"); // Slightly larger window
    win->begin();

    int current_y = 10;
    ethernet_status_box = new Fl_Box(10, current_y, win->w() - 20, 25, "Ethernet: Initializing...");
    ethernet_status_box->box(FL_UP_BOX);
    ethernet_status_box->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE | FL_ALIGN_CLIP);
    current_y += 35; // More space

    enable_eth_button = new Fl_Button(10, current_y, (win->w() - 30) / 2, 25, "&Enable Ethernet");
    enable_eth_button->callback(enableEthCb);

    disable_eth_button = new Fl_Button(enable_eth_button->x() + enable_eth_button->w() + 10, current_y, (win->w() - 30) / 2, 25, "&Disable Ethernet");
    disable_eth_button->callback(disableEthCb);
    current_y += 40; // More space

    Fl_Box* wifi_label = new Fl_Box(10, current_y, 150, 20, "Available Wi-Fi Networks:");
    wifi_label->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
    current_y += 25;

    int browser_height = win->h() - current_y - 50; // Space for bottom button + padding
    if (browser_height < 100) browser_height = 100; // Min height
    wifi_browser = new Fl_Browser(10, current_y, win->w() - 20, browser_height);
    wifi_browser->type(FL_HOLD_BROWSER);
    wifi_browser->callback(wifiBrowserCb);
    wifi_browser->tooltip("Double-click a network to connect/disconnect");


    rescan_button = new Fl_Button(win->w()/2 - 60, win->h() - 35, 120, 25, "&Rescan Wi-Fi");
    rescan_button->callback(rescanButtonCb);


    win->end();
    win->resizable(wifi_browser); // Browser resizes vertically
    win->size_range(400, 350); // Min size

    // --- Initial State Update ---
    updateEthernetStatus(getInterfaceOperstate(ethernet_interface) == "up"); // Try DHCP only if initially up
    scanWifiNetworks();

    win->show(argc, argv);
    return Fl::run();
}
