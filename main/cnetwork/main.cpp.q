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
#include <unistd.h> // For geteuid, usleep, pipe, fork, dup2, close, execlp
#include <sys/stat.h> // For stat, chmod
#include <algorithm> // for std::find
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
    std::string auth; // "PSK", "NONE", etc.
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
    pclose(pipe);
    // Trim trailing newline if present
    if (!result.empty() && result.back() == '\n') {
        result.pop_back();
    }
    return result;
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
    std::ifstream state_file("/sys/class/net/" + iface + "/operstate");
    std::string state = "unknown";
    if (state_file.is_open()) {
        std::getline(state_file, state);
        state_file.close(); // Good practice to close
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
        if (iface == "lo" || iface.find("docker") != std::string::npos || iface.find("veth") != std::string::npos || iface.find("br-") != std::string::npos) {
            continue;
        }
        // Check if interface is up before considering it potentially useful
        // although operstate might still be down if no cable/wifi connected
        std::string state_file_path = "/sys/class/net/" + iface + "/operstate";
        if (!pathExists(state_file_path)) continue; // Skip interfaces without operstate


        if (isWifiInterface(iface)) {
            if (wifi_interface.empty()) { // Take the first one found
                wifi_interface = iface;
            }
        } else {
            if (ethernet_interface.empty()) { // Take the first one found
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
    // Check for dhcpcd process associated with the interface
    std::string cmd = "pgrep -f \"dhcpcd.*" + iface + "\"";
    std::string pids = executeCommand(cmd);
    return !pids.empty();
}


void updateEthernetStatus(bool run_dhcp_if_up = false) {
    if (!ethernet_status_box) return;

    // Default button states (disabled if no interface)
    if (enable_eth_button) enable_eth_button->deactivate();
    if (disable_eth_button) disable_eth_button->deactivate();

    if (ethernet_interface.empty()) {
        ethernet_status_box->copy_label("Ethernet: No Wired Interface Found");
        ethernet_status_box->redraw_label();
        return;
    }

    std::string state = getInterfaceOperstate(ethernet_interface);
    std::string label_text = "Ethernet (" + ethernet_interface + "): " + state;
    bool is_up = (state == "up" || state == "unknown"); // Treat unknown as potentially up

    if (is_up) {
        // Check if DHCP client is actually running for this interface, even if we didn't start it
        if (!ethernet_connected_dhcp) { // Only check pgrep if we don't already think it's connected
             ethernet_connected_dhcp = isDhcpRunning(ethernet_interface);
             if(ethernet_connected_dhcp) {
                 std::cout << "Detected running DHCP client for " << ethernet_interface << std::endl;
             }
        }

        if (run_dhcp_if_up && !ethernet_connected_dhcp) {
             std::cout << "Ethernet interface " << ethernet_interface << " is up. Running DHCP..." << std::endl;
             std::string dhcp_cmd = std::string(DHCP_CLIENT_CMD) + " " + ethernet_interface;
             int ret = system(dhcp_cmd.c_str());
             // Wait a tiny bit for DHCP to potentially succeed before checking status again
             usleep(500000); // 0.5 seconds
             ethernet_connected_dhcp = isDhcpRunning(ethernet_interface); // Re-check if it started

             if (ethernet_connected_dhcp) {
                 label_text = "Ethernet (" + ethernet_interface + "): Connected (DHCP)";
             } else {
                 label_text = "Ethernet (" + ethernet_interface + "): Up (DHCP Failed?)";
                 std::cerr << "DHCP command failed or client did not stay running for " << ethernet_interface << std::endl;
             }
        } else if (ethernet_connected_dhcp) {
              label_text = "Ethernet (" + ethernet_interface + "): Connected (DHCP)";
        } else {
            // Just 'up' but no DHCP attempt or previous success tracked
            label_text = "Ethernet (" + ethernet_interface + "): Up";
            ethernet_connected_dhcp = false; // Ensure state is false
        }
        // If up (regardless of DHCP), enable disable button, disable enable button
        if (enable_eth_button) enable_eth_button->deactivate();
        if (disable_eth_button) disable_eth_button->activate();
    } else { // state is likely "down"
         label_text = "Ethernet (" + ethernet_interface + "): Down / Disconnected";
         // If DHCP was running, try to release it when going down
         if (ethernet_connected_dhcp) {
             std::cout << "Ethernet interface is down. Releasing DHCP..." << std::endl;
             std::string release_cmd = std::string(DHCP_RELEASE_CMD) + " " + ethernet_interface;
             system(release_cmd.c_str());
         }
         ethernet_connected_dhcp = false; // Cannot be connected if down
         if (enable_eth_button) enable_eth_button->activate();
         if (disable_eth_button) disable_eth_button->deactivate();
    }

    ethernet_status_box->copy_label(label_text.c_str());
    ethernet_status_box->redraw_label();
    if (enable_eth_button) enable_eth_button->redraw();
    if (disable_eth_button) disable_eth_button->redraw();
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
    int ret_up = system(up_cmd.c_str());
     if (WEXITSTATUS(ret_up) != 0) {
         std::cerr << "Warning: Failed to bring up " << wifi_interface << " for scanning." << std::endl;
         // Proceed anyway, iw might still work
     } else {
        usleep(500000); // Small delay only if 'up' command was attempted
     }


    std::string scan_cmd = "iw dev " + wifi_interface + " scan";
    std::string scan_output = executeCommand(scan_cmd);

    std::string connected_ssid = getConnectedSSID(wifi_interface);
    std::cout << "Currently connected to: '" << connected_ssid << "'" << std::endl;

    wifi_browser->clear(); // Clear "Scanning..." message

    std::stringstream ss(scan_output);
    std::string line;
    WifiNetwork current_network;
    current_network.connected = false;

    while (std::getline(ss, line)) {
         // Trim leading/trailing whitespace for more robust parsing
         line.erase(0, line.find_first_not_of(" \t\n\r\f\v"));
         line.erase(line.find_last_not_of(" \t\n\r\f\v") + 1);

        if (line.rfind("BSS ", 0) == 0) { // Check prefix using rfind
            // Before starting a new network, save the previous one if valid
            if (!current_network.ssid.empty()) {
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
        } else if (line.rfind("capability:", 0) != std::string::npos && line.find("Privacy") != std::string::npos) {
            // A simple check for Privacy capability often indicates WEP/WPA
            if (current_network.auth == "NONE") { // Don't override if we already found PSK etc.
               current_network.auth = "WEP/WPA?"; // Mark as potentially secured
            }
        } else if (line.rfind("RSN:", 0) != std::string::npos || line.rfind("WPA:", 0) != std::string::npos) {
            // More specific check for RSN (WPA2) or WPA information blocks
             if (line.find("Auth suites: PSK") != std::string::npos) {
                  current_network.auth = "PSK";
             } else if (line.find("Auth suites: 802.1x") != std::string::npos) {
                 current_network.auth = "EAP"; // Enterprise
             } else {
                 // Found RSN/WPA block but couldn't parse auth suite? Still likely secured.
                 if (current_network.auth == "NONE") current_network.auth = "WPA/WPA2";
             }
        } else if (line.rfind("Authentication suites (",0) != std::string::npos){ // Alternative format seen in some `iw` versions
             if (line.find("PSK") != std::string::npos) {
                current_network.auth = "PSK";
            } else if (line.find("802.1x") != std::string::npos) {
                 current_network.auth = "EAP"; // Enterprise
            }
        }
    }
    // Add the last network found
    if (!current_network.ssid.empty()) {
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
            return a.ssid < b.ssid;
        });

        for (const auto& net : scanned_networks) {
            std::string entry = net.ssid;
            if (net.connected) {
                entry += " [Connected]";
            }
            if (net.auth == "PSK") {
                 entry += " (WPA/PSK)";
            } else if (net.auth == "NONE") {
                 entry += " (Open)";
            } else if (net.auth == "EAP") {
                 entry += " (WPA/EAP)";
            } else if (net.auth != "NONE") { // Handle WEP/WPA?, WPA/WPA2 etc.
                entry += " (" + net.auth + ")";
            }
             wifi_browser->add(entry.c_str());
        }
    }
    wifi_browser->redraw();
}

// Function to restart wpa_supplicant (adapt command if needed)
bool restartWpaSupplicant() {
    // Check for systemd vs OpenRC (simple check)
    std::string restart_cmd;
    if (pathExists("/bin/systemctl")) {
         // Might need more specific service name like wpa_supplicant@<iface>.service sometimes
         restart_cmd = "systemctl restart wpa_supplicant.service";
         // Try interface specific service first? This gets complex. Start simple.
         // Alternative: stop, then start with specific interface
         // system(("systemctl stop wpa_supplicant.service; systemctl start wpa_supplicant@"+wifi_interface+".service").c_str());
         std::cout << "Attempting systemd restart: " << restart_cmd << std::endl;
    } else if (pathExists("/sbin/rc-service")) {
         restart_cmd = "rc-service " + std::string(WPA_SUPPLICANT_SERVICE) + " restart";
         std::cout << "Attempting OpenRC restart: " << restart_cmd << std::endl;
    } else {
        std::cerr << "Error: Cannot determine init system (systemd or OpenRC) to restart wpa_supplicant." << std::endl;
        // Fallback: Try killing and restarting manually (less robust)
        std::string kill_cmd = "pkill wpa_supplicant";
        std::string start_cmd = "wpa_supplicant -B -i " + wifi_interface + " -c " + WPA_SUPPLICANT_CONF;
        std::cout << "Falling back to pkill/manual start..." << std::endl;
        system(kill_cmd.c_str());
        usleep(500000); // Wait after kill
        int ret = system(start_cmd.c_str());
        return (WEXITSTATUS(ret) == 0);
    }

    int ret = system(restart_cmd.c_str());
    if (WEXITSTATUS(ret) != 0) {
        std::cerr << "Warning: Restart command failed with status " << WEXITSTATUS(ret) << std::endl;
        // Maybe try a stop/start?
        if (restart_cmd.find("systemctl") != std::string::npos) {
            std::cout << "Trying systemctl stop/start..." << std::endl;
            system("systemctl stop wpa_supplicant.service");
            usleep(200000);
            ret = system("systemctl start wpa_supplicant.service");
        } else if (restart_cmd.find("rc-service") != std::string::npos) {
             std::cout << "Trying rc-service stop/start..." << std::endl;
             system(("rc-service " + std::string(WPA_SUPPLICANT_SERVICE) + " stop").c_str());
             usleep(200000);
             ret = system(("rc-service " + std::string(WPA_SUPPLICANT_SERVICE) + " start").c_str());
        }
    }
     return (WEXITSTATUS(ret) == 0);
}


void connectToWifi(const WifiNetwork& net, const std::string& psk = "") {
     std::cout << "Attempting to connect to SSID: " << net.ssid << " with auth: " << net.auth << std::endl;

    if (wifi_interface.empty()) {
        fl_alert("Cannot connect: No Wi-Fi interface detected.");
        return;
    }

    // --- Ensure wpa_supplicant configuration file exists and has basic permissions ---
    if (!pathExists(WPA_SUPPLICANT_CONF)) {
        std::cout << WPA_SUPPLICANT_CONF << " not found. Creating basic config." << std::endl;
        // Create parent directory if it doesn't exist
        size_t last_slash = std::string(WPA_SUPPLICANT_CONF).find_last_of('/');
        if(last_slash != std::string::npos) {
            std::string dir_path = std::string(WPA_SUPPLICANT_CONF).substr(0, last_slash);
            if (!pathExists(dir_path)) {
                 std::string mkdir_cmd = "mkdir -p " + dir_path;
                 std::cout << "Creating directory: " << dir_path << std::endl;
                 system(mkdir_cmd.c_str());
            }
        }
        // Create a basic config file
        std::ofstream basic_conf(WPA_SUPPLICANT_CONF);
        if (basic_conf.is_open()) {
            basic_conf << "ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=wheel\n"; // Adjust group if needed
            basic_conf << "update_config=1\n";
            basic_conf.close();
            chmod(WPA_SUPPLICANT_CONF, S_IRUSR | S_IWUSR); // 0600
            std::cout << "Created basic " << WPA_SUPPLICANT_CONF << std::endl;
        } else {
            std::cerr << "Error: Could not create basic " << WPA_SUPPLICANT_CONF << std::endl;
             fl_alert("Error: Could not create required configuration file %s.", WPA_SUPPLICANT_CONF);
             return;
        }
    } else {
         // Ensure correct permissions on existing file (might be overly strict)
         chmod(WPA_SUPPLICANT_CONF, S_IRUSR | S_IWUSR); // 0600
    }


    // --- Generate the network block ---
    std::string config_entry;
    if (net.auth == "PSK" || net.auth == "WPA/PSK" || net.auth == "WPA/WPA2") { // Accept variations
        if (psk.empty()) {
            fl_alert("Password required for %s", net.ssid.c_str());
            return;
        }
        // Use wpa_passphrase to securely generate the PSK field
        std::string cmd = "wpa_passphrase \"" + net.ssid + "\" \"" + psk + "\"";
        std::string passphrase_output = executeCommand(cmd);
        std::stringstream ss(passphrase_output);
        std::string line;
        bool in_network_block = false;
         while (std::getline(ss, line)) {
             // Skip comments and find the network block generated by wpa_passphrase
             if (line.find("#") == 0) continue;
             if (line.find("network={") != std::string::npos) in_network_block = true;
             if (in_network_block) {
                 config_entry += line + "\n";
             }
             // Exit loop once the block is closed
             if (line.find("}") != std::string::npos && in_network_block) break;
         }
         if(config_entry.empty() || config_entry.find("psk=") == std::string::npos){ // Basic check
             std::cerr << "Error generating PSK config block from wpa_passphrase for " << net.ssid << std::endl;
             std::cerr << "wpa_passphrase output:\n" << passphrase_output << std::endl;
             fl_alert("Error generating secure config for %s. Check system logs.", net.ssid.c_str());
             return;
         }

    } else if (net.auth == "NONE" || net.auth == "Open") { // Accept variations
         config_entry = "network={\n";
         config_entry += "\tssid=\"" + net.ssid + "\"\n";
         config_entry += "\tkey_mgmt=NONE\n";
         config_entry += "}\n";
    } else if (net.auth == "EAP" || net.auth == "WPA/EAP") {
        fl_alert("Enterprise (EAP/802.1x) networks require manual configuration in %s.", WPA_SUPPLICANT_CONF);
        return;
    } else {
        fl_alert("Unsupported authentication method '%s' for %s", net.auth.c_str(), net.ssid.c_str());
        return;
    }

     std::cout << "Generated config block:\n" << config_entry << std::endl;

    // --- Update wpa_supplicant.conf (Robust replace/append logic) ---
    std::string temp_conf_path = std::string(WPA_SUPPLICANT_CONF) + ".tmp";
    std::ifstream infile(WPA_SUPPLICANT_CONF);
    std::ofstream outfile(temp_conf_path);

    if (!infile.is_open()) {
         std::cerr << "Error: Cannot open " << WPA_SUPPLICANT_CONF << " for reading." << std::endl;
         fl_alert("Error reading configuration file.");
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
    std::stringstream current_block_ss; // To hold the block being examined

    while (std::getline(infile, line)) {
        // Trim leading whitespace for easier matching
        size_t first_char = line.find_first_not_of(" \t");
        std::string trimmed_line = (first_char == std::string::npos) ? "" : line.substr(first_char);

        if (trimmed_line.rfind("network={", 0) == 0) {
            if (in_a_network_block) {
                 // Error: Nested network blocks? Or file parsing issue. Write previous block.
                 outfile << current_block_ss.str();
            }
            in_a_network_block = true;
            brace_level = 1; // Reset brace level for the new block
            current_block_ss.str(""); // Clear the stream for the new block
            current_block_ss << line << "\n";
        } else if (in_a_network_block) {
            current_block_ss << line << "\n";
            // Track braces to find the end of the block accurately
            for (char c : line) {
                if (c == '{') brace_level++;
                else if (c == '}') brace_level--;
            }

            if (brace_level == 0) { // End of the current network block
                in_a_network_block = false;
                std::string block_content = current_block_ss.str();
                // Check if this block is the one we want to replace
                 std::string ssid_to_find = "ssid=\"" + net.ssid + "\"";
                if (block_content.find(ssid_to_find) != std::string::npos) {
                     // This is the block for our target SSID. Replace it.
                     outfile << config_entry; // Write the NEW block
                     network_block_processed = true; // Mark that we've handled the target network
                     std::cout << "Replaced existing block for SSID: " << net.ssid << std::endl;
                } else {
                    // This is a different network block, keep it.
                    outfile << block_content;
                }
                current_block_ss.str(""); // Clear stream, block is processed
            } else if (brace_level < 0) {
                 // Error: Mismatched braces in config file. Write what we have and stop processing blocks.
                 std::cerr << "Warning: Mismatched braces detected in " << WPA_SUPPLICANT_CONF << ". Writing current block." << std::endl;
                 outfile << current_block_ss.str();
                 in_a_network_block = false; // Assume block ended incorrectly
                 brace_level = 0;
            }
        } else {
            // Line is outside any network block, write it directly.
            outfile << line << "\n";
        }
    }
    infile.close(); // Done reading

     // If we were still inside a block when EOF was reached (malformed file)
     if (in_a_network_block) {
         std::cerr << "Warning: Reached end of file while still inside a network block. Writing remaining buffer." << std::endl;
         outfile << current_block_ss.str();
     }

    // If the target network block was not found and replaced, append the new block.
    if (!network_block_processed) {
        outfile << "\n" << config_entry; // Add a newline for separation
        std::cout << "Appended new block for SSID: " << net.ssid << std::endl;
    }

    outfile.close(); // Done writing the temporary file

    // --- Replace original config with temporary file ---
    std::string backup_path = std::string(WPA_SUPPLICANT_CONF) + ".bak";
    std::cout << "Replacing " << WPA_SUPPLICANT_CONF << " with new configuration." << std::endl;
    // Optional: Create backup
    // rename(WPA_SUPPLICANT_CONF, backup_path.c_str());

    if (rename(temp_conf_path.c_str(), WPA_SUPPLICANT_CONF) != 0) {
        perror("Error renaming temporary config file");
        std::cerr << "Error: Failed to update " << WPA_SUPPLICANT_CONF << std::endl;
        fl_alert("Error updating configuration file.");
        remove(temp_conf_path.c_str()); // Clean up temp file on failure
        return;
    }
    // Ensure permissions are correct after replacing
    chmod(WPA_SUPPLICANT_CONF, S_IRUSR | S_IWUSR); // 0600

    // --- Restart Service and Run DHCP ---
    std::cout << "Restarting wpa_supplicant service..." << std::endl;
    if (!restartWpaSupplicant()) {
         std::cerr << "Warning: wpa_supplicant restart potentially failed. Connection might not establish." << std::endl;
         // Continue anyway, maybe it still worked or was already running correctly
    }


    std::cout << "Waiting for association (up to 10 seconds)..." << std::endl;
    bool associated = false;
    for (int i = 0; i < 20; ++i) { // Check every 0.5 seconds for 10 seconds
        if (getConnectedSSID(wifi_interface) == net.ssid) {
            associated = true;
            std::cout << "Associated with " << net.ssid << "." << std::endl;
            break;
        }
        usleep(500000); // 0.5 seconds
    }

    if (!associated) {
         std::cerr << "Warning: Failed to associate with " << net.ssid << " within timeout." << std::endl;
         // Don't run DHCP if not associated
         fl_alert("Failed to associate with %s. Check password and signal.", net.ssid.c_str());
         scanWifiNetworks(); // Refresh list maybe shows issue
         return;
    }

    // --- Release any old DHCP lease and request a new one ---
    std::cout << "Releasing old DHCP lease (if any) for " << wifi_interface << "..." << std::endl;
    std::string release_cmd = std::string(DHCP_RELEASE_CMD) + " " + wifi_interface;
    system(release_cmd.c_str()); // Okay if this fails (e.g., no lease)
    usleep(200000); // Small pause after release

    std::cout << "Running DHCP for " << wifi_interface << "..." << std::endl;
    std::string dhcp_cmd = std::string(DHCP_CLIENT_CMD) + " " + wifi_interface;
    int dhcp_ret = system(dhcp_cmd.c_str());
    usleep(1000000); // Wait 1 second for DHCP to potentially finish

    if (isDhcpRunning(wifi_interface)) { // Check if client process is running
         std::cout << "Connection successful (DHCP client started)." << std::endl;
         fl_message("Connected to %s", net.ssid.c_str());
         // Optional: Check IP address assignment for confirmation
         // std::string ip_cmd = "ip addr show dev " + wifi_interface + " | grep 'inet '";
         // if (executeCommand(ip_cmd).empty()) { ... warn about no IP ... }
    } else {
         std::cerr << "DHCP failed for " << wifi_interface << " after connecting to " << net.ssid << " (exit code: " << WEXITSTATUS(dhcp_ret) << ")" << std::endl;
         fl_alert("Connected to %s but DHCP failed.", net.ssid.c_str());
    }

    // Refresh the list to show [Connected] status and update ethernet status
    scanWifiNetworks();
    updateEthernetStatus(); // Update ethernet status (maybe wifi connection affected it?)
}


// --- FLTK Callbacks ---

void enableEthCb(Fl_Widget*, void*) {
    if (ethernet_interface.empty()) return;
    std::cout << "Enabling Ethernet: " << ethernet_interface << std::endl;
    std::string cmd = "ip link set dev " + ethernet_interface + " up";
    system(cmd.c_str());
    usleep(500000); // Give it a moment to change state
    // After enabling, try to get DHCP
    updateEthernetStatus(true);
}

void disableEthCb(Fl_Widget*, void*) {
    if (ethernet_interface.empty()) return;
    std::cout << "Disabling Ethernet: " << ethernet_interface << std::endl;
    // Release DHCP lease first, if possible and if we think it's running
    if (ethernet_connected_dhcp || isDhcpRunning(ethernet_interface)) {
        std::string release_cmd = std::string(DHCP_RELEASE_CMD) + " " + ethernet_interface;
        std::cout << "Releasing DHCP for " << ethernet_interface << "..." << std::endl;
        system(release_cmd.c_str());
        usleep(200000); // Brief pause
    }
    // Then take the interface down
    std::string cmd = "ip link set dev " + ethernet_interface + " down";
    system(cmd.c_str());
    usleep(100000); // Brief pause
    ethernet_connected_dhcp = false; // Mark as not connected
    updateEthernetStatus(false); // Update status without running DHCP
}

void rescanButtonCb(Fl_Widget*, void*) {
    scanWifiNetworks();
    updateEthernetStatus(); // Also refresh ethernet status
}

void wifiBrowserCb(Fl_Widget* w, void*) {
    Fl_Browser* browser = (Fl_Browser*)w;
    int selected_line = browser->value(); // Get selected line index (1-based)
    if (selected_line <= 0 || selected_line > scanned_networks.size()) { // Check bounds carefully
        return; // No valid selection or out of bounds
    }

    // Adjust index to be 0-based for vector access
    const WifiNetwork& selected_net = scanned_networks[selected_line - 1];

     std::cout << "Selected network: " << selected_net.ssid << ", Auth: " << selected_net.auth << std::endl;

     // Don't try to reconnect if already connected
     if (selected_net.connected) {
         std::cout << "Already connected to " << selected_net.ssid << std::endl;
         // Maybe offer to disconnect here? For now, do nothing.
         return;
     }

    if (selected_net.auth == "PSK" || selected_net.auth == "WPA/PSK" || selected_net.auth == "WPA/WPA2" || selected_net.auth == "WEP/WPA?") { // Handle secured types
        // Use fl_password for password entry
        const char* psk = fl_password("Enter password for\n%s:", "", selected_net.ssid.c_str());
        if (psk != nullptr) { // Check for NULL (cancel button)
             if(strlen(psk) > 0) { // Only connect if password entered
                connectToWifi(selected_net, std::string(psk));
             } else {
                 std::cout << "Password entry empty, connection aborted." << std::endl;
             }
        } else {
            std::cout << "Password entry cancelled." << std::endl;
        }
    } else if (selected_net.auth == "NONE" || selected_net.auth == "Open") {
        // Ask for confirmation before connecting to open network
        int choice = fl_choice("Connect to open (unsecured) network\n'%s'?", "Cancel", "Connect", nullptr, selected_net.ssid.c_str());
        if (choice == 1) { // 0=Cancel, 1=Connect
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
        // Initialize minimal FLTK needed for the password dialog
        Fl::args(argc, argv);
        Fl::get_system_colors();

        Fl_Window pass_win(300, 130, "Root Password Required");
        pass_win.begin();
        Fl_Box label(10, 10, 280, 25, "Root privileges required. Enter password:");
        label.align(FL_ALIGN_WRAP);
        Fl_Secret_Input pass_input(10, 40, 280, 25, "Password:");
        pass_input.take_focus(); // Set focus to password field
        Fl_Return_Button ok_btn(110, 80, 80, 30, "OK"); // Return button activates on Enter
        pass_win.end();

        // Callback for the OK button using a lambda
        ok_btn.callback([](Fl_Widget*, void* win) {
            ((Fl_Window*)win)->hide(); // Hide the password window to exit the loop
        }, &pass_win);
        pass_win.set_modal(); // Make the window modal
        pass_win.show();

        // Run a local event loop *only* for the password window
        while (pass_win.shown()) {
            Fl::wait();
        }

        std::string password = pass_input.value();
        if (password.empty()) {
            fl_alert("Password cannot be empty. Exiting.");
            return 1;
        }

        // --- Use sudo -S to re-execute the program ---
        int pipefd[2];
        if (pipe(pipefd) == -1) {
            fl_alert("Failed to create pipe for sudo. Exiting.");
            perror("pipe");
            return 1;
        }

        pid_t pid = fork();
        if (pid == -1) {
            fl_alert("Failed to fork process for sudo. Exiting.");
            perror("fork");
            close(pipefd[0]);
            close(pipefd[1]);
            return 1;
        }

        if (pid == 0) { // Child process: Executes sudo
            close(pipefd[1]); // Close the write end of the pipe in the child

            // Redirect stdin to the read end of the pipe
            if (dup2(pipefd[0], STDIN_FILENO) == -1) {
                perror("dup2 failed in child");
                close(pipefd[0]);
                exit(1); // Exit child with error
            }
            close(pipefd[0]); // Close the original pipe fd

            // Construct arguments for execlp
             std::vector<const char*> sudo_args;
             sudo_args.push_back("sudo");
             sudo_args.push_back("-S"); // Read password from stdin
             // Add original arguments passed to the program
             sudo_args.push_back(argv[0]); // The program executable itself
             for (int i = 1; i < argc; ++i) {
                 sudo_args.push_back(argv[i]);
             }
             sudo_args.push_back(nullptr); // Null terminate the argument list

            // Execute sudo -S ./program [original args]
            execvp("sudo", const_cast<char* const*>(sudo_args.data()));

            // If execlp returns, it failed
            fprintf(stderr, "Failed to execute sudo. Ensure sudo is installed and in PATH.\n");
            perror("execvp sudo");
            exit(1); // Exit child with error

        } else { // Parent process: Writes password and waits
            close(pipefd[0]); // Close the read end of the pipe in the parent

            // Write the password followed by a newline to the pipe
            std::string pass_with_nl = password + "\n";
            ssize_t bytes_written = write(pipefd[1], pass_with_nl.c_str(), pass_with_nl.size());
            close(pipefd[1]); // Close the write end, signaling EOF to sudo

            if (bytes_written != (ssize_t)pass_with_nl.size()) {
                 perror("write to pipe failed");
                 // Don't alert here, wait for sudo result
            }

            // Wait for the child process (sudo) to complete
            int status;
            waitpid(pid, &status, 0);

            // Check the exit status of sudo
            if (WIFEXITED(status)) {
                if (WEXITSTATUS(status) == 0) {
                    // Sudo was successful, the new process is running as root.
                    // The parent process can now exit cleanly.
                    exit(0);
                } else {
                    // Sudo failed (e.g., wrong password)
                    fl_alert("Authentication failed or sudo error (Code: %d).\nPlease check your password and try again.", WEXITSTATUS(status));
                    return 1; // Exit parent with error
                }
            } else {
                // Sudo process terminated abnormally
                fl_alert("Sudo process did not exit normally. Exiting.");
                return 1; // Exit parent with error
            }
        }
    }

    // --- If we reach here, we are running as root ---
    std::cout << "Running with root privileges." << std::endl;

    // --- Initial Setup (as root) ---
    findInterfaces(); // Find available network interfaces

    // --- Create Main GUI ---
    // Initialize FLTK fully now that we are root and launching the main app
    Fl::args(argc, argv); // Process FLTK arguments
    Fl::get_system_colors(); // Load theme/colors
    Fl::visual(FL_DOUBLE | FL_INDEX); // Use double buffering

    win = new Fl_Window(400, 400, "Chrona Network Manager");
    win->begin();

    int current_y = 10;
    ethernet_status_box = new Fl_Box(10, current_y, 380, 25, "Ethernet: Initializing...");
    ethernet_status_box->box(FL_UP_BOX); // Give it a slight border
    ethernet_status_box->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE | FL_ALIGN_CLIP);
    current_y += 30; // Space below box

    enable_eth_button = new Fl_Button(10, current_y, 185, 25, "Enable Ethernet");
    enable_eth_button->callback(enableEthCb);

    disable_eth_button = new Fl_Button(205, current_y, 185, 25, "Disable Ethernet");
    disable_eth_button->callback(disableEthCb);
    current_y += 35; // Space below buttons

    // Label for Wi-Fi section
    Fl_Box* wifi_label = new Fl_Box(10, current_y, 150, 20, "Wi-Fi Networks:");
    wifi_label->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
    current_y += 20; // Space below label

    wifi_browser = new Fl_Browser(10, current_y, 380, win->h() - current_y - 50); // Adjusted height calculation
    wifi_browser->type(FL_HOLD_BROWSER); // Select one line at a time
    wifi_browser->callback(wifiBrowserCb);
    // wifi_browser takes remaining space dynamically upon resize

    rescan_button = new Fl_Button(win->w()/2 - 50, win->h() - 35, 100, 25, "&Rescan Wi-Fi"); // Position near bottom center, add mnemonic
    rescan_button->callback(rescanButtonCb);


    win->end();
    win->resizable(wifi_browser); // Browser is the primary resizable element
    win->size_range(400, 350); // Set minimum size

    // --- Initial State Update ---
    // Update ethernet status, and try DHCP if the interface is initially up
    updateEthernetStatus(true);
    scanWifiNetworks(); // Perform initial Wi-Fi scan

    win->show(argc, argv); // Show the main window
    return Fl::run(); // Start the main FLTK event loop
}
