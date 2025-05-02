# Broadcom wl driver for alpine linux

Uses [akms](https://github.com/jirutka/akms)

Since alpine got rid of non-free repository, the only way is to build driver from third-party APKBUILD.

**Installation:**

1. follow this instructions: <https://wiki.alpinelinux.org/wiki/Creating_an_Alpine_package#Setup_your_system_and_account>
2. Copy ~/.abuild/key.rsa.pub into /etc/apk/keys
3. Enter PACKAGER_PRIVKEY="$HOME/.abuild/key.rsa" into ~/.abuild/abuild.conf
4. Clone this repo and cd into it
5. Build package with `abuild -r`
6. Go into ~/packages/broadcom-wl-akms/x86_64 and install package with `apk add broadcom-wl-6.30.223.271-r0.apk`

It`s done!

If you followed instructions in wiki about keygen you can skip steps 2 and 3.

---

Tested with Broadcom BCM43142, iwd, alpine edge

With iwd and busybox's dhcp you will need to add that to iwd config

```
[General]
EnableNetworkConfiguration=True
```

With dhcpcd it may work without it
