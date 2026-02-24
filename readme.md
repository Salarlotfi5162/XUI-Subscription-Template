<h1 align="center"/>⚡️ Welcome to XUI Panel Premium Subscription Template ⚡️</h1>

> **If you need explanations in Persian, check out the [Readme for Farsi](readme-fa.md).**
#
> ** This is a custom premium dark-mode subscription template designed for the Sanaei XUI Panel. It provides a beautiful, modern view of service details including usage, expiration date, active configs list, and connected apps.**

## Install & Upgrade

Since this is a custom fork, you should install it manually or clone it directly:

```bash
cd /opt
git clone git@github.com:Salarlotfi5162/XUI-Subscription-Template.git DVHOST
cd DVHOST
npm install
```

## Configuration File
```bash
nano /opt/DVHOST/dvhost.config
```
You must restart the service after changing the configuration file.
```bash
systemctl restart DVHOST_TEMPLATE
systemctl status DVHOST_TEMPLATE
```
**You should not have ports 2082 and 2083 involved.**

## Features
- Deep Dark premium aesthetic with pink accents.
- Dynamic Tab System (Apps, Configs, Add Sub).
- Smart Limit Calculation: Accurately displays remaining volume by analyzing all inbounds.
- Dummy Config Injection: Automatically injects a VLESS config showing user stats right inside v2ray clients.
- OS-specific App recommendations (iOS, Android, Windows, Linux).

Enjoy seamless and user-friendly subscription management with this template!
