
<p align="center">
  <img src="https://github.com/user-attachments/assets/39d6e99e-8281-4f48-811b-14478f25be99" alt="crtmon" width="600">
</p>

**crtmon** is a lightweight Certificate Transparency monitoring tool that discovers new subdomains in real time as soon as they appear.


##  Features

* Real-time subdomain discovery from CT logs
* Discord and Telegram notifications
* Smart batching with built-in rate limiting
* Supports single targets, files, and stdin

---

##  Installation

```bash
go install github.com/coffinxp/crtmon@latest
```

---

##  Configuration

Run `crtmon` once to generate the default configuration template:

```bash
crtmon
```

Edit the generated file:

```text
~/.config/crtmon/provider.yaml
```

<p align="center">
  <img src="https://github.com/user-attachments/assets/183cb7ab-6e52-40c8-9362-118bf97a0c84" alt="provider config" width="800">
</p>

---

##  Flags

```text
-target    target domain, file path, or '-' for stdin
-config    path to configuration file (default: ~/.config/crtmon/provider.yaml)
-notify    notification provider: discord, telegram, both
-version   show version
-update    update to latest version
-h, -help  show help message
```

<p align="center">
  <img src="https://github.com/user-attachments/assets/1209cd79-b52d-4aef-84c6-bccfc4fa3837" alt="help output" width="1000">
</p>

---

##  Usage Examples

### Monitor a single target

```bash
crtmon -target github.com
```

### Monitor targets from config file

```bash
crtmon # config: ~/.config/crtmon/provider.yaml
```

### Monitor multiple targets from a file

```bash
crtmon -target targets.txt
```

### Pipe targets via stdin

```bash
cat domains.txt | crtmon -target -
```

### Use Telegram notifications only

```bash
crtmon -target github.com -notify=telegram
```

### Dual notifications (Discord + Telegram)

```bash
echo -e "tesla.com\nuber.com\nmeta.com" | crtmon -target - -notify=both
```

### Start on system reboot (cron)

```bash
echo "@reboot nohup crtmon -target github.com > /tmp/crtmon.log 2>&1 &" | crontab -
```

---

## Troubleshooting

If you see no output or errors:

* Verify your targets are valid
* Double check notification credentials
* Ensure Docker is installed and running
* Check your internet connection
* Run `crtmon -h` for guidance

---

## TO-DO

* [ ] Separate notification channels per target

---

## ⚠️ Disclaimer

Use **crtmon** only on assets you own or have permission to test.
The authors are not responsible for misuse.

---
