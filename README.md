<div align="center">
  <img src="https://github.com/user-attachments/assets/39d6e99e-8281-4f48-811b-14478f25be99" alt="crtmon" width="800">
</div>

<br>
<br>
<br>


> [!NOTE]
> **crtmon is a minimal tool for monitoring certificate transparency logs without any hassle.**

<br>

- <sub> **detects new subdomains for your targets in realtime** </sub>
- <sub> **discord & telegram notifications** </sub>
- <sub> **smart batching with rate limiting** </sub>
- <sub> **stdin and file support for multiple targets** </sub>

<br>
<br>

<h4>Installation</h4>

```bash
go install github.com/coffinxp/crtmon@latest
```

<br>

<h6>setup configuration</h6>

```bash
# create config directory and provider template
crtmon
```

- <sub>**edit the generated config file at `~/.config/crtmon/provider.yaml`**</sub>

<div align="center">
  <img width="800" height="800" alt="provider" src="https://github.com/user-attachments/assets/183cb7ab-6e52-40c8-9362-118bf97a0c84" />
</div>

<br>
<br>

<h4>Flags</h4>

<pre>
  -target    : target domain, file path, or '-' for stdin
  -config    : path to configuration file (default: ~/.config/crtmon/provider.yaml)
  -notify    : notification provider: discord, telegram, both
  -version   : show version
  -update    : update to latest version
  -h, -help  : show help message
</pre>

<div align="center">
  <img width="1000" height="1000" alt="help" src="https://github.com/user-attachments/assets/1209cd79-b52d-4aef-84c6-bccfc4fa3837" />
</div>

<br>
<br>

<h4>Example Commands</h4>

```bash
# monitor github.com for new subdomains
crtmon -target github.com

# monitor multiple targets from config file
crtmon # config: ~/.config/crtmon/provider.yaml
```

<br>

```bash
# monitor multiple targets via file
crtmon -target targets.txt

# pipe targets from stdin
cat domains.txt | crtmon -target -

# monitor specific targets with telegram notifications
crtmon -target github.com -notify=telegram
```

<br>

```bash
# setup cron job to start crtmon on system reboot
echo "@reboot nohup crtmon -target github.com > /tmp/crtmon.log 2>&1 &" | crontab -
```

<br>

```bash
# multiple program targets with dual notifications
echo -e "tesla.com\nuber.com\nmeta.com" | crtmon -target - -notify=both
```

<br>
<br>

- **If you see no results or errors**
  - <sub> **verify your targets and notification configuration** </sub>
  - <sub> **check your internet connection** </sub>
  - <sub> **ensure docker is installed and running** </sub>
  - <sub> **use `-h` for guidance** </sub>

<br>

<h6>Telegram Setup</h6>

```bash
# run the telegram helper bot to get your chat ID
cd host/telegrambot && TELEGRAM_BOT_TOKEN=your_token go run main.go
```

<br>

<h6>TO-DO</h6>

- [ ] **different channels for specific targets capability**

<br>

> [!CAUTION]
> **never use `crtmon` for any illegal activites, we are not responsible for your deeds with it. Do for justice.**

<br>
<br>
<br>

<h6 align="center">kindly for hackers</h6>

<div align="center">
  <a href="https://github.com/1hehaq"><img src="https://img.icons8.com/material-outlined/20/808080/github.png" alt="GitHub"></a>
  <a href="https://twitter.com/1hehaq"><img src="https://img.icons8.com/material-outlined/20/808080/twitter.png" alt="X"></a>
</div></content>
