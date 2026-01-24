package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	charmlog "github.com/charmbracelet/log"
)

var (
	target         = flag.String("target", "", "target domain to monitor")
	scope          = flag.String("scope", "", "scope keyword to filter subdomains")
	configPath     = flag.String("config", "", "path to configuration file")
	notify         = flag.String("notify", "", "notification provider: discord, telegram, ntfy (comma-separated)")
	jsonOutput     = flag.Bool("json", false, "output raw JSON format to stdout")
	showVersion    = flag.Bool("version", false, "show version")
	update         = flag.Bool("update", false, "update to latest version")
	showHelp       = flag.Bool("h", false, "show help")
	showHelp2      = flag.Bool("help", false, "show help")
	logger         *charmlog.Logger
	targets        []string
	scopeFilter    string
	webhookURL     string
	telegramToken  string
	telegramChatID string
	ntfyURL        string
	notifyDiscord  bool
	notifyTelegram bool
	notifyNtfy     bool
)

func main() {
	flag.CommandLine.Usage = func() {
		displayHelp()
	}
	flag.Parse()

	if *jsonOutput {
		logger = charmlog.NewWithOptions(os.Stderr, charmlog.Options{
			ReportTimestamp: false,
			Level:           charmlog.FatalLevel,
		})
		log.SetOutput(io.Discard)
		log.SetFlags(0)
	} else {
		logger = charmlog.NewWithOptions(os.Stderr, charmlog.Options{
			ReportTimestamp: true,
			TimeFormat:      "15:04:05",
			Level:           charmlog.DebugLevel,
		})
	}

	if len(os.Args) > 1 {
		validFlags := map[string]bool{
			"-target":  true,
			"-scope":   true,
			"-config":  true,
			"-notify":  true,
			"-json":    true,
			"-version": true,
			"-update":  true,
			"-h":       true, "-help": true,
		}

		for i, arg := range os.Args[1:] {
			if strings.HasPrefix(arg, "-") && arg != "-" {
				flagName := arg
				if idx := strings.Index(arg, "="); idx != -1 {
					flagName = arg[:idx]
				}
				if !validFlags[flagName] {
					displayHelp()
					return
				}
			} else if arg == "-" && i > 0 {
				prevArg := os.Args[i]
				if !strings.HasPrefix(prevArg, "-") || strings.Contains(prevArg, "=") {
					displayHelp()
					return
				}
			}
		}
	}

	if *showVersion {
		displayVersion()
		return
	}

	if *update {
		performUpdate()
		return
	}

	if *showHelp || *showHelp2 {
		displayHelp()
		return
	}

	if !*jsonOutput {
		printBanner()
	}

	if *configPath != "" {
		setConfigPath(*configPath)
	}

	cfg, err := loadConfig()
	if err != nil {
		logger.Fatal("failed to load config", "error", err)
	}

	if cfg != nil {
		if cfg.Webhook == `""` {
			cfg.Webhook = ""
		}

		webhookURL = strings.TrimSpace(cfg.Webhook)
		if webhookURL == "" {
			logger.Warn("no discord webhook configured in configuration file; discord notifications disabled")
		}

		telegramToken = strings.TrimSpace(cfg.TelegramBotToken)
		telegramChatID = strings.TrimSpace(cfg.TelegramChatID)
		ntfyURL = strings.TrimSpace(cfg.NtfyURL)
	} else {
		webhookURL = ""
		telegramToken = ""
		telegramChatID = ""
		ntfyURL = ""
		logger.Warn("no configuration file found. notifications will be disabled unless providers are configured")
	}

	stdinAvailable := false
	if fi, err := os.Stdin.Stat(); err == nil && (fi.Mode()&os.ModeCharDevice) == 0 {
		stdinAvailable = true
	}

	switch {
	case *target != "":
		resolved, err := resolveTargetFlag(*target)
		if err != nil {
			logger.Fatal("failed to resolve target", "error", err)
		}
		if len(resolved) == 0 {
			logger.Fatal("no targets resolved from -target flag")
		}
		targets = resolved
		logger.Info("using targets from cli flag", "count", len(targets))
	case stdinAvailable:
		resolved, err := loadTargetsFromStdin()
		if err != nil {
			logger.Fatal("failed to read targets from stdin", "error", err)
		}
		if len(resolved) == 0 {
			logger.Fatal("no targets provided on stdin")
		}
		targets = resolved
		logger.Info("using targets from stdin", "count", len(targets))
	case cfg != nil:
		if len(cfg.Targets) == 0 {
			logger.Fatal("no targets configured. please add target domains to ~/.config/crtmon/provider.yaml or use -target flag or stdin")
		}
		targets = cfg.Targets
		logger.Info("loaded configuration", "targets", len(targets))
	default:
		if err := createConfigTemplate(); err != nil {
			logger.Fatal("failed to create config template", "error", err)
		}
		configPath, _ := getConfigPath()
		logger.Info("created config template", "path", configPath)
		logger.Fatal("please edit the configuration file or provide targets via -target or stdin and run again")
	}

	discordConfigured := webhookURL != ""
	telegramConfigured := telegramToken != "" && telegramChatID != ""
	ntfyConfigured := ntfyURL != ""

	scopeFilter = strings.TrimSpace(*scope)

	notifyValue := strings.ToLower(strings.TrimSpace(*notify))
	if notifyValue != "" {
		parts := strings.Split(notifyValue, ",")
		for _, raw := range parts {
			provider := strings.TrimSpace(raw)
			switch provider {
			case "":
				continue
			case "discord":
				if !discordConfigured {
					logger.Fatal("notify=discord selected but discord webhook is not configured. please configure it in your configuration file (use -config for a custom path)")
				}
				notifyDiscord = true
			case "telegram":
				if !telegramConfigured {
					logger.Fatal("notify=telegram selected but telegram bot token/chat id are not configured. please configure them in your configuration file (use -config for a custom path)")
				}
				notifyTelegram = true
			case "ntfy":
				if !ntfyConfigured {
					logger.Fatal("notify=ntfy selected but ntfy topic url is not configured. please configure it in your configuration file (use -config for a custom path)")
				}
				notifyNtfy = true
			case "both":
				if !discordConfigured || !telegramConfigured {
					logger.Fatal("notify=both selected but discord webhook or telegram credentials are not configured. please configure them in your configuration file (use -config for a custom path)")
				}
				notifyDiscord = true
				notifyTelegram = true
			case "all":
				if !discordConfigured || !telegramConfigured || !ntfyConfigured {
					logger.Fatal("notify=all selected but one or more providers are not configured. please configure discord, telegram, and ntfy in your configuration file (use -config for a custom path)")
				}
				notifyDiscord = true
				notifyTelegram = true
				notifyNtfy = true
			default:
				logger.Fatal("invalid value for -notify. valid options are: discord, telegram, ntfy, both, all, or comma-separated combinations")
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Info("shutting down...")
		cancel()
	}()

	logger.Info("starting crtmon")
	if !*jsonOutput {
		for i, t := range targets {
			fmt.Printf("         %d. %s\n", (i + 1), t)
		}
	}

	var notifyStatus string
	providers := []string{}
	if notifyDiscord {
		providers = append(providers, "discord")
	}
	if notifyTelegram {
		providers = append(providers, "telegram")
	}
	if notifyNtfy {
		providers = append(providers, "ntfy")
	}
	if len(providers) == 0 {
		notifyStatus = "off"
	} else {
		notifyStatus = strings.Join(providers, ", ")
	}
	logger.Debug("configuration", "targets", len(targets), "notification", notifyStatus)

	logger.Info("connecting to certificate transparency logs")

	stream := CertStreamEventStream()

	for {
		select {
		case <-ctx.Done():
			logger.Info("goodbye")
			return
		case entry := <-stream:
			processEntry(entry)
		}
	}
}

func resolveTargetFlag(value string) ([]string, error) {
	if value == "-" {
		return loadTargetsFromStdin()
	}

	if info, err := os.Stat(value); err == nil && !info.IsDir() {
		file, err := os.Open(value)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		var targets []string
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			targets = append(targets, line)
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}

		return targets, nil
	}

	return []string{value}, nil
}

func loadTargetsFromStdin() ([]string, error) {
	scanner := bufio.NewScanner(os.Stdin)
	var targets []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return targets, nil
}

func processEntry(entry CertEntry) {
	for _, domain := range entry.Domains {
		for _, target := range targets {
			if strings.Contains(strings.ToLower(domain), strings.ToLower(target)) {
				if scopeFilter != "" && !strings.Contains(strings.ToLower(domain), strings.ToLower(scopeFilter)) {
					continue
				}
				if *jsonOutput {
					outputJSON(domain, target, entry)
				} else {
					logger.Info("new subdomain", "domain", domain, "target", target)
				}
				if notifyDiscord || notifyTelegram || notifyNtfy {
					go sendToDiscord(domain, target)
				}
			}
		}
	}
}
