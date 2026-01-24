package main

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Webhook          string   `yaml:"webhook"`
	TelegramBotToken string   `yaml:"telegram_bot_token"`
	TelegramChatID   string   `yaml:"telegram_chat_id"`
	NtfyURL          string   `yaml:"ntfy_url"`
	Targets          []string `yaml:"targets"`
}

var customConfigPath string

func setConfigPath(path string) {
	customConfigPath = path
}

func getConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "crtmon"), nil
}

func getConfigPath() (string, error) {
	if customConfigPath != "" {
		return customConfigPath, nil
	}
	dir, err := getConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "provider.yaml"), nil
}

func createConfigTemplate() error {
	configPath, err := getConfigPath()
	if err != nil {
		return err
	}

	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	template := `# crtmon configuration
# monitor your targets real time via certificate transparency logs

# discord webhook url for notifications
webhook: ""

# telegram bot credentials for notifications (optional)
telegram_bot_token: ""
telegram_chat_id: ""

# ntfy topic URL for notifications (optional)
ntfy_url: ""

# target wildcard to monitor
targets:
`

	return os.WriteFile(configPath, []byte(template), 0644)
}

func loadConfig() (*Config, error) {
	configPath, err := getConfigPath()
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

func configExists() bool {
	configPath, err := getConfigPath()
	if err != nil {
		return false
	}
	_, err = os.Stat(configPath)
	return err == nil
}

func validateConfig(cfg *Config) error {
	discordConfigured := cfg.Webhook != "" && cfg.Webhook != `""`
	telegramConfigured := cfg.TelegramBotToken != "" && cfg.TelegramChatID != "" && cfg.TelegramBotToken != `""` && cfg.TelegramChatID != `""`
	ntfyConfigured := cfg.NtfyURL != "" && cfg.NtfyURL != `""`

	if len(cfg.Targets) == 0 {
		return fmt.Errorf("no targets configured. please add target domains to ~/.config/crtmon/provider.yaml")
	}

	if !discordConfigured && !telegramConfigured && !ntfyConfigured {
		return fmt.Errorf("no notification provider configured. please configure discord webhook, telegram bot, or ntfy topic url in ~/.config/crtmon/provider.yaml")
	}

	return nil
}

func updateWebhook(newWebhook string) error {
	configPath, err := getConfigPath()
	if err != nil {
		return err
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return err
	}

	config.Webhook = newWebhook

	newData, err := yaml.Marshal(&config)
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, newData, 0644)
}
