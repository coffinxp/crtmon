# crtmon — Add `-o` Output File Flag (Append Mode)

## Goal
Add a `-o outputfile.txt` flag to crtmon so that every matched subdomain is **also written to a local file in append mode**, while Discord/Telegram notifications continue to work exactly as before.

---

## Repository
`https://github.com/axosecurity/crtmon-modified`

All files are in the repo root. This patch touches:
- `main.go` (existing) — 4 small edits
- `output.go` (new file) — create from scratch
- `help.go` (existing) — add one line to the flag list

---

## Step 1 — Create new file `output.go`

Create a new file called `output.go` in the repo root with exactly this content:

```go
package main

import (
	"bufio"
	"fmt"
	"os"
	"sync"
	"time"
)

var (
	outputFilePath string
	outputFd       *os.File
	outputWriter   *bufio.Writer
	outputMu       sync.Mutex
)

// initOutputFile opens the file in append+create mode.
// Called once from main() when -o is provided.
func initOutputFile(path string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	outputFd = f
	outputWriter = bufio.NewWriter(f)
	outputFilePath = path
	return nil
}

// writeToOutputFile appends a single matched domain line to the file.
// Format:  2026-05-13T11:07:00  target.com  sub.target.com
func writeToOutputFile(domain, target string) {
	if outputWriter == nil {
		return
	}
	outputMu.Lock()
	defer outputMu.Unlock()
	ts := time.Now().Format("2006-01-02T15:04:05")
	line := fmt.Sprintf("%s\t%s\t%s\n", ts, target, domain)
	_, _ = outputWriter.WriteString(line)
	_ = outputWriter.Flush() // flush every line so file is always up-to-date
}

// closeOutputFile flushes and closes the file. Call on shutdown.
func closeOutputFile() {
	if outputFd == nil {
		return
	}
	outputMu.Lock()
	defer outputMu.Unlock()
	_ = outputWriter.Flush()
	_ = outputFd.Close()
}
```

---

## Step 2 — Edit `main.go`

### Edit 2A — Add the flag variable

In the `var (...)` block at the top of `main.go`, find this line (it is the last flag definition):

```go
showHelp2 = flag.Bool("help", false, "show help")
```

Add one new line immediately after it:

```go
outputPath = flag.String("o", "", "output file path (append mode)")
```

---

### Edit 2B — Register `-o` in the validFlags map

Find this block inside `main()`:

```go
validFlags := map[string]bool{
    "-target": true,
    "-scope":  true,
    "-config": true,
    "-notify": true,
    "-json":   true,
    "-version": true,
    "-update": true,
    "-h": true, "-help": true,
}
```

Add one entry so it becomes:

```go
validFlags := map[string]bool{
    "-target": true,
    "-scope":  true,
    "-config": true,
    "-notify": true,
    "-json":   true,
    "-version": true,
    "-update": true,
    "-h": true, "-help": true,
    "-o": true,
}
```

---

### Edit 2C — Initialize the output file at startup

Find these two lines (they appear near the bottom of `main()`, just before the certstream loop):

```go
logger.Debug("configuration", "targets", len(targets), "notification", notifyStatus)
logger.Info("connecting to certificate transparency logs")
```

Insert this new block **between** those two lines:

```go
logger.Debug("configuration", "targets", len(targets), "notification", notifyStatus)

// --- OUTPUT FILE INIT (new) ---
if *outputPath != "" {
    if err := initOutputFile(*outputPath); err != nil {
        logger.Fatal("failed to open output file", "path", *outputPath, "error", err)
    }
    logger.Info("output file opened", "path", *outputPath, "mode", "append")
    defer closeOutputFile()
}
// --- END OUTPUT FILE INIT ---

logger.Info("connecting to certificate transparency logs")
```

---

### Edit 2D — Write to file inside `processEntry()`

Find the current `processEntry()` function. The inner match block currently looks like this:

```go
if *jsonOutput {
    outputJSON(domain, target, entry)
} else {
    logger.Info("new subdomain", "domain", domain, "target", target)
}

if notifyDiscord || notifyTelegram {
    go sendToDiscord(domain, target)
}
```

Add `writeToOutputFile(domain, target)` after the JSON/log block and before the notify block, so it becomes:

```go
if *jsonOutput {
    outputJSON(domain, target, entry)
} else {
    logger.Info("new subdomain", "domain", domain, "target", target)
}

writeToOutputFile(domain, target) // always runs, independent of -json flag

if notifyDiscord || notifyTelegram {
    go sendToDiscord(domain, target)
}
```

---

## Step 3 — Edit `help.go`

Inside the help display function, find where the existing flags are listed (look for lines mentioning `-notify`, `-json`, `-version`, etc.) and add this line in the same style as the others:

```
-o           string   output file path; matched subdomains are appended line by line
```

---

## Final Result — How the output file looks

Each line written to the file has three tab-separated columns:

```
2026-05-13T11:07:00    tesla.com    api.tesla.com
2026-05-13T11:07:04    tesla.com    staging-01.tesla.com
2026-05-13T11:08:12    tesla.com    cdn.tesla.com
```

Columns: `timestamp` → `target` → `discovered subdomain`

---

## Usage Examples After the Patch

```bash
# File output + Discord notifications
crtmon -target tesla.com -notify discord -o /home/axo/recon/tesla_subs.txt

# File output + both Discord and Telegram
crtmon -target tesla.com -notify both -o tesla_output.txt

# File output only, no notifications
crtmon -target tesla.com -o results.txt

# Pipe mode + file output
cat targets.txt | crtmon -target - -o /tmp/all_subs.txt

# JSON stdout + file output at the same time
crtmon -target tesla.com -json -o tesla_subs.txt
```

---

## Why Each Decision Was Made

| Decision | Reason |
|---|---|
| Separate `output.go` file | Keeps `main.go` clean; matches the repo pattern (`send.go`, `config.go`, etc.) |
| `bufio.Writer` + `sync.Mutex` | Thread-safe; `processEntry` fires rapidly and concurrently |
| `Flush()` on every line | If the process is killed, no buffered results are lost |
| `os.O_APPEND\|os.O_CREATE\|os.O_WRONLY` | True append mode — never overwrites existing file data |
| `defer closeOutputFile()` in `main()` | Final flush happens cleanly on normal exit or Ctrl+C |
| `writeToOutputFile` outside the `if *jsonOutput` block | File writing works regardless of whether `-json` flag is used |



# after doing this compille and run this tool ok but make sure to not make it globbaly right now run it in this directory 

when it will pass everyrthing than remove my existing tool that is running and install it via go install ok ? 



