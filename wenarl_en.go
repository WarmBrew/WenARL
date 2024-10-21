package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"
)

type Config struct {
	Server           string `json:"server"`
	Username         string `json:"username"`
	Password         string `json:"password"`
	DomainBruteType  string `json:"domain_brute_type"`
	PortScanType     string `json:"port_scan_type"`
	DomainBrute      bool   `json:"domain_brute"`
	AltDNS           bool   `json:"alt_dns"`
	DNSQueryPlugin   bool   `json:"dns_query_plugin"`
	ARLSearch        bool   `json:"arl_search"`
	PortScan         bool   `json:"port_scan"`
	ServiceDetection bool   `json:"service_detection"`
	OSDetection      bool   `json:"os_detection"`
	SSLCert          bool   `json:"ssl_cert"`
	SkipScanCDNIP    bool   `json:"skip_scan_cdn_ip"`
	SiteIdentify     bool   `json:"site_identify"`
	SearchEngines    bool   `json:"search_engines"`
	SiteSpider       bool   `json:"site_spider"`
	SiteCapture      bool   `json:"site_capture"`
	FileLeak         bool   `json:"file_leak"`
	FindVhost        bool   `json:"findvhost"`
	NucleiScan       bool   `json:"nuclei_scan"`
	WebInfoHunter    bool   `json:"web_info_hunter"`
}

type TaskListResponse struct {
	Page  int `json:"page"`
	Size  int `json:"size"`
	Total int `json:"total"`
	Items []struct {
		ID        string `json:"_id"`
		Name      string `json:"name"`
		Target    string `json:"target"`
		Status    string `json:"status"`
		StartTime string `json:"start_time"`
		EndTime   string `json:"end_time"`
		Statistic struct {
			SiteCnt   int `json:"site_cnt"`
			DomainCnt int `json:"domain_cnt"`
		} `json:"statistic"`
	} `json:"items"`
}
type LoginResponse struct {
	Code int `json:"code"`
	Data struct {
		Token string `json:"token"`
	} `json:"data"`
}

type Task struct {
	Name             string `json:"name"`
	Target           string `json:"target"`
	DomainBruteType  string `json:"domain_brute_type"`
	PortScanType     string `json:"port_scan_type"`
	DomainBrute      bool   `json:"domain_brute"`
	AltDNS           bool   `json:"alt_dns"`
	DNSQueryPlugin   bool   `json:"dns_query_plugin"`
	ARLSearch        bool   `json:"arl_search"`
	PortScan         bool   `json:"port_scan"`
	ServiceDetection bool   `json:"service_detection"`
	OSDetection      bool   `json:"os_detection"`
	SSLCert          bool   `json:"ssl_cert"`
	SkipScanCDNIP    bool   `json:"skip_scan_cdn_ip"`
	SiteIdentify     bool   `json:"site_identify"`
	SearchEngines    bool   `json:"search_engines"`
	SiteSpider       bool   `json:"site_spider"`
	SiteCapture      bool   `json:"site_capture"`
	FileLeak         bool   `json:"file_leak"`
	FindVhost        bool   `json:"findvhost"`
	NucleiScan       bool   `json:"nuclei_scan"`
	WebInfoHunter    bool   `json:"web_info_hunter"`
}

const configFile = "config.json"

func main() {
	// Display startup banner
	displayBanner()

	// Check if the configuration file exists, create a default one if not
	config, err := loadOrCreateConfig(configFile)
	if err != nil {
		color.Red("[-] 😒 Failed to read config file: %v", err)
		return
	}

	// If the config file was newly created, prompt the user to modify it and exit
	if config == nil {
		color.Yellow("Please modify the config.json file and rerun the program.")
		return
	}

	// Parse command-line arguments
	taskCmd := flag.Bool("task", false, "Display current ARL task status")
	taskName := flag.String("n", "", "Task name (required)")
	target := flag.String("t", "", "Target IP or domain")
	filePath := flag.String("f", "", "Read scan targets from file")
	outCmd := flag.String("out", "", "Export report for the specified task ID")
	flag.Parse()

	token, err := login(config.Server, config.Username, config.Password)
	if err != nil {
		color.Red("[-] 😭 Login failed: Check username/password or server address. Error: %v", err)
		return // Exit if login fails
	}
	color.Green("[+] 🕵️ Login successful!")

	// If -task is specified, output the current task status
	if *taskCmd {
		getTaskList(config.Server, token)
		return
	}

	// If -out is specified, export the task report
	if *outCmd != "" {
		color.Cyan("Starting report export, Task ID: %s", *outCmd)
		err = exportTaskReport(config.Server, token, *outCmd)
		if err != nil {
			color.Red("[-] Report export failed: %v", err)
			os.Exit(1)
		}
		color.Green("[+] Report exported successfully!")
		return
	}

	// If -f is specified, read targets from file
	if *filePath != "" {
		targets, err := readTargetsFromFile(*filePath)
		if err != nil {
			color.Red("Failed to read file: %v", err)
			os.Exit(1) // Exit if file reading fails
		}

		// Create a task for each target
		for _, target := range targets {
			if *taskName != "" {
				err = addTask(config.Server, token, *taskName, target, config)
				if err != nil {
					color.Red("Task creation failed: %v", err)
					os.Exit(1) // Exit if task creation fails
				}
				color.Green("[+] Task created successfully: %s Target: %s", *taskName, target)
			}
		}
		return
	}

	// If task name and target are provided, create the task
	if *taskName != "" && *target != "" {
		err = addTask(config.Server, token, *taskName, *target, config)
		if err != nil {
			color.Red("Task creation failed: %v", err)
			os.Exit(1) // Exit if task creation fails
		}
		color.Green("[+] Task created successfully: %s Target: %s", *taskName, *target)
	} else {
		showUsage()
		color.Red("Please use -n <task name> and -t <target> or -f <file path> to create a task, or use -task to view task status")
		os.Exit(1) // Exit if arguments are insufficient
	}
}

// Export task report
func exportTaskReport(serverURL, token, taskID string) error {
	req, err := http.NewRequest("GET", serverURL+"api/export/"+taskID, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Token", token)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("Export failed, response: %s", string(body))
	}

	// Get the filename and decode URL
	contentDisposition := resp.Header.Get("Content-Disposition")
	filename := "report.xlsx"
	if strings.Contains(contentDisposition, "filename=") {
		filename = strings.Split(contentDisposition, "filename=")[1]
		filename = strings.Trim(filename, "\"")
		decodedFilename, err := url.QueryUnescape(filename)
		if err == nil {
			filename = decodedFilename
		}
	}

	// Save the file
	outFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, resp.Body)
	if err != nil {
		return err
	}

	color.Green("Report successfully exported as: %s", filename)
	return nil
}

// Display startup banner
func displayBanner() {
	banner := `
 __      __                 ______         ___      
/\ \  __/\ \               /\  _  \       /\_ \     
\ \ \/\ \ \ \     __    ___\ \ \L\ \  _ __\//\ \    
 \ \ \ \ \ \ \  /'__` + "`" + `\/' _ ` + "`" + `\ \  __ \/\` + "`" + `'__\\ \ \   
  \ \ \_/ \_\ \/\  __//\ \/\ \ \ \/\ \ \ \/  \_\ \_ 
   \ ` + "`" + `\___x___/\ \____\ \_\ \_\ \_\ \_\ \_\  /\____\
    '\/__//__/  \/____/\/_/\/_/\/_/\/_/\/_/  \/____/

		Author: wencha v1.0.3
`
	color.Cyan(banner)
}

// Display usage instructions
func showUsage() {
	color.Cyan("Usage:")
	fmt.Println("  -n <Task Name>    Set the task name (required)")
	fmt.Println("  -t <Target>       Set the scan target IP or domain")
	fmt.Println("  -f <File Path>    Read scan targets from file")
	fmt.Println("  -task             View current task status")
	fmt.Println("  -out <Task ID>    Export report for the specified task ID")
	fmt.Println("\nExamples:")
	fmt.Println("  ./wenarl -n mytask -t example.com")
	fmt.Println("  ./wenarl -n mytask -f targets.txt")
	fmt.Println("  ./wenarl -task")
	fmt.Println("  ./wenarl -out <Task ID (obtain via -task)>")
}

// Load or create config file
func loadOrCreateConfig(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if os.IsNotExist(err) {
		// If the file doesn't exist, create a default config file
		defaultConfig := &Config{
			Server:           "http://xxx.xxx.xxx:5003/ (ARL address)",
			Username:         "admin",
			Password:         "arlpass",
			DomainBruteType:  "big",
			PortScanType:     "all",
			DomainBrute:      true,
			AltDNS:           true,
			DNSQueryPlugin:   true,
			ARLSearch:        true,
			PortScan:         true,
			ServiceDetection: true,
			OSDetection:      true,
			SSLCert:          false,
			SkipScanCDNIP:    true,
			SiteIdentify:     true,
			SearchEngines:    true,
			SiteSpider:       true,
			SiteCapture:      true,
			FileLeak:         true,
			FindVhost:        true,
			NucleiScan:       false,
			WebInfoHunter:    false,
		}
		err = createDefaultConfig(filename, defaultConfig)
		if err != nil {
			return nil, err
		}
		color.Green("Config file not found, created default config file %s.", filename)
		return nil, nil // Notify user and exit
	} else if err != nil {
		return nil, err
	}
	defer file.Close()

	// Load existing config file
	var config Config
	err = json.NewDecoder(file).Decode(&config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

// Create default config file
func createDefaultConfig(filename string, config *Config) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	_, err = file.Write(data)
	if err != nil {
		return err
	}
	return nil
}

// Login function to get the token
func login(url, username, password string) (string, error) {
	loginData := map[string]string{
		"username": username,
		"password": password,
	}
	jsonData, _ := json.Marshal(loginData)

	// Skip TLS certificate verification (if needed)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Post(url+"api/user/login", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Login response error: %s", string(body))
	}

	var loginResp LoginResponse
	err = json.Unmarshal(body, &loginResp)
	if err != nil {
		return "", err
	}

	if loginResp.Code != 200 {
		return "", fmt.Errorf("Login failed, response code: %d", loginResp.Code)
	}

	return loginResp.Data.Token, nil
}

// Read targets from file
func readTargetsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	content, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	// Split targets by line
	targets := strings.Split(string(content), "\n")
	// Remove empty lines
	var validTargets []string
	for _, target := range targets {
		trimmed := strings.TrimSpace(target)
		if trimmed != "" {
			validTargets = append(validTargets, trimmed)
		}
	}
	return validTargets, nil
}

// Create task
func addTask(url, token, taskName, target string, config *Config) error {
	task := Task{
		Name:             taskName,
		Target:           target,
		DomainBruteType:  config.DomainBruteType,
		PortScanType:     config.PortScanType,
		DomainBrute:      config.DomainBrute,
		AltDNS:           config.AltDNS,
		DNSQueryPlugin:   config.DNSQueryPlugin,
		ARLSearch:        config.ARLSearch,
		PortScan:         config.PortScan,
		ServiceDetection: config.ServiceDetection,
		OSDetection:      config.OSDetection,
		SSLCert:          config.SSLCert,
		SkipScanCDNIP:    config.SkipScanCDNIP,
		SiteIdentify:     config.SiteIdentify,
		SearchEngines:    config.SearchEngines,
		SiteSpider:       config.SiteSpider,
		SiteCapture:      config.SiteCapture,
		FileLeak:         config.FileLeak,
		FindVhost:        config.FindVhost,
		NucleiScan:       config.NucleiScan,
		WebInfoHunter:    config.WebInfoHunter,
	}

	jsonData, _ := json.Marshal(task)

	req, err := http.NewRequest("POST", url+"api/task/", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Token", token)

	// Use the same client, skip TLS certificate verification
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("Task creation failed: %s", string(body))
	}

	color.Green("[+] Task '%s' created successfully, scanning target '%s'", taskName, target)
	displayScanConfig(config)
	return nil
}

// Display scan configuration
func displayScanConfig(config *Config) {
	color.Cyan("\nScan configuration:")
	fmt.Printf("Domain brute force: %t\nDNS query plugin: %t\nPort scan: %t\nSkip CDN: %t\nService detection: %t\nOS detection: %t\nSite identification: %t\nFile leak scan: %t\nSmart DNS dictionary generation: %t\nSite spider: %t\nSite capture: %t\nARL search: %t\n",
		config.DomainBrute, config.DNSQueryPlugin, config.PortScan, config.SkipScanCDNIP, config.ServiceDetection, config.OSDetection,
		config.SiteIdentify, config.FileLeak, config.AltDNS, config.SiteSpider, config.SiteCapture, config.ARLSearch)
}

// Get task list and display in formatted output
func getTaskList(url, token string) {
	req, err := http.NewRequest("GET", url+"api/task/?page=1&size=100", nil)
	if err != nil {
		color.Red("Failed to get task list: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Token", token)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		color.Red("Request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		color.Red("Failed to get task list: %s", string(body))
		return
	}

	// Parse task list
	var taskList TaskListResponse
	err = json.Unmarshal(body, &taskList)
	if err != nil {
		color.Red("Failed to parse task list: %v", err)
		return
	}

	// Use tabwriter for formatted table output
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.AlignRight|tabwriter.Debug)

	// Table header
	fmt.Fprintln(w, "Task Name\tSites Count\tDomains Count\tStatus\tStart Time\tEnd Time\tTask ID")
	fmt.Fprintln(w, "------------------------------------------------------------------------")

	// Iterate over task list and print information
	for _, task := range taskList.Items {
		statisticsSites := fmt.Sprintf("%d", task.Statistic.SiteCnt)
		statisticsDomains := fmt.Sprintf("%d", task.Statistic.DomainCnt)
		startTime := formatTime(task.StartTime)
		endTime := formatTime(task.EndTime)
		status := getStatus(task.Status)

		// Output task information, ensuring alignment
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			task.Name, statisticsSites, statisticsDomains, status, startTime, endTime, task.ID)
	}

	// Flush output to ensure correct table display
	w.Flush()
}

// Format time for readability
func formatTime(timeStr string) string {
	if timeStr == "-" || timeStr == "" {
		return "-"
	}

	parsedTime, err := time.Parse("2006-01-02 15:04:05", timeStr)
	if err != nil {
		return timeStr // Return original format on parse error
	}

	return parsedTime.Format("2006/01/02 15:04")
}

// Get task status and return colored string
func getStatus(status string) string {
	switch status {
	case "done":
		return color.GreenString("Completed")
	case "stop":
		return color.RedString("Stopped")
	default:
		return color.BlueString("Running")
	}
}
