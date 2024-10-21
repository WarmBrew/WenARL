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
	// 显示启动字符画
	displayBanner()
	

	// 检查配置文件是否存在，如果不存在则创建默认配置文件并提示用户修改
	config, err := loadOrCreateConfig(configFile)
	if err != nil {
		color.Red("[-] 😒读取配置文件失败: %v", err)
		return
	}

	// 如果配置文件是新创建的，提醒用户修改配置文件并退出
	if config == nil {
		color.Yellow("请先修改配置文件 config.json，然后重新运行程序。")
		return
	}

	// 解析命令行参数
	taskCmd := flag.Bool("task", false, "输出当前ARL的任务状态")
	taskName := flag.String("n", "", "任务名称 (必填)")
	target := flag.String("t", "", "目标IP或域名")
	filePath := flag.String("f", "", "从文件读取扫描目标")
	outCmd := flag.String("out", "", "导出指定任务ID的报告")
	flag.Parse()

	token, err := login(config.Server, config.Username, config.Password)
	if err != nil {
		color.Red("[-] 😭 登录失败: 请检查账号密码及服务器地址是否正确. 错误信息: %v", err)
		return // 登录失败，退出程序
	}
	color.Green("[+] 🕵️ 登录成功！")

	// 如果指定了 -task 参数，输出当前任务状态
	if *taskCmd {
		getTaskList(config.Server, token)
		return
	}

	// 如果指定了 -out 参数，导出任务报告
    if *outCmd != "" {
        color.Cyan("开始导出任务报告，任务ID: %s", *outCmd) // 增加调试输出
        err = exportTaskReport(config.Server, token, *outCmd)
        if err != nil {
            color.Red("[-] 报告导出失败: %v", err)
            os.Exit(1)
        }
        color.Green("[+] 报告导出成功！")
        return
    }


	// 如果指定了 -f 参数，从文件读取目标
	if *filePath != "" {
		targets, err := readTargetsFromFile(*filePath)
		if err != nil {
			color.Red("读取文件失败: %v", err)
			os.Exit(1) // 文件读取失败，退出程序
		}

		// 对于每个目标创建一个任务
		for _, target := range targets {
			if *taskName != "" {
				err = addTask(config.Server, token, *taskName, target, config)
				if err != nil {
					color.Red("任务创建失败: %v", err)
					os.Exit(1) // 任务创建失败，退出程序
				}
				color.Green("[+] 任务已成功创建：%s 目标：%s", *taskName, target)
			}
		}
		return
	}

	// 如果提供了任务名称和目标，则创建任务
	if *taskName != "" && *target != "" {
		err = addTask(config.Server, token, *taskName, *target, config)
		if err != nil {
			color.Red("任务创建失败: %v", err)
			os.Exit(1) // 任务创建失败，退出程序
		}
		color.Green("[+] 任务已成功创建：%s 目标：%s", *taskName, *target)
	} else {
		showUsage()
		color.Red("请使用 -n <任务名称> 和 -t <目标> 或 -f <文件路径> 来创建任务，或使用 -task 查看任务状态")
		os.Exit(1) // 参数不足，退出程序
	}
}



// 导出任务报告
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
		return fmt.Errorf("导出失败，响应: %s", string(body))
	}

	// 获取文件名并进行URL解码
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

	// 保存文件
	outFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, resp.Body)
	if err != nil {
		return err
	}

	color.Green("报告已成功导出为: %s", filename)
	return nil
}


// 显示启动字符画
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

// 显示使用方法
func showUsage() {
	color.Cyan("Usage:")
	fmt.Println("  -n <任务名称>   设置任务名称 (必填)")
	fmt.Println("  -t <目标>       设置扫描目标IP或域名")
	fmt.Println("  -f <文件路径>   从文件读取扫描目标")
	fmt.Println("  -task          查看当前任务状态")
	fmt.Println("  -out <任务ID>   导出指定任务ID的报告     ")
	fmt.Println("\n示例:")
	fmt.Println("  ./wenarl -n mytask -t example.com")
	fmt.Println("  ./wenarl -n mytask -f targets.txt")
	fmt.Println("  ./wenarl -task ")
	fmt.Println("  ./wenarl -out 任务id(通过task获取)")
}

// 加载或创建配置文件
func loadOrCreateConfig(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if os.IsNotExist(err) {
		// 如果文件不存在，创建默认配置文件
		defaultConfig := &Config{
			Server:           "http://xxx.xxx.xxx:5003/（ARL地址）",
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
		color.Green("配置文件不存在，已创建默认配置文件 %s。", filename)
		return nil, nil // 提示用户后退出程序
	} else if err != nil {
		return nil, err
	}
	defer file.Close()

	// 加载现有配置文件
	var config Config
	err = json.NewDecoder(file).Decode(&config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

// 创建默认配置文件
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

// 登录函数，获取Token
func login(url, username, password string) (string, error) {
	loginData := map[string]string{
		"username": username,
		"password": password,
	}
	jsonData, _ := json.Marshal(loginData)

	// 跳过 TLS 证书验证（如果需要）
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
		return "", fmt.Errorf("登录响应错误: %s", string(body))
	}

	var loginResp LoginResponse
	err = json.Unmarshal(body, &loginResp)
	if err != nil {
		return "", err
	}

	if loginResp.Code != 200 {
		return "", fmt.Errorf("登录失败，响应代码: %d", loginResp.Code)
	}

	return loginResp.Data.Token, nil
}

// 从文件读取目标
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

	// 按行分割目标
	targets := strings.Split(string(content), "\n")
	// 去除空行
	var validTargets []string
	for _, target := range targets {
		trimmed := strings.TrimSpace(target)
		if trimmed != "" {
			validTargets = append(validTargets, trimmed)
		}
	}
	return validTargets, nil
}

// 创建任务
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

	// 使用同样的 client，跳过 TLS 证书验证
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
		return fmt.Errorf("任务创建失败: %s", string(body))
	}

	color.Green("[+] 任务 '%s' 创建成功，正在扫描目标 '%s'", taskName, target)
	displayScanConfig(config)
	return nil
}

// 输出扫描配置
func displayScanConfig(config *Config) {
	color.Cyan("\n扫描配置:")
	fmt.Printf("域名爆破: %t\n域名查询插件: %t\n端口扫描: %t\n跳过CDN: %t\n服务识别: %t\n操作系统识别: %t\n站点识别: %t\n文件泄露扫描: %t\nDNS字典智能生成: %t\n站点爬虫: %t\n站点截图: %t\nARL 历史查询: %t\n",
		config.DomainBrute, config.DNSQueryPlugin, config.PortScan, config.SkipScanCDNIP, config.ServiceDetection, config.OSDetection,
		config.SiteIdentify, config.FileLeak, config.AltDNS, config.SiteSpider, config.SiteCapture, config.ARLSearch)
}

// 获取任务列表并进行美化格式输出
func getTaskList(url, token string) {
	req, err := http.NewRequest("GET", url+"api/task/?page=1&size=100", nil)
	if err != nil {
		color.Red("获取任务列表失败: %v", err)
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
		color.Red("请求失败: %v", err)
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		color.Red("获取任务列表失败: %s", string(body))
		return
	}

	// 解析任务列表
	var taskList TaskListResponse
	err = json.Unmarshal(body, &taskList)
	if err != nil {
		color.Red("解析任务列表失败: %v", err)
		return
	}

	// 使用 tabwriter 设置表格格式化输出
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.AlignRight|tabwriter.Debug)

	// 表头
	fmt.Fprintln(w, "任务名\t站点统计\t域名统计\t状态\t开始时间\t结束时间\t任务ID")
	fmt.Fprintln(w, "------------------------------------------------------------------------")

	// 遍历任务列表并输出信息
	for _, task := range taskList.Items {
		statisticsSites := fmt.Sprintf("%d", task.Statistic.SiteCnt)
		statisticsDomains := fmt.Sprintf("%d", task.Statistic.DomainCnt)
		startTime := formatTime(task.StartTime)
		endTime := formatTime(task.EndTime)
		status := getStatus(task.Status)

		// 输出每个任务的信息，确保列对齐
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			task.Name, statisticsSites, statisticsDomains, status, startTime, endTime, task.ID)
	}

	// 刷新输出，确保表格正确显示
	w.Flush()
}

// 格式化时间，保持简洁
func formatTime(timeStr string) string {
	if timeStr == "-" || timeStr == "" {
		return "-"
	}

	parsedTime, err := time.Parse("2006-01-02 15:04:05", timeStr)
	if err != nil {
		return timeStr // 返回原始时间格式
	}

	return parsedTime.Format("2006/01/02 15:04")
}

// 获取任务状态并返回对应的颜色
func getStatus(status string) string {
	switch status {
	case "done":
		return color.GreenString("已完成")
	case "stop":
		return color.RedString("已停止")
	default:
		return color.BlueString("正在运行")
	}
}
