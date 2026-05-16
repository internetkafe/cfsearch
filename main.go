package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	targetHost   string
	scheme       string
	workers      int
	reqTimeout   time.Duration
	cidrs        arrayFlags
	filePath     string
	dedup        bool
	outputFile   string
	showProgress bool
)

type arrayFlags []string

func (a *arrayFlags) String() string { return strings.Join(*a, ",") }
func (a *arrayFlags) Set(v string) error {
	*a = append(*a, v)
	return nil
}

func init() {
	flag.StringVar(&targetHost, "target", "", "")
	flag.StringVar(&scheme, "scheme", "https", "")
	flag.IntVar(&workers, "workers", 100, "")
	flag.DurationVar(&reqTimeout, "timeout", 2*time.Second, "")
	flag.Var(&cidrs, "cidr", "")
	flag.StringVar(&filePath, "file", "", "")
	flag.BoolVar(&dedup, "dedup", false, "")
	flag.StringVar(&outputFile, "output", "cfsearch.txt", "")
	flag.BoolVar(&showProgress, "progress", false, "")
}

func main() {
	flag.Parse()
	if targetHost == "" {
		fmt.Println("укажите -target")
		os.Exit(1)
	}
	if scheme != "http" && scheme != "https" {
		fmt.Println("scheme должен быть http или https")
		os.Exit(1)
	}

	out, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ошибка открытия файла вывода: %v\n", err)
		os.Exit(1)
	}
	defer out.Close()

	ipChan := make(chan net.IP, workers)
	var genWg sync.WaitGroup

	seen := make(map[string]struct{})
	var ipMutex sync.Mutex
	var totalIPs uint64
	var checkedIPs uint64
	var foundIPs uint64

	if filePath != "" {
		genWg.Add(1)
		go func() {
			defer genWg.Done()
			f, err := os.Open(filePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ошибка открытия файла: %v\n", err)
				return
			}
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" {
					continue
				}
				ip := net.ParseIP(line)
				if ip == nil {
					continue
				}
				if dedup {
					ipMutex.Lock()
					if _, ok := seen[ip.String()]; ok {
						ipMutex.Unlock()
						continue
					}
					seen[ip.String()] = struct{}{}
					ipMutex.Unlock()
				}
				atomic.AddUint64(&totalIPs, 1)
				ipChan <- ip
			}
		}()
	}

	for _, cidr := range cidrs {
		genWg.Add(1)
		go func(cidr string) {
			defer genWg.Done()
			ip, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "неверный CIDR %s: %v\n", cidr, err)
				return
			}
			for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
				ipCopy := make(net.IP, len(ip))
				copy(ipCopy, ip)
				if dedup {
					ipMutex.Lock()
					if _, ok := seen[ipCopy.String()]; ok {
						ipMutex.Unlock()
						continue
					}
					seen[ipCopy.String()] = struct{}{}
					ipMutex.Unlock()
				}
				atomic.AddUint64(&totalIPs, 1)
				ipChan <- ipCopy
			}
		}(cidr)
	}

	go func() {
		genWg.Wait()
		close(ipChan)
	}()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
			DialContext: (&net.Dialer{
				Timeout: reqTimeout,
			}).DialContext,
		},
		Timeout: reqTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	sem := make(chan struct{}, workers)
	var workerWg sync.WaitGroup
	var fileMutex sync.Mutex

	if showProgress {
		go func() {
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				checked := atomic.LoadUint64(&checkedIPs)
				total := atomic.LoadUint64(&totalIPs)
				found := atomic.LoadUint64(&foundIPs)
				if total > 0 {
					fmt.Printf("\rпрогресс: %d / %d (%.2f%%), найдено: %d", checked, total, float64(checked)*100/float64(total), found)
				} else {
					fmt.Printf("\rпрогресс: %d, найдено: %d", checked, found)
				}
			}
		}()
	}

	for ip := range ipChan {
		sem <- struct{}{}
		workerWg.Add(1)
		go func(ip net.IP) {
			defer func() {
				<-sem
				workerWg.Done()
			}()
			if checkHTTP(ip, client) {
				entry := fmt.Sprintf("%s - %s\n", ip.String(), targetHost)
				fileMutex.Lock()
				out.WriteString(entry)
				fileMutex.Unlock()
				atomic.AddUint64(&foundIPs, 1)
				fmt.Printf("\n[+] найден origin IP: %s\n", ip.String())
			}
			atomic.AddUint64(&checkedIPs, 1)
		}(ip)
	}

	workerWg.Wait()
	if showProgress {
		fmt.Println()
	}
	fmt.Println("сканирование завершено")
}

func checkHTTP(ip net.IP, client *http.Client) bool {
	url := fmt.Sprintf("%s://%s/", scheme, ip.String())
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}
	req.Host = targetHost

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "keep-alive")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return strings.Contains(string(body), targetHost)
	}

	if resp.StatusCode >= 301 && resp.StatusCode <= 308 {
		location := resp.Header.Get("Location")
		return strings.Contains(location, targetHost)
	}

	return false
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
