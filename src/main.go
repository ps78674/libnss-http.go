package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type passwd struct {
	Username string `json:"pw_name"`
	Password string `json:"pw_passwd"`
	UID      uint   `json:"pw_uid"`
	GID      uint   `json:"pw_gid"`
	Gecos    string `json:"pw_gecos"`
	Dir      string `json:"pw_dir"`
	Shell    string `json:"pw_shell"`
}

type group struct {
	Groupname string   `json:"gr_name"`
	Password  string   `json:"gr_passwd"`
	GID       uint     `json:"gr_gid"`
	Members   []string `json:"gr_mem"`
}

type shadow struct {
	Username        string      `json:"sp_namp"`
	Password        string      `json:"sp_pwdp"`
	LastChange      int         `json:"sp_lstchg"`
	MinChange       int         `json:"sp_min"`
	MaxChange       int         `json:"sp_max"`
	PasswordWarn    int         `json:"sp_warn"`
	InactiveLockout interface{} `json:"sp_inact"`
	ExpirationDate  interface{} `json:"sp_expire"`
	Reserved        interface{} `json:"sp_flag"`
}

type response struct {
	Type string
	Data []byte
	Err  error
}

var (
	passwdEntries    []passwd
	shadowEntries    []shadow
	groupEntries     []group
	passwdEntryIndex int
	shadowEntryIndex int
	groupEntryIndex  int
)

type config struct {
	url     string
	debug   bool
	timeout time.Duration
}

var (
	configFile = "/etc/nss_http.conf"
	conf       config
)

func debugFnName(s string) {
	if conf.debug {
		s = fmt.Sprintf("NSS-HTTP.go: called function %s\n", s)
		os.Stderr.WriteString(s)
	}
}

func readConfig() {
	f, err := os.Open(configFile)
	if err != nil {
		msg := fmt.Sprintf("error reading config %s: %s\n", configFile, err)
		os.Stderr.WriteString(msg)
		os.Exit(1)
	}

	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		confline := strings.SplitN(scanner.Text(), "=", 2)
		switch strings.TrimSpace(confline[0]) {
		case "HTTPSERVER", "APIURL":
			conf.url = strings.TrimSpace(confline[1])
		case "DEBUG":
			conf.debug, _ = strconv.ParseBool(strings.TrimSpace(confline[1]))
		case "TIMEOUT", "HTTPTIMEOUT":
			timeo, _ := strconv.Atoi(strings.TrimSpace(confline[1]))
			conf.timeout = time.Second * time.Duration(timeo)
		}
	}
}

// get fqdn - not using uname
func getHostname() (string, error) {
	// If conf.debug -> print func name
	debugFnName("getHostname")

	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}

	addrs, err := net.LookupIP(hostname)
	if err != nil {
		return hostname, nil
	}

	for _, addr := range addrs {
		if ipv4 := addr.To4(); ipv4 != nil {
			ip, err := ipv4.MarshalText()
			if err != nil {
				return hostname, nil
			}
			hosts, err := net.LookupAddr(string(ip))
			if err != nil || len(hosts) == 0 {
				return hostname, nil
			}
			fqdn := hosts[0]
			return strings.TrimSuffix(fqdn, "."), nil // return fqdn without trailing dot
		}
	}
	return hostname, nil
}

func doRequest(reqType string, hostname string) ([]byte, error) {
	// If conf.debug -> print func name
	debugFnName("doRequest")

	urandom, err := os.Open("/dev/urandom")
	if err != nil {
		err := fmt.Errorf("error opening urandom: %s", err)
		return nil, err
	}
	defer urandom.Close()

	reqURL := fmt.Sprintf("%s/%s?format=json&hostname=%s", conf.url, reqType, hostname)

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		err := fmt.Errorf("error creating request: %s", err)
		return nil, err
	}

	req.Header.Add("User-Agent", "NSS-HTTP.go")

	var transport = &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: conf.timeout,
		}).DialContext,
		TLSHandshakeTimeout: conf.timeout,
		// random too slow to initialize entropy on some OSs
		TLSClientConfig: &tls.Config{
			Rand: urandom,
		},
	}

	client := &http.Client{
		Timeout:   conf.timeout,
		Transport: transport,
	}

	resp, err := client.Do(req)
	if err != nil {
		err := fmt.Errorf("error getting response: %s", err)
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		err := fmt.Errorf("error reading response data: %s", err)
		return nil, err
	}

	return body, nil
}

func init() {
	readConfig()
}

func main() {}
