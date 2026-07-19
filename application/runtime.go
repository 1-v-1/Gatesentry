package gatesentryf

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"time"

	"bitbucket.org/abdullah_irfan/gatesentryf/internalfiles"
	gatesentry2proxy "bitbucket.org/abdullah_irfan/gatesentryf/proxy"
	GatesentryTypes "bitbucket.org/abdullah_irfan/gatesentryf/types"
	gatesentryWebserverTypes "bitbucket.org/abdullah_irfan/gatesentryf/webserver/types"
	"bitbucket.org/abdullah_irfan/gatesentryproxy"

	"io/ioutil"
	"os"
	"runtime"
	"syscall"

	gatesentry2filters "bitbucket.org/abdullah_irfan/gatesentryf/filters"
	gatesentry2logger "bitbucket.org/abdullah_irfan/gatesentryf/logger"
	gatesentry2storage "bitbucket.org/abdullah_irfan/gatesentryf/storage"
)

//   _____       _       _____            _
//  |  __ \     | |     /  ___|          | |
//  | |  \/ __ _| |_ ___\ `--.  ___ _ __ | |_ _ __ _   _
//  | | __ / _` | __/ _ \`--. \/ _ \ '_ \| __| '__| | | |
//  | |_\ \ (_| | ||  __/\__/ /  __/ | | | |_| |  | |_| |
//   \____/\__,_|\__\___\____/ \___|_| |_|\__|_|   \__, |
//                                                  __/ |
//                                                 |___/

const GSKEEPALIVETIMEOUT = 60 * 20 //minutes
const NONALIVESBEFOREKILL = 20
const CONSUMPTIONUPDATEINTERVAL = 60 * 10
const NONCONSUMPTIONUPDATESBEFOREKILL = 24

var INSTALLATIONID = "a"
var GSAPIBASEPOINT = "a"
var GSBASEDIR = "./"
var GSBASEPATH = "/"

// const INSTALLATIONID = "3";
var GSVerString = ""

func SetGSVer(v string) {
	GSVerString = v
}

func SetInstallationID(a string) {
	INSTALLATIONID = a
}

func SetAPIBaseEndpoint(a string) {
	GSAPIBASEPOINT = a
}

type GSRuntime struct {
	WebServerPort               int
	FilterFiles                 map[string]string
	MemLog                      []GSFilterLog
	MemLogSz                    int
	Filters                     []gatesentry2filters.GSFilter
	GSWebSettings               *gatesentry2storage.MapStore
	GSSettings                  *gatesentry2storage.MapStore
	GSUpdateLog                 *gatesentry2storage.MapStore
	Logger                      *gatesentry2logger.Log
	Proxy                       *gatesentry2proxy.GSProxy
	AuthUsers                   []GatesentryTypes.GSUser
	FailedConsumptionUpdates    int
	GSUserDataSaverRunning      bool
	GSKeepSentryAliveRunning    bool
	GSConsumptionUpdaterRunning bool
	DNSServerChannel            chan int
	BoundAddress                *string
	DnsServerInfo               *GatesentryTypes.DnsServerInfo
	// MITMListManager owns the regex-driven MITM allow/passthrough/blackhole
	// list. Populated once at webserver startup before any request can hit
	// the proxy hot path. Nil before webserver start.
	MITMListManager *MITMListManager
	// BlockPageHTML is the in-memory cache of the admin-supplied custom block
	// page. Read on every proxy block event, so caching avoids re-parsing
	// GSSettings JSON on the hot path. Refresh via ReloadBlockPage().
	BlockPageHTML string
}

func SetBaseDir(a string) {
	GSBASEDIR = a
}

func GetBaseDir() string {
	return GSBASEDIR
}

// SetBasePath sets the URL base path for reverse proxy deployments.
// Normalizes to ensure leading slash, strips trailing slash (unless root "/").
// e.g., "gatesentry" → "/gatesentry", "/gatesentry/" → "/gatesentry", "" → "/"
func SetBasePath(p string) {
	if p == "" || p == "/" {
		GSBASEPATH = "/"
		return
	}
	// Ensure leading slash
	if p[0] != '/' {
		p = "/" + p
	}
	// Strip trailing slash
	if len(p) > 1 && p[len(p)-1] == '/' {
		p = p[:len(p)-1]
	}
	GSBASEPATH = p
}

func GetBasePath() string {
	return GSBASEPATH
}

func (R *GSRuntime) GSWasUpdated() {
	t := time.Now()
	ts := t.String()
	prevversions := R.GSUpdateLog.Get("versions")
	R.GSUpdateLog.Update("versions", prevversions+R.GSSettings.Get("version")+" - "+R.GetApplicationVersion()+" on = "+ts+",")
	log.Println("GateSentry was updated.")
	R.GSSettings.Update("version", R.GetApplicationVersion())
}

func (R *GSRuntime) UpdateConsumption(consumedBytes int64) {

}

func InitTasks() {
	if runtime.GOOS == "windows" {
		data, err := internalfiles.Asset("zoneinfo.zip")
		if err == nil {
			log.Println("Creating a zoneinfo file")
			err = ioutil.WriteFile(GSBASEDIR+"zoneinfo.zip", data, 0755)
			if err == nil {
				log.Println("Setting zoneinfo env variable")
				zz := "C:\\Users\\dell\\Downloads\\gs\\zoneinfo.zip"
				os.Setenv("ZONEINFO", zz)
				syscall.Setenv("ZONEINFO", zz)
				log.Println(os.Getenv("ZONEINFO"))
				log.Println(syscall.Getenv("ZONEINFO"))
			} else {
				log.Println(err.Error())
			}
		} else {
			log.Println(err.Error())
		}
	}
}

func (R *GSRuntime) Init() {
	startuptext := ` +-+-+-+-+-+-+-+-+-+-+
    |G|a|t|e|S|e|n|t|r|y|
    +-+-+-+-+-+-+-+-+-+-+`
	fmt.Println(startuptext)

	// kill process on port 53
	if runtime.GOOS == "windows" {
		cmd := exec.Command("netstat", "-ano", "|", "findstr", "53")
		out, err := cmd.Output()
		if err != nil {
			log.Println(err.Error())
		}
		log.Println(string(out))
	} else {
		cmd := exec.Command("lsof", "-i", ":53")
		out, err := cmd.Output()
		if err != nil {
			log.Println(err.Error())
		}
		log.Println(string(out))
	}

	InitTasks()
	R.MemLogSz = 1024
	R.MemLog = make([]GSFilterLog, R.MemLogSz)
	R.DnsServerInfo = &GatesentryTypes.DnsServerInfo{}

	filters := []gatesentry2filters.GSFilter{}
	gatesentry2filters.SetBaseDir(GSBASEDIR)
	R.Filters = gatesentry2filters.LoadFilters(filters)
	R.AuthUsers = []GatesentryTypes.GSUser{}
	gatesentry2storage.SetBaseDir(GSBASEDIR)
	log.Println("Making a new MapStore for GSSettings")
	R.GSSettings = gatesentry2storage.NewMapStore("GSSettings", true)
	R.GSUpdateLog = gatesentry2storage.NewMapStore("GSUpdateLog", false)
	R.GSSettings.SetDefault("strictness", "2000")
	R.GSSettings.SetDefault("general_settings", "{\"log_location\": \"./log.db\", \"admin_password\": \"admin\", \"admin_username\": \"admin\" }")
	R.GSSettings.SetDefault("blocktimes", "{\"fromhours\":0,\"tohours\":0,\"fromminutes\":58,\"tominutes\":59}")
	R.GSSettings.SetDefault("authusers", "[{\"username\": \"guest\", \"password\": \"\",\"Base64String\":\"Z3Vlc3Q6cGFzc3dvcmQ=\", \"allowaccess\": true, \"dataconsumed\": 0 }]")
	// R.GSSettings.Update("authusers", "[{\"user\": \"guest\", \"pass\": \"guest\", \"allowaccess\": true, \"dataconsumed\": 0 }]" );
	R.GSSettings.SetDefault("EnableUsers", "false")
	R.GSSettings.SetDefault("NonAlives", "0")
	R.GSSettings.SetDefault("Noheartbeat", "0")
	R.GSSettings.SetDefault("Noheartbeatmessage", "")
	R.GSSettings.SetDefault("timezone", "Europe/Oslo")
	R.GSSettings.SetDefault("enable_https_filtering", "false")
	R.GSSettings.SetDefault("enable_dns_server", "true")
	R.GSSettings.SetDefault("socks5_enabled", "true")
	R.GSSettings.SetDefault("socks5_port", "10415")
	// egress_socks5: empty = direct egress (no upstream proxy).
	// When set, Gatesentry's own outbound HTTP calls (DNS blocklist
	// downloads, AIA cert fetches, AI image scanner) go through this
	// SOCKS5 proxy. Format: socks5://[user:pass@]host:port
	R.GSSettings.SetDefault("egress_socks5", "")
	// Use environment variable for DNS resolver if set, otherwise use default
	// Environment variable takes precedence over stored settings to allow
	// containerized/deployment-time configuration
	if envResolver := os.Getenv("GATESENTRY_DNS_RESOLVER"); envResolver != "" {
		// Normalize resolver address - ensure port is included
		// Use net.SplitHostPort to properly handle IPv6 addresses
		dnsResolverValue := envResolver
		_, _, err := net.SplitHostPort(envResolver)
		if err != nil {
			// No port specified, add default :53
			// net.JoinHostPort handles IPv6 bracketing automatically
			dnsResolverValue = net.JoinHostPort(envResolver, "53")
		}
		log.Printf("[DNS] Using resolver from environment (overrides settings): %s", dnsResolverValue)
		R.GSSettings.Update("dns_resolver", dnsResolverValue)
	} else {
		R.GSSettings.SetDefault("dns_resolver", "8.8.8.8:53")
	}
	R.GSSettings.SetDefault("idemail", "")
	R.GSSettings.SetDefault("enable_ai_image_filtering", "false")
	R.GSSettings.SetDefault("ai_scanner_url", "")

	R.GSSettings.SetDefault("version", R.GetApplicationVersion())
	R.GSUpdateLog.SetDefault("versions", "")

	log.Println("Version from file = " + R.GSSettings.Get("version"))
	if R.GetApplicationVersion() != R.GSSettings.Get("version") {
		R.GSWasUpdated()
	} else {

		R.GSSettings.Update("version", R.GetApplicationVersion())
	}
	R.GSSettings.SetDefault("capem", "")
	R.GSSettings.SetDefault("keypem", "")

	// Generate the CA cert on first run (or after the admin hits
	// "regenerate certificate"). capem/keypem are empty by default; if
	// they are still empty when Init() runs, generate a fresh RSA-4096
	// root CA valid for 100 years and persist it.
	if R.GSSettings.Get("capem") == "" || R.GSSettings.Get("keypem") == "" {
		certPEM, keyPEM, err := generateCA()
		if err != nil {
			log.Fatalf("[Runtime] Failed to generate CA certificate: %v", err)
		}
		R.GSSettings.Update("capem", certPEM)
		R.GSSettings.Update("keypem", keyPEM)
		log.Printf("[Runtime] Generated new CA certificate (CN=%s, validity=100y)", caCommonName)
	}

	R.GSSettings.SetDefault("dns_custom_entries", `[
		"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
		"https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
		"https://v.firebog.net/hosts/AdguardDNS.txt",
		"https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt",
		"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts",
		"https://v.firebog.net/hosts/static/w3kbl.txt",
		"https://adaway.org/hosts.txt",
		"https://v.firebog.net/hosts/RPiList-Phishing.txt",
		"https://v.firebog.net/hosts/RPiList-Malware.txt",
		"https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt",
		"https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
		"https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt",
		"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/popupads-onlydomains.txt",
		"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt"
	]`)

	general_settings := R.GSSettings.Get("general_settings")
	general_settings_parsed := gatesentryWebserverTypes.GSGeneral_Settings{}
	json.Unmarshal([]byte(general_settings), &general_settings_parsed)

	log_location := general_settings_parsed.LogLocation
	log_location = strings.Replace(log_location, "./", "", -1)
	if !strings.HasPrefix(log_location, "/tmp") {
		log_location = GSBASEDIR + log_location
	}

	if R.Logger == nil {
		R.Logger = gatesentry2logger.NewLogger(log_location)
	} else {
		log.Println("Gatesentry Logger already exists")
	}

	for i := 0; i < len(R.Filters); i++ {
		// log.Println( R.GSSettings.GetInt("strictness") )
		R.Filters[i].Strictness = R.GSSettings.GetInt("strictness")
	}
	R.LoadUsers()
	//
	R.GSUserRunDataSaver()

	// Prime the in-memory block page cache from GSSettings so the proxy
	// hot path doesn't re-parse the settings JSON on every block event.
	R.ReloadBlockPage()

	//R.KeepAliveMonitor()

	/**
	 * 1.73
	 * Disabling Consumption Updater
	 * Consumption Updater sends utilization data (bytes passed through GS) to the main server
	 */
	ConsumptionUpdater()

	R.ReloadCertificate()

	go func() {
		dnsEnabled := R.GSSettings.Get("enable_dns_server")
		log.Println("DNS server setting = " + dnsEnabled)
		if dnsEnabled == "true" {
			R.DNSServerChannel <- 1
		} else {
			R.DNSServerChannel <- 2
		}
	}()
}

func (R *GSRuntime) GetInstallationId() string {
	return INSTALLATIONID
}

func GetApplicationVersion() string {
	return GSVerString
}

func (R *GSRuntime) GetApplicationVersion() string {
	return GetApplicationVersion()
}

func (R *GSRuntime) ReloadCertificate() {
	capembytes := []byte(R.GSSettings.Get("capem"))
	keypembytes := []byte(R.GSSettings.Get("keypem"))

	gatesentryproxy.InitWithDataCerts(capembytes, keypembytes)
}

// ReloadBlockPage refreshes the in-memory BlockPageHTML cache from GSSettings.
// Called once during Init() and again by the settings POST handler when the
// admin updates the custom HTML — so changes propagate without a restart.
func (R *GSRuntime) ReloadBlockPage() {
	if R.GSSettings == nil {
		return
	}
	R.BlockPageHTML = R.GSSettings.Get("block_page_html")
}

func (R *GSRuntime) GetTotalConsumptionData() (string, string) {
	dd, msg, err := GSGetConsumptionData(R.GetInstallationId())
	if err != nil {
		return "Unable to get Data", ""
	}
	data := GetHumanDataSize(dd)
	return data, msg
}

func (R *GSRuntime) OnHeartbeat() {
	R.GSSettings.Update("Noheartbeat", "0")
	R.GSSettings.Update("Noheartbeatmessage", "")
}

func (R *GSRuntime) OnNoHeartbeat(message string) {
	R.GSSettings.Update("Noheartbeat", "1")
	R.GSSettings.Update("Noheartbeatmessage", message)
}

func (R *GSRuntime) IsBlackoutModeActive() (bool, string) {
	/*
	   * Temporarily disabled
	   if ( R.FailedConsumptionUpdates > NONCONSUMPTIONUPDATESBEFOREKILL){
	      return true, "Unable to connect to GateSentry's Main Server.";
	   }
	*/
	active := R.GSSettings.Get("Noheartbeat")
	if active == "1" {
		message := R.GSSettings.Get("Noheartbeatmessage")
		if message == "EOF" {
			return true, "Unable to get a Keep Alive from GateSentry's Main Server."
		}
		return true, message
	}
	return false, ""
}
