package gatesentryproxy

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/h2non/filetype"
)

var IProxy *GSProxy
var MaxContentScanSize int64 = 1e7 // Reduced from 100MB to 10MB for low-spec hardware
var DebugLogging = false           // Disable verbose logging for performance
var ip6Loopback = net.ParseIP("::1")
var httpTransport = &http.Transport{
	Proxy:                 http.ProxyFromEnvironment,
	DialContext:           DialUpstream,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

func NewGSProxyPassthru() *GSProxyPassthru {
	p := GSProxyPassthru{}
	p.ProxyActionToLog = ProxyActionFilterNone
	return &p
}

func NewGSHandler(handlerid string, f func(*[]byte, *GSResponder, *GSProxyPassthru)) *GSHandler {
	// h := GSHandler{Id: handlerid, Handle: f}
	// h.Handle = f;
	// return &h
	return nil
}

func NewGSProxy() *GSProxy {
	proxy := GSProxy{}
	IProxy = &proxy
	IProxy.UsersCache = map[string]GSUserCached{}
	return &proxy
}

func (p *GSProxy) RegisterHandler(id string, f func(*[]byte, *GSResponder, *GSProxyPassthru)) {
	h := NewGSHandler(id, f)
	if p.Handlers == nil {
		p.Handlers = map[string][]*GSHandler{}
	}
	log.Printf("Registering Handler for " + id)
	mm, ok := p.Handlers[id]
	if !ok {
		mm = ([]*GSHandler{})
		p.Handlers[id] = mm
	}
	p.Handlers[id] = append(p.Handlers[id], h)
}

func (p *GSProxy) RegisterAuthHandler(f func(authheader string) bool) {
	log.Println("Registering Auth Handler")
	p.AuthHandler = f
}

func (p *GSProxy) RunHandler(handlerid string, content *GSContentFilterData) {
	if p.Handlers[handlerid] != nil {
		for i := 0; i < len(p.Handlers[handlerid]); i++ {
			p.Handlers[handlerid][i].Handle(content)
		}
	}
}

func (p *GSProxy) RunAuthHandler(authheader string) bool {
	if p.AuthHandler != nil {
		return p.AuthHandler(authheader)
	}
	return false
}

func InitProxy() {
	CreateBlockedImageBytes()
	MaxContentScanSize = 1e7 // 10MB for low-spec hardware
}

type ProxyHandler struct {
	// TLS is whether this is an HTTPS connection.
	TLS bool

	// connectPort is the server port that was specified in a CONNECT request.
	connectPort string

	// user is a user that has already been authenticated.
	user string

	// rt is the RoundTripper that will be used to fulfill the requests.
	// If it is nil, a default Transport will be used.
	rt http.RoundTripper

	Iproxy *GSProxy
}

func decodeBase64Credentials(auth string) (user, pass string, ok bool) {
	auth = strings.TrimSpace(auth)
	enc := base64.StdEncoding

	// Use buffer pool for small allocations
	bufPtr := GetSmallBuffer()
	defer PutSmallBuffer(bufPtr)
	buf := *bufPtr

	n, err := enc.Decode(buf, []byte(auth))
	if err != nil {
		return "", "", false
	}
	auth = string(buf[:n])

	colon := strings.Index(auth, ":")
	if colon == -1 {
		return "", "", false
	}

	return auth[:colon], auth[colon+1:], true
}

type DataPassThru struct {
	io.Writer
	Bytes []byte
	// total int64 // Total # of bytes transferred
	Contenttype string
	Passthru    *GSProxyPassthru
}

func (pt *DataPassThru) Write(p []byte) (int, error) {
	n, err := pt.Writer.Write(p)
	pt.Bytes = append(pt.Bytes, p...)
	if err == nil {
		IProxy.ContentSizeHandler(
			GSContentSizeFilterData{
				Url:         "",
				ContentType: pt.Contenttype,
				ContentSize: int64(n),
				User:        pt.Passthru.User,
			},
		)
	}
	return n, err
}

func (h ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	passthru := NewGSProxyPassthru()

	client := r.RemoteAddr
	host, _, err := net.SplitHostPort(client)
	if err == nil {
		client = host
	}

	if TransparentProxyEnabled && IsTransparentProxyRequest(r) {
		if DebugLogging {
			log.Printf("[Transparent] Detected transparent proxy request from %s to %s", client, r.Host)
		}

		originalDst := r.Host
		if originalDst == "" {
			log.Printf("[Transparent] No Host header in transparent request from %s", client)
			http.Error(w, "No Host header", http.StatusBadRequest)
			return
		}

		if !strings.Contains(originalDst, ":") {
			originalDst = net.JoinHostPort(originalDst, "80")
		}

		r.URL.Scheme = "http"
		r.URL.Host = originalDst
	}

	hostaddress := strings.Split(r.URL.Host, ":")[0]
	isHostLanAddress := isLanAddress(hostaddress)

	if len(r.URL.String()) > 10000 {
		http.Error(w, "URL too long", http.StatusRequestURITooLong)
		return
	}

	if r.URL.Scheme == "" {
		if h.TLS {
			r.URL.Scheme = "https"
		} else {
			r.URL.Scheme = "http"
		}
	}
	if r.URL.Host == "" {
		if r.Host != "" {
			r.URL.Host = r.Host
		} else {
			log.Printf("Request from %s has no host in URL: %v", client, r.URL)
			time.Sleep(time.Second)
			http.Error(w, "No host in request URL, and no Host header.", http.StatusBadRequest)
			return
		}
	}

	authEnabled := true
	authEnabled = IProxy.IsAuthEnabled()
	user, _, authUser := HandleAuthAndAssignUser(r, passthru, h, authEnabled, client)
	if authEnabled {
		if user == "" || user == "127.0.0.1" {
			w.Header().Set("Proxy-Authenticate", "Basic realm="+"gsrealm")
			http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
			log.Printf("Missing required proxy authentication from %v to %v", r.RemoteAddr, r.URL)
			return
		} else {
			// _, userAuthStatus := IProxy.RunHandler("isaccessactive", "", &EMPTY_BYTES, passthru)
			userAccessFilterData := GSUserAccessFilterData{User: user}
			IProxy.UserAccessHandler(&userAccessFilterData)
			userAuthStatusString := userAccessFilterData.FilterResponseAction

			if DebugLogging {
				log.Println("User auth status = ", userAuthStatusString, " For user = ", user)
			}
			if userAuthStatusString == ProxyActionUserNotFound {
				w.Header().Set("Proxy-Authenticate", "Basic realm="+"gsrealm")
				http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
				log.Printf("Missing required proxy authentication from %v to %v", r.RemoteAddr, r.URL)
				return
			}
			if userAuthStatusString != ProxyActionUserActive && !isHostLanAddress {
				sendBlockMessageBytes(w, r, nil, userAccessFilterData.FilterResponse, nil)
				return
			}
		}
	}

	action := ACTION_NONE

	// requestUrlBytes := []byte(r.URL.String())
	// isBlockedInternet, _ := IProxy.RunHandler(FILTER_USER_ACCESS_DISABLED, "", &requestUrlBytes, passthru)
	// userAccess := GSUserAccessFilterData{User: user}
	// IProxy.UserAccessHandler(&userAccess)
	// if userAccess.FilterResponseAction == (ProxyActionBlockedInternetForUser) {
	// 	// requestUrlBytes_log := []byte(r.URL.String())
	// 	passthru.ProxyActionToLog = ProxyActionBlockedInternetForUser
	// 	// IProxy.RunHandler("log", "", &requestUrlBytes_log, passthru)
	// 	IProxy.LogHandler(GSLogData{Url: r.URL.String(), User: user, Action: ProxyActionBlockedInternetForUser})
	// 	showBlockPage(w, r, nil, userAccess.FilterResponse)
	// 	return
	// }

	// timeblocked, _ := IProxy.RunHandler(FILTER_TIME, "", &EMPTY_BYTES, passthru)
	timefilterData := GSTimeAccessFilterData{Url: r.URL.String(), User: user}
	IProxy.TimeAccessHandler(&timefilterData)
	if timefilterData.FilterResponseAction == string(ProxyActionBlockedTime) {
		passthru.ProxyActionToLog = ProxyActionBlockedTime
		IProxy.LogHandler(GSLogData{Url: r.URL.String(), User: user, Action: ProxyActionBlockedTime})
		sendBlockMessageBytes(w, r, nil, timefilterData.FilterResponse, nil)
		return
	}

	if r.Method == "CONNECT" {
		hostport := r.URL.Host
		host, port, err := net.SplitHostPort(hostport)
		if err, ok := err.(*net.AddrError); ok && err.Err == "too many colons in address" {
			colon := strings.LastIndex(hostport, ":")
			host, port = hostport[:colon], hostport[colon+1:]
			if ip := net.ParseIP(host); ip != nil {
				r.URL.Host = net.JoinHostPort(host, port)
			}
		}
	}

	urlFilterData := GSUrlFilterData{Url: r.URL.String(), User: user}

	// isBlockedUrl, _ := IProxy.RunHandler(FILTER_ACCESS_URL, "", &requestUrlBytes, passthru)
	IProxy.UrlAccessHandler(&urlFilterData)

	if urlFilterData.FilterResponseAction == ProxyActionBlockedUrl {
		passthru.ProxyActionToLog = ProxyActionBlockedUrl
		IProxy.LogHandler(GSLogData{Url: r.URL.String(), User: user, Action: ProxyActionBlockedUrl})
		sendBlockMessageBytes(w, r, nil, urlFilterData.FilterResponse, nil)
		return
	}

	fileExt := getFileExtensionFromUrl(r.URL.String())
	fileMime := getMimeByExtension(fileExt)
	contentTypeScan := &GSContentTypeFilterData{Url: r.URL.String(), ContentType: fileMime}
	IProxy.ContentTypeHandler(contentTypeScan)

	if DebugLogging {
		log.Println("Url File extension = ", fileExt, " mime ", fileMime)
	}

	if contentTypeScan.FilterResponseAction == ProxyActionBlockedFileType {
		passthru.ProxyActionToLog = ProxyActionBlockedUrl
		IProxy.LogHandler(GSLogData{Url: r.URL.String(), User: user, Action: ProxyActionBlockedUrl})
		// sendBlockMessageBytes(w, r, nil, urlFilterData.FilterResponse, nil)
		r.URL.Host = "blocked.gatesentryguard.com"
		r.URL.Scheme = "https"
		r.URL.Path = "/file/gatesentryguard/blocked.svg"
		// query := r.URL.Query()
		// query.Add("text", "Blocked")
		// r.URL.RawQuery = query.Encode()
		w.Header().Set("Location", r.URL.String())
		w.WriteHeader(http.StatusMovedPermanently)
		log.Println("Modified url = ", r.URL.String())
		// return
	}

	if r.Method == "CONNECT" {
		action = ACTION_SSL_BUMP
	}

	requestHost, _, _ := net.SplitHostPort(r.URL.Host)
	if requestHost == "" {
		requestHost = r.URL.Host
	}

	shouldBlock, ruleMatch, ruleShouldMITM := CheckProxyRules(requestHost, user)
	if shouldBlock {
		if DebugLogging {
			log.Printf("[Proxy] Blocking request to %s by rule", r.URL.String())
		}
		LogProxyAction(r.URL.String(), user, ProxyActionBlockedUrl)
		return
	}

	ruleMatched := ruleMatch != nil
	if ruleMatch != nil {
		passthru.UserData = ruleMatch
	}

	mitmDecision := IProxy.DoMitm(r.URL.Host)
	if ruleMatched {
		// Rule match wins over the MITM list / global toggle — explicit
		// rules are higher priority than a generic list decision. Block
		// short-circuits up at proxy.go:~330 so we only land here for
		// non-blocking rule matches.
		mitmDecision = MITMDecision{ShouldMITM: ruleShouldMITM, Reason: "rule-override"}
	}

	// MITM-list / global-teller says blackhole: emit block page and drop,
	// bypassing all subsequent MITM/rule logic. sendBlockMessageBytes
	// hijacks the conn and does the synthetic TLS handshake for HTTPS.
	if mitmDecision.ShouldBlock {
		if DebugLogging {
			log.Printf("[Proxy] Blocking %s by MITM decision (%s)", r.URL.String(), mitmDecision.Reason)
		}
		sendBlockMessageBytes(w, r, nil, mitmDecision.BlockPage, nil)
		LogProxyAction(r.URL.String(), user, ProxyActionBlockedUrl)
		return
	}
	shouldMitm := mitmDecision.ShouldMITM

	if DebugLogging {
		log.Println("Should MITM = ", shouldMitm, " currentAction = "+action, " for ", r.URL.String())
	}

	if isHostLanAddress {
		action = ACTION_NONE
		// modified = true
	}

	if shouldMitm == false {
		action = ACTION_NONE
	}

	if !ruleMatched {
		isExceptionUrl := IProxy.IsExceptionUrl(r.URL.String())
		if isExceptionUrl {
			action = ACTION_NONE
		}
	}

	if action == ACTION_SSL_BUMP {
		HandleSSLBump(r, w, user, authUser, passthru, IProxy)
		return
	}

	if r.Method == "CONNECT" {
		// requestUrlBytes_log := []byte(r.URL.String())
		passthru.ProxyActionToLog = ProxyActionSSLDirect
		// IProxy.RunHandler("log", "", &requestUrlBytes_log, passthru)
		IProxy.LogHandler(GSLogData{Url: r.URL.String(), User: user, Action: ProxyActionSSLDirect})
		HandleSSLConnectDirect(r, w, user, passthru)
		return
	}

	if r.Header.Get("Upgrade") == "websocket" {
		HandleWebsocketConnection(r, w)
		return
	}

	if len(r.Header["X-Forwarded-For"]) >= 10 {
		http.Error(w, "Proxy forwarding loop", http.StatusBadRequest)
		log.Printf("Proxy forwarding loop from %s to %v", r.Header.Get("X-Forwarded-For"), r.URL)
		return
	}

	gzipOK := strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") && !isLanAddress(client)
	r.Header.Del("Accept-Encoding")

	var rt http.RoundTripper
	if h.rt == nil {
		rt = httpTransport
	} else {
		rt = h.rt
	}

	if r.ContentLength == 0 {
		r.Body.Close()
		r.Body = nil
	}

	removeHopByHopHeaders(r.Header)

	resp, err := rt.RoundTrip(r)
	if err != nil {
		log.Printf("error fetching %s: %s", r.URL, err)
		// errorBytes := []byte(err.Error())
		// IProxy.RunHandler("proxyerror", "", &errorBytes, passthru)
		errorData := &GSProxyErrorData{Error: err.Error()}
		IProxy.ProxyErrorHandler(errorData)
		sendBlockMessageBytes(w, r, nil, errorData.FilterResponse, nil)
		return
	}
	defer resp.Body.Close()

	if passthru.UserData != nil {
		matchVal := reflect.ValueOf(passthru.UserData)
		if matchVal.Kind() == reflect.Struct {
			urlRegexField := matchVal.FieldByName("BlockURLRegexes")
			actionField := matchVal.FieldByName("ShouldBlock")

			if urlRegexField.IsValid() && urlRegexField.Kind() == reflect.Slice && urlRegexField.Len() > 0 {
				requestURL := r.URL.String()
				shouldBlock := false
				blockAction := actionField.IsValid() && actionField.Kind() == reflect.Bool && actionField.Bool()
				for i := 0; i < urlRegexField.Len(); i++ {
					patternVal := urlRegexField.Index(i)
					log.Println("Checking URL regex pattern ", patternVal.String(), " for ", requestURL)
					if patternVal.Kind() == reflect.String {
						pattern := patternVal.String()
						matched, err := regexp.MatchString(pattern, requestURL)
						log.Printf("Regex match result for pattern %s on URL %s: %v (err: %v)", pattern, requestURL, matched, err)
						if err == nil && matched {
							shouldBlock = blockAction
							break
						}
					}
				}

				if shouldBlock {
					passthru.ProxyActionToLog = ProxyActionBlockedUrl
					IProxy.LogHandler(GSLogData{Url: requestURL, User: user, Action: ProxyActionBlockedUrl})
					sendBlockMessageBytes(w, r, nil, []byte("URL blocked by rule"), nil)
					return
				}
			}
		}
	}

	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(contentType, ";") {
		t := strings.Split(contentType, ";")
		if len(t) > 0 {
			contentType = t[0]
		}
	}
	if DebugLogging {
		log.Println("Content type is = ", contentType, " for ", r.URL.String())
	}
	// contentTypeBytes := []byte(contentType)

	// contentTypeStatusBlocked, _ := IProxy.RunHandler("contenttypeblocked", "", &contentTypeBytes, passthru)
	contentTypeData := GSContentTypeFilterData{Url: r.URL.String(), ContentType: contentType}
	IProxy.ContentTypeHandler(&contentTypeData)

	if contentTypeData.FilterResponseAction == ProxyActionBlockedFileType {
		// requestUrlBytes_log := []byte(r.URL.String())
		passthru.ProxyActionToLog = ProxyActionBlockedFileType
		// IProxy.RunHandler("log", "", &requestUrlBytes_log, passthru)
		IProxy.LogHandler(GSLogData{Url: r.URL.String(), User: user, Action: ProxyActionBlockedFileType})
		sendBlockMessageBytes(w, r, nil, BLOCKED_CONTENT_TYPE, &contentType)
		return
	}

	var buf bytes.Buffer
	limitedReader := &io.LimitedReader{R: resp.Body, N: int64(MaxContentScanSize)}
	teeReader := io.TeeReader(limitedReader, &buf)

	localCopyData, err := io.ReadAll(teeReader)

	if err != nil {
		log.Printf("error while reading response body (URL: %s): %s", r.URL, err)
	}

	if limitedReader.N == 0 {
		log.Println("response body too long to filter:", r.URL)
		if gzipOK {
			resp.Header.Set("Content-Encoding", "gzip")
			gzw := gzip.NewWriter(w)
			defer gzw.Close()
		} else if resp.ContentLength > 0 {
			w.Header().Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
		}

		destwithcounter := &DataPassThru{
			Writer:      w,
			Contenttype: contentType,
			Passthru:    passthru,
		}

		copyResponseHeader(w, resp)

		_, err := io.Copy(destwithcounter, resp.Body)
		resp.Header.Set("Content-Encoding", "gzip")

		if err != nil {
			log.Printf("error while copying response (URL: %s): %s", r.URL, err)
			errorData := &GSProxyErrorData{Error: err.Error()}
			IProxy.ProxyErrorHandler(errorData)
			sendBlockMessageBytes(w, r, nil, errorData.FilterResponse, nil)
			return
		}
	}

	kind, _ := filetype.Match(localCopyData)
	if kind != filetype.Unknown {
		if DebugLogging {
			log.Printf("File type: %s. MIME: %s\n", kind.Extension, kind.MIME.Value)
		}
		contentType = kind.MIME.Value
	}
	responseSentMedia, proxyActionTaken := ScanMedia(localCopyData, contentType, r, w, resp, buf, passthru)
	if responseSentMedia == true {
		passthru.ProxyActionToLog = proxyActionTaken
		// IProxy.RunHandler("log", "", &requestUrlBytes, passthru)
		IProxy.LogHandler(GSLogData{Url: r.URL.String(), User: user, Action: proxyActionTaken})
		return
	}

	responseSentText, proxyActionTaken := ScanText(localCopyData, contentType, r, w, resp, buf, passthru)
	if responseSentText == true {
		passthru.ProxyActionToLog = proxyActionTaken
		// IProxy.RunHandler("log", "", &requestUrlBytes, passthru)
		IProxy.LogHandler(GSLogData{Url: r.URL.String(), User: user, Action: proxyActionTaken})
		return
	}

	if gzipOK && len(localCopyData) > 1000 {
		resp.Header.Set("Content-Encoding", "gzip")
		copyResponseHeader(w, resp)
		gzw := gzip.NewWriter(w)
		var dest io.Writer
		dest = gzw
		destwithcounter := &DataPassThru{Writer: dest, Contenttype: contentType, Passthru: passthru}
		destwithcounter.Write(localCopyData)
		gzw.Close()
	} else {
		w.Header().Set("Content-Length", strconv.Itoa(len(localCopyData)))
		copyResponseHeader(w, resp)
		destwithcounter := &DataPassThru{Writer: w, Contenttype: contentType, Passthru: passthru}
		destwithcounter.Write(localCopyData)
	}
}

func sendInsecureBlockBytes(w http.ResponseWriter, r *http.Request, resp *http.Response, content []byte, contentType *string) {
	w.WriteHeader(http.StatusOK)
	// string ends with

	if contentType != nil && isImage(*contentType) {
		reasonForBlockArray := append([]string{"", "Image blocked by Gatesentry", "Reason(s) for blocking", "1. The content type is blocked"})
		emptyImage, _ := createEmptyImage(500, 500, "jpeg", reasonForBlockArray)
		w.Header().Set("Content-Type", "image/jpeg; charset=utf-8")
		w.Write(emptyImage)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// CSP allows inline scripts/styles (admin's custom HTML may use them) and
	// data-URI images (the default block icon), but blocks external sources.
	w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline' data:; img-src 'self' data:;")
	w.Write(content)
}

func sendBlockMessageBytes(w http.ResponseWriter, r *http.Request, resp *http.Response, content []byte, contentType *string) {
	// check if request is https
	if strings.Contains(r.URL.String(), ":443") {
		log.Println("[Proxy] Sending block page for https request")
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			sendInsecureBlockBytes(w, r, resp, content, contentType)
			return
		}
		defer conn.Close()
		conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		sendBlockMessageOverConn(conn, content)
	} else {
		sendInsecureBlockBytes(w, r, resp, content, contentType)
	}

}

// sendBlockMessageOverConn performs the post-CONNECT part of "ghost bump":
// builds a self-signed server TLS config, shakes hands over the supplied
// raw conn, then writes a synthetic 403 + block-page body. Used by:
//   - sendBlockMessageBytes (CONNECT / HTTP path, after Hijack)
//   - the transparent and SOCKS5 listeners when a MITM-list entry says
//     action=blackhole
//
// The conn is closed when this function returns — callers must not reuse it.
func sendBlockMessageOverConn(conn net.Conn, content []byte) {
	tlsConfig, err := createSelfSignedTLSConfig()
	if err != nil {
		log.Printf("[Proxy][Error:sendBlockMessageOverConn] self-signed cert: %v", err)
		return
	}
	tlsConn := tls.Server(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[Proxy][Error:sendBlockMessageOverConn] handshake: %v", err)
		return
	}
	defer tlsConn.Close()
	// CSP allows inline scripts/styles (admin's custom HTML may use them) and
	// data-URI images (the default block icon), but blocks external sources.
	headers := []string{
		"HTTP/1.1 403 Forbidden\r\n",
		"Content-Security-Policy: default-src 'self' 'unsafe-inline' data:; img-src 'self' data:\r\n",
		"Content-Type: text/html\r\n\r\n",
	}
	for _, h := range headers {
		if _, err := tlsConn.Write([]byte(h)); err != nil {
			log.Printf("[Proxy][Error:sendBlockMessageOverConn] write header: %v", err)
			return
		}
	}
	if _, err := tlsConn.Write(content); err != nil {
		log.Printf("[Proxy][Error:sendBlockMessageOverConn] write body: %v", err)
		return
	}
}

// CheckProxyRules checks proxy rules for a given host and user.
// Returns: shouldBlock (bool), ruleMatch (interface{}), shouldMITM (bool)
func CheckProxyRules(host string, user string) (bool, interface{}, bool) {
	if IProxy == nil || IProxy.RuleMatchHandler == nil {
		return false, nil, false
	}

	ruleMatch := IProxy.RuleMatchHandler(host, user)
	if ruleMatch == nil {
		return false, nil, false
	}

	matchVal := reflect.ValueOf(ruleMatch)
	if matchVal.Kind() != reflect.Struct {
		return false, nil, false
	}

	matchedField := matchVal.FieldByName("Matched")
	if !matchedField.IsValid() || matchedField.Kind() != reflect.Bool || !matchedField.Bool() {
		return false, nil, false
	}

	shouldBlockField := matchVal.FieldByName("ShouldBlock")
	urlRegexField := matchVal.FieldByName("BlockURLRegexes")
	mitmField := matchVal.FieldByName("ShouldMITM")

	shouldBlock := false
	shouldMITM := false

	if shouldBlockField.IsValid() && shouldBlockField.Kind() == reflect.Bool && shouldBlockField.Bool() {
		// Only block if no URL regexes specified (domain-level block)
		if !urlRegexField.IsValid() || urlRegexField.Len() == 0 {
			shouldBlock = true
		}
	}

	if mitmField.IsValid() && mitmField.Kind() == reflect.Bool {
		shouldMITM = mitmField.Bool()
	}

	return shouldBlock, ruleMatch, shouldMITM
}

// LogProxyAction logs a proxy action with the given URL, user, and action
func LogProxyAction(url string, user string, action ProxyAction) {
	if IProxy != nil && IProxy.LogHandler != nil {
		IProxy.LogHandler(GSLogData{Url: url, User: user, Action: action})
	}
}

// copyResponseHeader writes resp's header and status code to w.
func copyResponseHeader(w http.ResponseWriter, resp *http.Response) {
	newHeader := w.Header()
	for key, values := range resp.Header {
		if key == "Content-Length" {
			continue
		}
		for _, v := range values {
			newHeader.Add(key, v)
		}
	}

	w.WriteHeader(resp.StatusCode)
}

// removeHopByHopHeaders removes header fields listed in
// http://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-14#section-7.1.3.1
func removeHopByHopHeaders(h http.Header) {
	toRemove := HOP_BY_HOP
	if c := h.Get("Connection"); c != "" {
		for _, key := range strings.Split(c, ",") {
			toRemove = append(toRemove, strings.TrimSpace(key))
		}
	}
	for _, key := range toRemove {
		h.Del(key)
	}
}

// A hijackedConn is a connection that has been hijacked (to fulfill a CONNECT
// request).
type hijackedConn struct {
	net.Conn
	io.Reader
}

func (hc *hijackedConn) Read(b []byte) (int, error) {
	return hc.Reader.Read(b)
}
