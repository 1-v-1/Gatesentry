package gatesentryproxy

type GSProxyPassthru struct {
	UserData         interface{}
	DontTouch        bool
	User             string
	ProxyActionToLog ProxyAction
}

type GSResponder struct {
	Changed bool
	Data    []byte
}

type GSHandler struct {
	Id     string
	Handle func(*GSContentFilterData)
}

type GSUserCached struct {
	User string
	Pass string
}

type GSProxy struct {
	AuthHandler        func(authheader string) bool
	ContentHandler     func(*GSContentFilterData)
	ContentTypeHandler func(*GSContentTypeFilterData)
	ContentSizeHandler func(GSContentSizeFilterData)
	UserAccessHandler  func(*GSUserAccessFilterData)
	TimeAccessHandler  func(*GSTimeAccessFilterData)
	UrlAccessHandler   func(*GSUrlFilterData)
	ProxyErrorHandler  func(*GSProxyErrorData)
	DoMitm             func(host string) MITMDecision
	IsExceptionUrl     func(url string) bool
	IsAuthEnabled      func() bool
	LogHandler         func(GSLogData)
	RuleMatchHandler   func(domain string, user string) interface{} // Returns RuleMatch
	Handlers           map[string][]*GSHandler
	UsersCache         map[string]GSUserCached
}

// MITMDecision is the result of asking the proxy whether/how to MITM a host.
// Call sites consult one struct instead of juggling booleans — see
// application/main.go for the implementation and application/types for the
// MITM list that drives filter/passthrough/blackhole outcomes.
type MITMDecision struct {
	ShouldMITM  bool   // true => run SSLBump + filter pipeline (existing pre-MITM-List behaviour when global toggle is on)
	ShouldBlock bool   // true => emit BlockPage and drop the connection. Never combined with ShouldMITM=true.
	BlockPage   []byte // body used when ShouldBlock=true. Sourced from the admin's block-page template.
	Reason      string // short label, primarily for logs: e.g. "mitm-list:github", "global-toggle", "rule-override"
}

// For the refactored filter input
type GSContentFilterData struct {
	Url                  string
	ContentType          string
	Content              []byte
	FilterResponse       []byte
	FilterResponseAction ProxyAction
}

type GSContentTypeFilterData struct {
	Url                  string
	ContentType          string
	FilterResponseAction ProxyAction
	FilterResponse       []byte
}

type GSContentSizeFilterData struct {
	Url         string
	ContentType string
	ContentSize int64
	User        string
}

type GSUserAccessFilterData struct {
	User                 string
	FilterResponseAction ProxyAction
	FilterResponse       []byte
}

type GSTimeAccessFilterData struct {
	Url                  string
	ContentType          string
	User                 string
	FilterResponseAction string
	FilterResponse       []byte
}

type GSLogData struct {
	Url         string
	ContentType string
	User        string
	Action      ProxyAction
}

type GSUrlFilterData struct {
	Url                  string
	User                 string
	FilterResponseAction ProxyAction
	FilterResponse       []byte
}

type GSProxyErrorData struct {
	Error          string
	FilterResponse []byte
}
