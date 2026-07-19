package GatesentryTypes

import "regexp"

// MITMListAction defines what a matching MITM-list entry does to a host.
type MITMListAction string

const (
	// MITMListActionFilter — perform SSL MITM on the matching host and run
	// Gatesentry's existing filter pipeline against the cleartext request.
	MITMListActionFilter MITMListAction = "filter"
	// MITMListActionPassthrough — bypass MITM for the matching host and
	// tunnel the connection through (existing direct-connect path).
	MITMListActionPassthrough MITMListAction = "passthrough"
	// MITMListActionBlackhole — serve Gatesentry's block page and drop the
	// connection; no MITM. Requires the Gatesentry CA to be trusted on the
	// client device for a clean block page.
	MITMListActionBlackhole MITMListAction = "blackhole"
)

// MITMListEntry is one ordered regex-matching rule in the MITM list. The
// hot path reads `compiled` (filled in at Add/Update/Reload time) — never
// re-compile per request.
type MITMListEntry struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Regex       string         `json:"regex"`  // regex pattern matched against host
	Action      MITMListAction `json:"action"` // filter / passthrough / blackhole
	Priority    int            `json:"priority"`
	Enabled     bool           `json:"enabled"`
	Description string         `json:"description"`
	CreatedAt   string         `json:"created_at"`
	UpdatedAt   string         `json:"updated_at"`

	// Not serialized — populated at Add/Update/Reload.
	Compiled *regexp.Regexp `json:"-"`
}

// MITMList is the on-disk representation of the collection.
type MITMList struct {
	Entries []MITMListEntry `json:"entries"`
}
