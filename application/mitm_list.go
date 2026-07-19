package gatesentryf

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	gatesentry2storage "bitbucket.org/abdullah_irfan/gatesentryf/storage"
	GatesentryTypes "bitbucket.org/abdullah_irfan/gatesentryf/types"
	gatesentryUtils "bitbucket.org/abdullah_irfan/gatesentryf/utils"
)

const mitmListStorageKey = "mitm_list"

// MITMListManager owns the MITM list and exposes CRUD + MatchHost. The hot
// path reads `snapshot` under a read lock; writers (Add/Update/Delete)
// acquire the write lock around persist + Reload.
type MITMListManager struct {
	storage  *gatesentry2storage.MapStore
	reloadMu sync.RWMutex
	snapshot []GatesentryTypes.MITMListEntry
}

// NewMITMListManager builds a manager, primes `SetDefault("mitm_list", "")`
// so the key exists on first run, and reloads the in-memory snapshot.
func NewMITMListManager(storage *gatesentry2storage.MapStore) *MITMListManager {
	storage.SetDefault(mitmListStorageKey, "")
	m := &MITMListManager{storage: storage}
	m.Reload()
	return m
}

// Reload rebuilds the in-memory snapshot from storage. Safe to call at any
// time; idempotent. Skips regex compilation for entries whose regex fails
// to compile (logs a warning) so a corrupt entry can't crash the hot path.
func (m *MITMListManager) Reload() {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()

	data := m.storage.Get(mitmListStorageKey)
	if data == "" {
		m.snapshot = []GatesentryTypes.MITMListEntry{}
		return
	}

	// New format: {"entries": [...]} — mirror RuleManager.GetRules.
	var list GatesentryTypes.MITMList
	if err := json.Unmarshal([]byte(data), &list); err == nil {
		m.snapshot = compileAndSort(list.Entries)
		return
	}
	// Legacy / bare-array fallback.
	var entries []GatesentryTypes.MITMListEntry
	if err := json.Unmarshal([]byte(data), &entries); err != nil {
		log.Printf("[MITMList] storage corrupted (json unmarshal failed): %v", err)
		m.snapshot = []GatesentryTypes.MITMListEntry{}
		return
	}
	m.snapshot = compileAndSort(entries)
}

// Snapshot returns a copy of the in-memory list for read-only consumers.
func (m *MITMListManager) Snapshot() []GatesentryTypes.MITMListEntry {
	m.reloadMu.RLock()
	defer m.reloadMu.RUnlock()
	out := make([]GatesentryTypes.MITMListEntry, len(m.snapshot))
	copy(out, m.snapshot)
	return out
}

// GetList returns all entries (sorted ascending by priority). Persists a
// sanitized copy — the `Compiled` field is unexported.
func (m *MITMListManager) GetList() ([]GatesentryTypes.MITMListEntry, error) {
	return m.Snapshot(), nil
}

// Get returns a single entry by ID, or nil if not found.
func (m *MITMListManager) Get(id string) (*GatesentryTypes.MITMListEntry, error) {
	m.reloadMu.RLock()
	defer m.reloadMu.RUnlock()
	for i := range m.snapshot {
		if m.snapshot[i].ID == id {
			e := m.snapshot[i]
			return &e, nil
		}
	}
	return nil, nil
}

// Add validates the entry (regex must compile, action must be one of the
// three known values), assigns an ID if missing, then persists and reloads.
func (m *MITMListManager) Add(entry GatesentryTypes.MITMListEntry) (GatesentryTypes.MITMListEntry, error) {
	if err := validateEntry(&entry); err != nil {
		return entry, err
	}
	now := time.Now().Format(time.RFC3339)
	entry.CreatedAt = now
	entry.UpdatedAt = now
	if entry.ID == "" {
		entry.ID = generateMITMListID()
	}

	entries, err := m.entriesWithoutCompiled()
	if err != nil {
		return entry, err
	}
	entries = append(entries, entry)
	if err := m.persist(entries); err != nil {
		return entry, err
	}
	m.Reload()
	return entry, nil
}

// Update replaces the entry with the given ID.
func (m *MITMListManager) Update(id string, updated GatesentryTypes.MITMListEntry) error {
	if err := validateEntry(&updated); err != nil {
		return err
	}
	entries, err := m.entriesWithoutCompiled()
	if err != nil {
		return err
	}
	found := false
	for i := range entries {
		if entries[i].ID == id {
			updated.ID = id
			updated.CreatedAt = entries[i].CreatedAt
			updated.UpdatedAt = time.Now().Format(time.RFC3339)
			entries[i] = updated
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("entry not found: %s", id)
	}
	if err := m.persist(entries); err != nil {
		return err
	}
	m.Reload()
	return nil
}

// Delete removes the entry with the given ID. Idempotent — deleting a
// missing entry succeeds.
func (m *MITMListManager) Delete(id string) error {
	entries, err := m.entriesWithoutCompiled()
	if err != nil {
		return err
	}
	filtered := entries[:0]
	for _, e := range entries {
		if e.ID != id {
			filtered = append(filtered, e)
		}
	}
	if len(filtered) == 0 {
		filtered = []GatesentryTypes.MITMListEntry{}
	}
	if err := m.persist(filtered); err != nil {
		return err
	}
	m.Reload()
	return nil
}

// MatchHost returns the highest-priority enabled entry whose regex matches
// the host (case-insensitive). Returns (nil, false) when no entry matches.
// Reads `snapshot` under the read lock so it stays consistent with writers.
func (m *MITMListManager) MatchHost(host string) (*GatesentryTypes.MITMListEntry, bool) {
	host = strings.ToLower(host)
	m.reloadMu.RLock()
	defer m.reloadMu.RUnlock()
	for i := range m.snapshot {
		e := &m.snapshot[i]
		if !e.Enabled || e.Compiled == nil {
			continue
		}
		if e.Compiled.MatchString(host) {
			// Return a copy so the caller can't observe a later mutation
			// of `snapshot` (writers swap the slice on Reload).
			entry := *e
			return &entry, true
		}
	}
	return nil, false
}

// --- internals ---

func (m *MITMListManager) entriesWithoutCompiled() ([]GatesentryTypes.MITMListEntry, error) {
	data := m.storage.Get(mitmListStorageKey)
	if data == "" {
		return []GatesentryTypes.MITMListEntry{}, nil
	}
	var list GatesentryTypes.MITMList
	if err := json.Unmarshal([]byte(data), &list); err == nil {
		return list.Entries, nil
	}
	var entries []GatesentryTypes.MITMListEntry
	if err := json.Unmarshal([]byte(data), &entries); err != nil {
		return nil, fmt.Errorf("invalid storage: %w", err)
	}
	return entries, nil
}

func (m *MITMListManager) persist(entries []GatesentryTypes.MITMListEntry) error {
	wrapped := GatesentryTypes.MITMList{Entries: entries}
	bs, err := json.Marshal(wrapped)
	if err != nil {
		return err
	}
	m.storage.Update(mitmListStorageKey, string(bs))
	return nil
}

// validateEntry checks that an entry has a compilable regex and a known
// action. Mutates the entry by attaching the compiled regex so callers can
// reuse it without recompiling. Regexes are forced case-insensitive because
// the matched host is not normalised ahead of time in all proxy paths.
func validateEntry(e *GatesentryTypes.MITMListEntry) error {
	if strings.TrimSpace(e.Regex) == "" {
		return fmt.Errorf("regex is required")
	}
	re, err := compileCaseInsensitive(e.Regex)
	if err != nil {
		return fmt.Errorf("invalid regex: %w", err)
	}
	e.Compiled = re
	switch e.Action {
	case GatesentryTypes.MITMListActionFilter,
		GatesentryTypes.MITMListActionPassthrough,
		GatesentryTypes.MITMListActionBlackhole:
	default:
		return fmt.Errorf("invalid action: %q", e.Action)
	}
	return nil
}

// compileCaseInsensitive returns a compiled regex that ignores case. The
// raw pattern is preserved so users can keep their natural casing — we
// inject `(?i)` once at compile time.
func compileCaseInsensitive(pattern string) (*regexp.Regexp, error) {
	if strings.HasPrefix(pattern, "(?i)") {
		return regexp.Compile(pattern)
	}
	return regexp.Compile("(?i)" + pattern)
}

// compileAndSort returns a fresh slice sorted ascending by priority (then by
// CreatedAt as a stable tiebreaker) with each entry's Compiled field filled.
func compileAndSort(in []GatesentryTypes.MITMListEntry) []GatesentryTypes.MITMListEntry {
	out := make([]GatesentryTypes.MITMListEntry, len(in))
	copy(out, in)
	for i := range out {
		re, err := compileCaseInsensitive(out[i].Regex)
		if err != nil {
			log.Printf("[MITMList] entry %q has invalid regex %q: %v — skipping match",
				out[i].Name, out[i].Regex, err)
			out[i].Compiled = nil
			continue
		}
		out[i].Compiled = re
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].CreatedAt < out[j].CreatedAt
	})
	return out
}

func generateMITMListID() string {
	return gatesentryUtils.RandomString(16)
}
