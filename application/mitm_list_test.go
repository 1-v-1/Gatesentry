package gatesentryf

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"

	gatesentry2storage "bitbucket.org/abdullah_irfan/gatesentryf/storage"
	GatesentryTypes "bitbucket.org/abdullah_irfan/gatesentryf/types"
)

// newTestManager builds an isolated MITMListManager backed by a temp file.
// Each test gets its own file so concurrent runs don't collide.
func newTestManager(t *testing.T) *MITMListManager {
	t.Helper()
	dir := t.TempDir()
	storage := gatesentry2storage.NewMapStore(filepath.Join(dir, "settings"), true)
	return NewMITMListManager(storage)
}

func TestMITMListManager_EmptyGet(t *testing.T) {
	m := newTestManager(t)
	got, err := m.GetList()
	if err != nil {
		t.Fatalf("GetList: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty list, got %d entries", len(got))
	}
	if _, matched := m.MatchHost("anything"); matched {
		t.Fatalf("expected no match on empty manager")
	}
}

func TestMITMListManager_AddUpdateDelete_RoundTrip(t *testing.T) {
	m := newTestManager(t)
	in := GatesentryTypes.MITMListEntry{
		Name:     "GitHub passthrough",
		Regex:    `.*\.github\.com`,
		Action:   GatesentryTypes.MITMListActionPassthrough,
		Priority: 5,
		Enabled:  true,
	}
	created, err := m.Add(in)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if created.ID == "" {
		t.Fatalf("Add must populate ID")
	}

	got, err := m.GetList()
	if err != nil || len(got) != 1 {
		t.Fatalf("GetList: %v / %d entries", err, len(got))
	}
	if got[0].Name != in.Name {
		t.Fatalf("Name round-trip failed: got %q", got[0].Name)
	}

	// Update — change action.
	updated := created
	updated.Action = GatesentryTypes.MITMListActionBlackhole
	if err := m.Update(created.ID, updated); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ = m.GetList()
	if got[0].Action != GatesentryTypes.MITMListActionBlackhole {
		t.Fatalf("Update did not persist action: got %q", got[0].Action)
	}

	// Delete — empty after.
	if err := m.Delete(created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	got, _ = m.GetList()
	if len(got) != 0 {
		t.Fatalf("expected empty after delete, got %d", len(got))
	}
}

func TestMITMListManager_PriorityOrdering(t *testing.T) {
	m := newTestManager(t)
	// Lower priority wins. We add in reverse priority so the snapshot must reorder.
	if _, err := m.Add(GatesentryTypes.MITMListEntry{
		Name: "catch-all", Regex: `.*`, Action: GatesentryTypes.MITMListActionFilter, Priority: 100, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Add(GatesentryTypes.MITMListEntry{
		Name: "exact", Regex: `^example\.com$`, Action: GatesentryTypes.MITMListActionPassthrough, Priority: 5, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Add(GatesentryTypes.MITMListEntry{
		Name: "fallback", Regex: `.*\.example\.com`, Action: GatesentryTypes.MITMListActionBlackhole, Priority: 50, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		host       string
		wantName   string
		wantAction GatesentryTypes.MITMListAction
	}{
		{"example.com", "exact", GatesentryTypes.MITMListActionPassthrough},
		{"www.example.com", "fallback", GatesentryTypes.MITMListActionBlackhole},
		{"github.com", "catch-all", GatesentryTypes.MITMListActionFilter},
	}
	for _, tc := range cases {
		entry, ok := m.MatchHost(tc.host)
		if !ok {
			t.Errorf("%s: no match", tc.host)
			continue
		}
		if entry.Name != tc.wantName {
			t.Errorf("%s: got %q want %q", tc.host, entry.Name, tc.wantName)
		}
		if entry.Action != tc.wantAction {
			t.Errorf("%s: action %q want %q", tc.host, entry.Action, tc.wantAction)
		}
	}
}

func TestMITMListManager_DisabledSkipped(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Add(GatesentryTypes.MITMListEntry{
		Name: "high", Regex: `^example\.com$`, Action: GatesentryTypes.MITMListActionPassthrough, Priority: 1, Enabled: false,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Add(GatesentryTypes.MITMListEntry{
		Name: "fallback", Regex: `.*`, Action: GatesentryTypes.MITMListActionFilter, Priority: 100, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	entry, ok := m.MatchHost("example.com")
	if !ok {
		t.Fatal("expected fallback to match")
	}
	if entry.Name != "fallback" {
		t.Fatalf("disabled entry was matched instead of fallback: got %q", entry.Name)
	}
}

func TestMITMListManager_InvalidRegexRejected(t *testing.T) {
	m := newTestManager(t)
	_, err := m.Add(GatesentryTypes.MITMListEntry{
		Name: "bad", Regex: `[invalid`, Action: GatesentryTypes.MITMListActionFilter, Priority: 1, Enabled: true,
	})
	if err == nil {
		t.Fatal("expected validation error for invalid regex")
	}
	if !strings.Contains(err.Error(), "regex") {
		t.Fatalf("expected regex-related error, got %v", err)
	}
	got, _ := m.GetList()
	if len(got) != 0 {
		t.Fatalf("entry should not have been persisted on validation failure")
	}
}

func TestMITMListManager_InvalidActionRejected(t *testing.T) {
	m := newTestManager(t)
	_, err := m.Add(GatesentryTypes.MITMListEntry{
		Name: "bad-action", Regex: `.*`, Action: GatesentryTypes.MITMListAction("nuke"), Priority: 1, Enabled: true,
	})
	if err == nil {
		t.Fatal("expected validation error for unknown action")
	}
}

func TestMITMListManager_CaseInsensitive(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Add(GatesentryTypes.MITMListEntry{
		Name: "case", Regex: `^Example\.Com$`, Action: GatesentryTypes.MITMListActionFilter, Priority: 1, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"example.com", "EXAMPLE.COM", "ExAmPlE.cOm"} {
		if _, ok := m.MatchHost(h); !ok {
			t.Errorf("expected case-insensitive match for %q", h)
		}
	}
}

func TestMITMListManager_SnapshotConsistentAfterAdd(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Add(GatesentryTypes.MITMListEntry{
		Name: "x", Regex: `.*`, Action: GatesentryTypes.MITMListActionFilter, Priority: 1, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if len(m.snapshot) != 1 {
		t.Fatalf("Add should have refreshed the snapshot; got len=%d", len(m.snapshot))
	}
}

func TestMITMListManager_DeleteUnknownIsNoop(t *testing.T) {
	m := newTestManager(t)
	if err := m.Delete("does-not-exist"); err != nil {
		t.Fatalf("Delete on unknown id should be idempotent, got %v", err)
	}
}

func TestMITMListManager_ConcurrentReadersAndWriter(t *testing.T) {
	m := newTestManager(t)
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writer goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_, _ = m.Add(GatesentryTypes.MITMListEntry{
				Name:     "x",
				Regex:    `^host[0-9]+\.example\.com$`,
				Action:   GatesentryTypes.MITMListActionFilter,
				Priority: i,
				Enabled:  true,
			})
			select {
			case <-stop:
				return
			default:
			}
		}
	}()

	// Reader goroutines
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				_, _ = m.MatchHost("host1.example.com")
				_, _ = m.GetList()
			}
		}()
	}

	wg.Wait()
	close(stop)
}
