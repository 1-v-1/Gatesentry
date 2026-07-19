package gatesentryWebserverEndpoints

import (
	"encoding/json"
	"net/http"

	GatesentryTypes "bitbucket.org/abdullah_irfan/gatesentryf/types"
	"github.com/gorilla/mux"
)

// MITMListManagerInterface is the contract the endpoint layer needs from a
// MITM-list manager. Defined here (rather than in the application package)
// so the endpoints package never depends on the application package's
// concrete MITMListManager.
type MITMListManagerInterface interface {
	GetList() ([]GatesentryTypes.MITMListEntry, error)
	Get(id string) (*GatesentryTypes.MITMListEntry, error)
	Add(entry GatesentryTypes.MITMListEntry) (GatesentryTypes.MITMListEntry, error)
	Update(id string, updated GatesentryTypes.MITMListEntry) error
	Delete(id string) error
	MatchHost(host string) (*GatesentryTypes.MITMListEntry, bool)
}

var mitmListManager MITMListManagerInterface

// InitMITMListManager wires the global manager used by the handlers below.
// Must be called before the routes start serving traffic.
func InitMITMListManager(m MITMListManagerInterface) {
	mitmListManager = m
}

// RegisterMITMListEndpoints mounts the /api/mitmlist routes on the supplied
// router using gorilla/mux. Authentication and JSON parsing are handled by
// each handler explicitly, matching the Rules endpoint pattern.
func RegisterMITMListEndpoints(router *mux.Router, m MITMListManagerInterface) {
	InitMITMListManager(m)

	router.HandleFunc("/api/mitmlist", GSApiMITMListGetAll).Methods("GET")
	router.HandleFunc("/api/mitmlist", GSApiMITMListCreate).Methods("POST")
	router.HandleFunc("/api/mitmlist/{id}", GSApiMITMListGet).Methods("GET")
	router.HandleFunc("/api/mitmlist/{id}", GSApiMITMListUpdate).Methods("PUT")
	router.HandleFunc("/api/mitmlist/{id}", GSApiMITMListDelete).Methods("DELETE")
	router.HandleFunc("/api/mitmlist/test", GSApiMITMListTest).Methods("POST")
}

// GetMITMListManager exposes the live manager instance to other endpoint
// handlers (mostly for diagnostic / debugging routes).
func GetMITMListManager() MITMListManagerInterface {
	return mitmListManager
}

func GSApiMITMListGetAll(w http.ResponseWriter, r *http.Request) {
	if mitmListManager == nil {
		http.Error(w, "MITM list manager not initialized", http.StatusInternalServerError)
		return
	}
	entries, err := mitmListManager.GetList()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"entries": entries,
	})
}

func GSApiMITMListGet(w http.ResponseWriter, r *http.Request) {
	if mitmListManager == nil {
		http.Error(w, "MITM list manager not initialized", http.StatusInternalServerError)
		return
	}
	vars := mux.Vars(r)
	entry, err := mitmListManager.Get(vars["id"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if entry == nil {
		http.Error(w, "entry not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entry)
}

func GSApiMITMListCreate(w http.ResponseWriter, r *http.Request) {
	if mitmListManager == nil {
		http.Error(w, "MITM list manager not initialized", http.StatusInternalServerError)
		return
	}
	var entry GatesentryTypes.MITMListEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	created, err := mitmListManager.Add(entry)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "MITM list entry created",
		"entry":   created,
	})
}

func GSApiMITMListUpdate(w http.ResponseWriter, r *http.Request) {
	if mitmListManager == nil {
		http.Error(w, "MITM list manager not initialized", http.StatusInternalServerError)
		return
	}
	vars := mux.Vars(r)
	var entry GatesentryTypes.MITMListEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := mitmListManager.Update(vars["id"], entry); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "MITM list entry updated",
		"entry":   entry,
	})
}

func GSApiMITMListDelete(w http.ResponseWriter, r *http.Request) {
	if mitmListManager == nil {
		http.Error(w, "MITM list manager not initialized", http.StatusInternalServerError)
		return
	}
	vars := mux.Vars(r)
	if err := mitmListManager.Delete(vars["id"]); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "MITM list entry deleted",
	})
}

// GSApiMITMListTest resolves a host against the live MITM list and returns
// the matched entry (or a `matched: false` payload). Useful for the UI to
// live-preview whether a regex will fire before saving the entry.
func GSApiMITMListTest(w http.ResponseWriter, r *http.Request) {
	if mitmListManager == nil {
		http.Error(w, "MITM list manager not initialized", http.StatusInternalServerError)
		return
	}
	var req struct {
		Host string `json:"host"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	entry, matched := mitmListManager.MatchHost(req.Host)
	w.Header().Set("Content-Type", "application/json")
	if !matched {
		json.NewEncoder(w).Encode(map[string]interface{}{"matched": false})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"matched": true,
		"entry":   entry,
	})
}
