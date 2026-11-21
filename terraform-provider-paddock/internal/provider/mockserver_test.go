package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// mockPaddock is an in-memory stand-in for the orchestrator endpoints the
// provider uses. It mimics the real response shapes (list endpoints without a
// GET-by-id, 204 deletes, scope deactivation, write-only integration secrets).
type mockPaddock struct {
	t   *testing.T
	mu  sync.Mutex
	seq int

	scope        map[int64]map[string]any
	alertRules   map[string]map[string]any
	owners       map[string]map[string]any
	integrations map[string]map[string]any
	secrets      map[string]map[string]string
	findings     []map[string]any
	requests     []string
}

func newMock(t *testing.T) (*mockPaddock, *httptest.Server) {
	m := &mockPaddock{
		t: t, scope: map[int64]map[string]any{}, alertRules: map[string]map[string]any{},
		owners: map[string]map[string]any{}, integrations: map[string]map[string]any{},
		secrets: map[string]map[string]string{},
	}
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)
	return m, srv
}

func (m *mockPaddock) nextID(prefix string) string {
	m.seq++
	return fmt.Sprintf("%s-%04d", prefix, m.seq)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (m *mockPaddock) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = append(m.requests, r.Method+" "+r.URL.Path)
	if r.Header.Get("Authorization") != "Bearer pak_test_key" {
		writeJSON(w, 401, map[string]any{"detail": "authentication required"})
		return
	}
	var body map[string]any
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 || parts[0] != "v1" {
		writeJSON(w, 404, map[string]any{"detail": "Not Found"})
		return
	}
	id := ""
	if len(parts) > 2 {
		id = parts[2]
	}
	switch parts[1] {
	case "scope":
		m.serveScope(w, r, id, body)
	case "alert-rules":
		m.serveCRUDList(w, r, id, body, m.alertRules, "alert rule")
	case "owners":
		m.serveCRUDList(w, r, id, body, m.owners, "owner")
	case "integrations":
		m.serveIntegrations(w, r, id, body)
	case "findings":
		m.serveFindings(w, r)
	default:
		writeJSON(w, 404, map[string]any{"detail": "Not Found"})
	}
}

func (m *mockPaddock) serveScope(w http.ResponseWriter, r *http.Request, id string, body map[string]any) {
	switch {
	case r.Method == http.MethodPost && id == "":
		m.seq++
		n := int64(m.seq)
		body["id"] = n
		body["active"] = true
		m.scope[n] = body
		writeJSON(w, 201, body)
	case r.Method == http.MethodGet && id == "":
		activeOnly := r.URL.Query().Get("active_only") != "false"
		keys := make([]int64, 0, len(m.scope))
		for k := range m.scope {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		out := []map[string]any{}
		for _, k := range keys {
			if !activeOnly || m.scope[k]["active"] == true {
				out = append(out, m.scope[k])
			}
		}
		writeJSON(w, 200, out)
	case r.Method == http.MethodDelete:
		n, _ := strconv.ParseInt(id, 10, 64)
		e, ok := m.scope[n]
		if !ok {
			writeJSON(w, 404, map[string]any{"detail": "scope entry not found"})
			return
		}
		e["active"] = false
		writeJSON(w, 200, e)
	default:
		writeJSON(w, 405, map[string]any{"detail": "Method Not Allowed"})
	}
}

func (m *mockPaddock) serveCRUDList(w http.ResponseWriter, r *http.Request, id string, body map[string]any,
	store map[string]map[string]any, what string) {
	switch {
	case r.Method == http.MethodPost && id == "":
		body["id"] = m.nextID(what)
		store[body["id"].(string)] = body
		writeJSON(w, 201, body)
	case r.Method == http.MethodGet && id == "":
		keys := make([]string, 0, len(store))
		for k := range store {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := []map[string]any{}
		for _, k := range keys {
			out = append(out, store[k])
		}
		writeJSON(w, 200, out)
	case r.Method == http.MethodPatch:
		cur, ok := store[id]
		if !ok {
			writeJSON(w, 404, map[string]any{"detail": what + " not found"})
			return
		}
		for k, v := range body {
			cur[k] = v
		}
		writeJSON(w, 200, cur)
	case r.Method == http.MethodDelete:
		if _, ok := store[id]; !ok {
			writeJSON(w, 404, map[string]any{"detail": what + " not found"})
			return
		}
		delete(store, id)
		w.WriteHeader(204)
	default:
		writeJSON(w, 405, map[string]any{"detail": "Method Not Allowed"})
	}
}

func (m *mockPaddock) public(rec map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range rec {
		if k != "secrets" {
			out[k] = v
		}
	}
	// The server re-serializes JSON objects (key order/whitespace differ).
	return out
}

func (m *mockPaddock) serveIntegrations(w http.ResponseWriter, r *http.Request, id string, body map[string]any) {
	storeSecrets := func(id string, b map[string]any) {
		if s, ok := b["secrets"].(map[string]any); ok {
			m.secrets[id] = map[string]string{}
			for k, v := range s {
				m.secrets[id][k] = fmt.Sprint(v)
			}
		}
	}
	switch {
	case r.Method == http.MethodPost && id == "":
		body["id"] = m.nextID("int")
		storeSecrets(body["id"].(string), body)
		m.integrations[body["id"].(string)] = body
		writeJSON(w, 201, m.public(body))
	case r.Method == http.MethodGet && id != "":
		rec, ok := m.integrations[id]
		if !ok {
			writeJSON(w, 404, map[string]any{"detail": "integration not found"})
			return
		}
		writeJSON(w, 200, m.public(rec))
	case r.Method == http.MethodPatch:
		rec, ok := m.integrations[id]
		if !ok {
			writeJSON(w, 404, map[string]any{"detail": "integration not found"})
			return
		}
		storeSecrets(id, body)
		for k, v := range body {
			rec[k] = v
		}
		writeJSON(w, 200, m.public(rec))
	case r.Method == http.MethodDelete:
		if _, ok := m.integrations[id]; !ok {
			writeJSON(w, 404, map[string]any{"detail": "integration not found"})
			return
		}
		delete(m.integrations, id)
		w.WriteHeader(204)
	default:
		writeJSON(w, 405, map[string]any{"detail": "Method Not Allowed"})
	}
}

func (m *mockPaddock) serveFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var match []map[string]any
	for _, f := range m.findings {
		if s := q.Get("severity"); s != "" && f["severity"] != s {
			continue
		}
		if s := q.Get("status"); s != "" && f["status"] != s {
			continue
		}
		match = append(match, f)
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	end := offset + limit
	if end > len(match) {
		end = len(match)
	}
	items := []map[string]any{}
	if offset < len(match) {
		items = match[offset:end]
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": len(match), "limit": limit, "offset": offset})
}
