package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetriesIdempotentGETOn503(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) < 3 {
			w.WriteHeader(503)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer pak_test" {
			t.Errorf("auth header = %q", got)
		}
		_ = json.NewEncoder(w).Encode([]AlertRule{{ID: "a1", Name: "x"}})
	}))
	defer srv.Close()
	c := New(srv.URL+"/", "pak_test", "test")
	c.Sleep = func(time.Duration) {}
	r, err := c.GetAlertRule(context.Background(), "a1")
	if err != nil || r.Name != "x" {
		t.Fatalf("got %v, %v", r, err)
	}
	if n != 3 {
		t.Fatalf("expected 3 attempts, got %d", n)
	}
}

func TestPOSTNotRetriedOn503(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(503)
		_, _ = w.Write([]byte(`{"detail":"down"}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "", "test")
	c.Sleep = func(time.Duration) {}
	_, err := c.CreateAlertRule(context.Background(), AlertRule{Name: "x"})
	ae, ok := err.(*APIError)
	if !ok || ae.Status != 503 || ae.Detail != "down" {
		t.Fatalf("unexpected error %#v", err)
	}
	if n != 1 {
		t.Fatalf("POST retried: %d attempts", n)
	}
}

func TestStructuredDetailAndNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"detail":{"error":"gone"}}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "", "test")
	_, err := c.GetIntegration(context.Background(), "i/1")
	if !IsNotFound(err) {
		t.Fatalf("expected not found, got %v", err)
	}
	if ae := err.(*APIError); ae.Detail != `{"error":"gone"}` || ae.Path != "/v1/integrations/i%2F1" {
		t.Fatalf("detail/path = %q %q", ae.Detail, ae.Path)
	}
}

func TestGetScopeEntryPagesAndMisses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("active_only") != "false" {
			t.Errorf("expected active_only=false")
		}
		_ = json.NewEncoder(w).Encode([]ScopeEntry{{ID: 1, Kind: "domain", Value: "a.example"}})
	}))
	defer srv.Close()
	c := New(srv.URL, "", "test")
	if e, err := c.GetScopeEntry(context.Background(), 1); err != nil || e.Value != "a.example" {
		t.Fatalf("got %v %v", e, err)
	}
	if _, err := c.GetScopeEntry(context.Background(), 2); !IsNotFound(err) {
		t.Fatalf("expected not found, got %v", err)
	}
}
