// Package client is a minimal HTTP client for the Paddock /v1 API, used by the
// Terraform provider. It only knows the handful of endpoints the provider
// manages; the full API is covered by the generated Python/TypeScript SDKs.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client talks to one Paddock orchestrator.
type Client struct {
	BaseURL    string
	APIKey     string
	HTTP       *http.Client
	UserAgent  string
	MaxRetries int
	// Sleep is injectable for tests.
	Sleep func(time.Duration)
}

// New returns a client with sane defaults.
func New(baseURL, apiKey, version string) *Client {
	return &Client{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		APIKey:     apiKey,
		HTTP:       &http.Client{Timeout: 30 * time.Second},
		UserAgent:  "terraform-provider-paddock/" + version,
		MaxRetries: 3,
		Sleep:      time.Sleep,
	}
}

// APIError is a non-2xx answer from the server.
type APIError struct {
	Status int
	Method string
	Path   string
	Detail string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s %s -> HTTP %d: %s", e.Method, e.Path, e.Status, e.Detail)
}

// IsNotFound reports whether err is an HTTP 404.
func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

func retryable(method string, status int) bool {
	if status == http.StatusTooManyRequests {
		return true
	}
	idempotent := method == http.MethodGet || method == http.MethodPut || method == http.MethodDelete
	return idempotent && (status == 502 || status == 503 || status == 504)
}

// Do sends a JSON request and decodes a JSON response into out (if non-nil).
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	var payload []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = b
	}
	u := c.BaseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", c.UserAgent)
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if c.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+c.APIKey)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			if attempt < c.MaxRetries && method == http.MethodGet && ctx.Err() == nil {
				c.backoff(attempt)
				continue
			}
			return fmt.Errorf("%s %s: %w", method, path, err)
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if readErr != nil {
			return readErr
		}
		if resp.StatusCode >= 400 {
			if attempt < c.MaxRetries && retryable(method, resp.StatusCode) {
				c.backoff(attempt)
				continue
			}
			return &APIError{Status: resp.StatusCode, Method: method, Path: path, Detail: detail(data)}
		}
		if out == nil || resp.StatusCode == http.StatusNoContent || len(data) == 0 {
			return nil
		}
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("%s %s: decoding response: %w", method, path, err)
		}
		return nil
	}
}

func (c *Client) backoff(attempt int) {
	d := time.Duration(float64(500*time.Millisecond) * float64(int(1)<<attempt) * rand.Float64())
	if d > 10*time.Second {
		d = 10 * time.Second
	}
	if c.Sleep != nil {
		c.Sleep(d)
	}
}

func detail(data []byte) string {
	var m map[string]any
	if json.Unmarshal(data, &m) == nil {
		if d, ok := m["detail"]; ok {
			if s, ok := d.(string); ok {
				return s
			}
			b, _ := json.Marshal(d)
			return string(b)
		}
	}
	s := strings.TrimSpace(string(data))
	if len(s) > 500 {
		s = s[:500] + "..."
	}
	return s
}

// ---------------------------------------------------------------------------
// Typed endpoints
// ---------------------------------------------------------------------------

// ScopeEntry mirrors ScopeEntryOut / ScopeEntryIn.
type ScopeEntry struct {
	ID         int64          `json:"id,omitempty"`
	Kind       string         `json:"kind"`
	Value      string         `json:"value"`
	AddedBy    string         `json:"added_by"`
	AuthDocRef *string        `json:"auth_doc_ref,omitempty"`
	ExpiresAt  *string        `json:"expires_at,omitempty"`
	Notes      *string        `json:"notes,omitempty"`
	Active     bool           `json:"active,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

func (c *Client) CreateScopeEntry(ctx context.Context, in ScopeEntry) (*ScopeEntry, error) {
	var out ScopeEntry
	return &out, c.Do(ctx, http.MethodPost, "/v1/scope", nil, in, &out)
}

// GetScopeEntry finds an entry by id (the API has no GET-by-id, so it pages
// through the list including inactive entries). Returns a 404 APIError when absent.
func (c *Client) GetScopeEntry(ctx context.Context, id int64) (*ScopeEntry, error) {
	const page = 500
	for offset := 0; ; offset += page {
		q := url.Values{"active_only": {"false"}, "limit": {fmt.Sprint(page)}, "offset": {fmt.Sprint(offset)}}
		var rows []ScopeEntry
		if err := c.Do(ctx, http.MethodGet, "/v1/scope", q, nil, &rows); err != nil {
			return nil, err
		}
		for i := range rows {
			if rows[i].ID == id {
				return &rows[i], nil
			}
		}
		if len(rows) < page {
			return nil, &APIError{Status: 404, Method: "GET", Path: fmt.Sprintf("/v1/scope/%d", id), Detail: "scope entry not found"}
		}
	}
}

func (c *Client) DeleteScopeEntry(ctx context.Context, id int64) error {
	return c.Do(ctx, http.MethodDelete, fmt.Sprintf("/v1/scope/%d", id), nil, nil, nil)
}

// AlertRule mirrors AlertRuleIn/Out.
type AlertRule struct {
	ID      string         `json:"id,omitempty"`
	Name    string         `json:"name"`
	Match   map[string]any `json:"match"`
	Channel string         `json:"channel"`
	Target  *string        `json:"target"`
	Enabled bool           `json:"enabled"`
}

func (c *Client) CreateAlertRule(ctx context.Context, in AlertRule) (*AlertRule, error) {
	var out AlertRule
	return &out, c.Do(ctx, http.MethodPost, "/v1/alert-rules", nil, in, &out)
}

func (c *Client) GetAlertRule(ctx context.Context, id string) (*AlertRule, error) {
	var rows []AlertRule
	if err := c.Do(ctx, http.MethodGet, "/v1/alert-rules", nil, nil, &rows); err != nil {
		return nil, err
	}
	for i := range rows {
		if rows[i].ID == id {
			return &rows[i], nil
		}
	}
	return nil, &APIError{Status: 404, Method: "GET", Path: "/v1/alert-rules/" + id, Detail: "alert rule not found"}
}

func (c *Client) UpdateAlertRule(ctx context.Context, id string, in AlertRule) (*AlertRule, error) {
	var out AlertRule
	return &out, c.Do(ctx, http.MethodPatch, "/v1/alert-rules/"+url.PathEscape(id), nil, in, &out)
}

func (c *Client) DeleteAlertRule(ctx context.Context, id string) error {
	return c.Do(ctx, http.MethodDelete, "/v1/alert-rules/"+url.PathEscape(id), nil, nil, nil)
}

// OwnerRule mirrors OwnerIn/Out (/v1/owners).
type OwnerRule struct {
	ID       string         `json:"id,omitempty"`
	Name     string         `json:"name"`
	Match    map[string]any `json:"match"`
	Team     string         `json:"team"`
	Contact  *string        `json:"contact"`
	Priority int64          `json:"priority"`
	Enabled  bool           `json:"enabled"`
}

func (c *Client) CreateOwnerRule(ctx context.Context, in OwnerRule) (*OwnerRule, error) {
	var out OwnerRule
	return &out, c.Do(ctx, http.MethodPost, "/v1/owners", nil, in, &out)
}

func (c *Client) GetOwnerRule(ctx context.Context, id string) (*OwnerRule, error) {
	var rows []OwnerRule
	if err := c.Do(ctx, http.MethodGet, "/v1/owners", nil, nil, &rows); err != nil {
		return nil, err
	}
	for i := range rows {
		if rows[i].ID == id {
			return &rows[i], nil
		}
	}
	return nil, &APIError{Status: 404, Method: "GET", Path: "/v1/owners/" + id, Detail: "owner not found"}
}

func (c *Client) UpdateOwnerRule(ctx context.Context, id string, in OwnerRule) (*OwnerRule, error) {
	var out OwnerRule
	return &out, c.Do(ctx, http.MethodPatch, "/v1/owners/"+url.PathEscape(id), nil, in, &out)
}

func (c *Client) DeleteOwnerRule(ctx context.Context, id string) error {
	return c.Do(ctx, http.MethodDelete, "/v1/owners/"+url.PathEscape(id), nil, nil, nil)
}

// Integration mirrors the documented /v1/integrations shape. Secrets are
// write-only: the server never returns them.
type Integration struct {
	ID           string            `json:"id,omitempty"`
	Kind         string            `json:"kind"`
	Name         string            `json:"name"`
	Enabled      bool              `json:"enabled"`
	Config       map[string]any    `json:"config"`
	Secrets      map[string]string `json:"secrets,omitempty"`
	Events       []string          `json:"events"`
	MinSeverity  string            `json:"min_severity"`
	Filters      map[string]any    `json:"filters"`
	AllowPrivate bool              `json:"allow_private"`
}

func (c *Client) CreateIntegration(ctx context.Context, in Integration) (*Integration, error) {
	var out Integration
	return &out, c.Do(ctx, http.MethodPost, "/v1/integrations", nil, in, &out)
}

func (c *Client) GetIntegration(ctx context.Context, id string) (*Integration, error) {
	var out Integration
	return &out, c.Do(ctx, http.MethodGet, "/v1/integrations/"+url.PathEscape(id), nil, nil, &out)
}

func (c *Client) UpdateIntegration(ctx context.Context, id string, in Integration) (*Integration, error) {
	var out Integration
	return &out, c.Do(ctx, http.MethodPatch, "/v1/integrations/"+url.PathEscape(id), nil, in, &out)
}

func (c *Client) DeleteIntegration(ctx context.Context, id string) error {
	return c.Do(ctx, http.MethodDelete, "/v1/integrations/"+url.PathEscape(id), nil, nil, nil)
}

// Finding is the subset of FindingOut the data source exposes.
type Finding struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	Severity   string `json:"severity"`
	Status     string `json:"status"`
	RuleID     string `json:"rule_id"`
	AssetValue string `json:"asset_value"`
	LastSeen   string `json:"last_seen"`
}

// FindingPage mirrors FindingPage.
type FindingPage struct {
	Items  []Finding `json:"items"`
	Total  int64     `json:"total"`
	Limit  int64     `json:"limit"`
	Offset int64     `json:"offset"`
}

// ListFindings pages through /v1/findings up to max items; returns items and the server total.
func (c *Client) ListFindings(ctx context.Context, filter url.Values, max int) ([]Finding, int64, error) {
	var all []Finding
	var total int64
	const page = 500
	for offset := 0; ; offset += page {
		q := url.Values{}
		for k, v := range filter {
			q[k] = v
		}
		q.Set("limit", fmt.Sprint(page))
		q.Set("offset", fmt.Sprint(offset))
		var p FindingPage
		if err := c.Do(ctx, http.MethodGet, "/v1/findings", q, nil, &p); err != nil {
			return nil, 0, err
		}
		total = p.Total
		all = append(all, p.Items...)
		if max > 0 && len(all) >= max {
			return all[:max], total, nil
		}
		if len(p.Items) < page || int64(offset+len(p.Items)) >= p.Total {
			return all, total, nil
		}
	}
}
