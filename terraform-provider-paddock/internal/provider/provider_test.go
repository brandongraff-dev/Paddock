package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/brandongraff-dev/Paddock/terraform-provider-paddock/internal/client"
)

var ctx = context.Background()

func noErr(t *testing.T, d diag.Diagnostics) {
	t.Helper()
	if d.HasError() {
		t.Fatalf("diagnostics: %v", d)
	}
}

// harness drives one resource through the framework's CRUD entry points with
// real tfsdk Plan/State values (no terraform binary needed).
type harness struct {
	t   *testing.T
	r   resource.Resource
	sch tfsdk.State
}

func newHarness(t *testing.T, r resource.Resource, c *client.Client) *harness {
	var sresp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &sresp)
	noErr(t, sresp.Diagnostics)
	var cresp resource.ConfigureResponse
	r.(resource.ResourceWithConfigure).Configure(ctx, resource.ConfigureRequest{ProviderData: c}, &cresp)
	noErr(t, cresp.Diagnostics)
	empty := tfsdk.State{Schema: sresp.Schema, Raw: tftypes.NewValue(sresp.Schema.Type().TerraformType(ctx), nil)}
	return &harness{t: t, r: r, sch: empty}
}

func (h *harness) empty() tfsdk.State {
	return tfsdk.State{Schema: h.sch.Schema, Raw: h.sch.Raw.Copy()}
}

func (h *harness) plan(model any) tfsdk.Plan {
	st := h.empty()
	noErr(h.t, st.Set(ctx, model))
	return tfsdk.Plan{Schema: st.Schema, Raw: st.Raw}
}

func (h *harness) create(model any) tfsdk.State {
	resp := resource.CreateResponse{State: h.empty()}
	h.r.Create(ctx, resource.CreateRequest{Plan: h.plan(model)}, &resp)
	noErr(h.t, resp.Diagnostics)
	return resp.State
}

// read returns the refreshed state and whether the resource still exists.
func (h *harness) read(st tfsdk.State) (tfsdk.State, bool) {
	resp := resource.ReadResponse{State: tfsdk.State{Schema: st.Schema, Raw: st.Raw.Copy()}}
	h.r.Read(ctx, resource.ReadRequest{State: st}, &resp)
	noErr(h.t, resp.Diagnostics)
	return resp.State, !resp.State.Raw.IsNull()
}

func (h *harness) update(prior tfsdk.State, model any) tfsdk.State {
	resp := resource.UpdateResponse{State: tfsdk.State{Schema: prior.Schema, Raw: prior.Raw.Copy()}}
	h.r.Update(ctx, resource.UpdateRequest{Plan: h.plan(model), State: prior}, &resp)
	noErr(h.t, resp.Diagnostics)
	return resp.State
}

func (h *harness) delete(st tfsdk.State) {
	resp := resource.DeleteResponse{State: st}
	h.r.Delete(ctx, resource.DeleteRequest{State: st}, &resp)
	noErr(h.t, resp.Diagnostics)
}

func testClient(url string) *client.Client {
	c := client.New(url, "pak_test_key", "test")
	c.MaxRetries = 0
	return c
}

func strList(vals ...string) types.List { return stringsToList(vals) }

// --------------------------------------------------------------------------

func TestProviderShape(t *testing.T) {
	p := New("test")()
	var md provider.MetadataResponse
	p.Metadata(ctx, provider.MetadataRequest{}, &md)
	if md.TypeName != "paddock" {
		t.Fatalf("type name %q", md.TypeName)
	}
	var ps provider.SchemaResponse
	p.Schema(ctx, provider.SchemaRequest{}, &ps)
	noErr(t, ps.Diagnostics)
	if !ps.Schema.Attributes["api_key"].IsSensitive() {
		t.Fatal("api_key must be sensitive")
	}
	want := map[string]bool{"paddock_scope_entry": true, "paddock_alert_rule": true,
		"paddock_owner_rule": true, "paddock_integration": true}
	for _, f := range p.Resources(ctx) {
		var m resource.MetadataResponse
		f().Metadata(ctx, resource.MetadataRequest{ProviderTypeName: "paddock"}, &m)
		if !want[m.TypeName] {
			t.Fatalf("unexpected resource %s", m.TypeName)
		}
		delete(want, m.TypeName)
	}
	if len(want) != 0 {
		t.Fatalf("missing resources %v", want)
	}
	ds := p.DataSources(ctx)
	var dm datasource.MetadataResponse
	ds[0]().Metadata(ctx, datasource.MetadataRequest{ProviderTypeName: "paddock"}, &dm)
	if len(ds) != 1 || dm.TypeName != "paddock_findings" {
		t.Fatalf("data sources: %d %s", len(ds), dm.TypeName)
	}
}

func TestProviderConfigureFromEnv(t *testing.T) {
	t.Setenv("PADDOCK_URL", "https://paddock.example.internal/")
	t.Setenv("PADDOCK_API_KEY", "pak_env")
	p := New("test")()
	var ps provider.SchemaResponse
	p.Schema(ctx, provider.SchemaRequest{}, &ps)
	st := tfsdk.State{Schema: ps.Schema, Raw: tftypes.NewValue(ps.Schema.Type().TerraformType(ctx), nil)}
	noErr(t, st.Set(ctx, &providerModel{URL: types.StringNull(), APIKey: types.StringNull()}))
	var resp provider.ConfigureResponse
	p.Configure(ctx, provider.ConfigureRequest{Config: tfsdk.Config{Schema: ps.Schema, Raw: st.Raw}}, &resp)
	noErr(t, resp.Diagnostics)
	c := resp.ResourceData.(*client.Client)
	if c.BaseURL != "https://paddock.example.internal" || c.APIKey != "pak_env" {
		t.Fatalf("client %s %s", c.BaseURL, c.APIKey)
	}
}

func TestScopeEntryLifecycle(t *testing.T) {
	m, srv := newMock(t)
	h := newHarness(t, NewScopeEntryResource(), testClient(srv.URL))
	st := h.create(&scopeEntryModel{
		ID: types.StringUnknown(), Kind: types.StringValue("domain"), Value: types.StringValue("example.com"),
		AuthDocRef: types.StringValue("SOW-2026-14"), Notes: types.StringNull(), ExpiresAt: types.StringNull(),
		AddedBy: types.StringValue("terraform"), Active: types.BoolUnknown(),
	})
	var got scopeEntryModel
	noErr(t, st.Get(ctx, &got))
	if got.ID.ValueString() != "1" || !got.Active.ValueBool() || got.AuthDocRef.ValueString() != "SOW-2026-14" {
		t.Fatalf("state after create: %+v", got)
	}
	st, exists := h.read(st)
	if !exists {
		t.Fatal("entry vanished on read")
	}
	// Deactivated out of band -> removed from state so Terraform re-creates it.
	m.scope[1]["active"] = false
	if _, exists := h.read(st); exists {
		t.Fatal("inactive entry should be dropped from state")
	}
	m.scope[1]["active"] = true
	h.delete(st)
	if m.scope[1]["active"] != false {
		t.Fatal("delete should deactivate the entry")
	}
	h.delete(st) // idempotent
}

func TestAlertRuleLifecycle(t *testing.T) {
	m, srv := newMock(t)
	h := newHarness(t, NewAlertRuleResource(), testClient(srv.URL))
	model := &alertRuleModel{
		ID: types.StringUnknown(), Name: types.StringValue("new-hosts"), Channel: types.StringValue("slack"),
		Target: types.StringValue("https://hooks.slack.example/T000/B000/XXXX"), Enabled: types.BoolValue(true),
		ChangeTypes: strList("subdomain_discovered", "port_opened"), MinSeverity: types.StringValue("high"),
		Kinds: types.ListNull(types.StringType),
	}
	st := h.create(model)
	var got alertRuleModel
	noErr(t, st.Get(ctx, &got))
	rec := m.alertRules[got.ID.ValueString()]
	match := rec["match"].(map[string]any)
	if match["min_severity"] != "high" || len(match["change_types"].([]any)) != 2 {
		t.Fatalf("server got %v", rec)
	}
	if _, ok := match["kinds"]; ok {
		t.Fatal("unset kinds must not be sent")
	}
	st, _ = h.read(st)
	noErr(t, st.Get(ctx, &got))
	if got.MinSeverity.ValueString() != "high" || !got.Kinds.IsNull() {
		t.Fatalf("read back %+v", got)
	}

	model.ID = got.ID
	model.Name = types.StringValue("renamed")
	model.Enabled = types.BoolValue(false)
	st = h.update(st, model)
	noErr(t, st.Get(ctx, &got))
	if got.Name.ValueString() != "renamed" || got.Enabled.ValueBool() || rec["enabled"] != false {
		t.Fatalf("update: %+v / %v", got, rec)
	}
	h.delete(st)
	if len(m.alertRules) != 0 {
		t.Fatal("rule not deleted")
	}
	if _, exists := h.read(st); exists {
		t.Fatal("deleted rule should drop from state")
	}
}

func TestOwnerRuleLifecycle(t *testing.T) {
	m, srv := newMock(t)
	h := newHarness(t, NewOwnerRuleResource(), testClient(srv.URL))
	model := &ownerRuleModel{
		ID: types.StringUnknown(), Name: types.StringValue("payments"), Team: types.StringValue("payments-team"),
		Contact: types.StringValue("#payments-sec"), Priority: types.Int64Value(10), Enabled: types.BoolValue(true),
		MatchKinds: strList("subdomain"), MatchValueRegex: types.StringValue(`^pay\.`),
		MatchCIDR: types.StringNull(), MatchEnv: types.StringValue("prod"), MatchTag: types.StringNull(),
	}
	st := h.create(model)
	var got ownerRuleModel
	noErr(t, st.Get(ctx, &got))
	rec := m.owners[got.ID.ValueString()]
	match := rec["match"].(map[string]any)
	if match["value_regex"] != `^pay\.` || match["metadata_env"] != "prod" || rec["priority"] != float64(10) {
		t.Fatalf("server got %v", rec)
	}
	model.ID = got.ID
	model.Priority = types.Int64Value(5)
	model.MatchEnv = types.StringNull()
	st = h.update(st, model)
	noErr(t, st.Get(ctx, &got))
	if got.Priority.ValueInt64() != 5 {
		t.Fatalf("priority %v", got.Priority)
	}
	st, _ = h.read(st)
	noErr(t, st.Get(ctx, &got))
	if got.MatchKinds.IsNull() || got.Team.ValueString() != "payments-team" {
		t.Fatalf("read back %+v", got)
	}
	h.delete(st)
	if len(m.owners) != 0 {
		t.Fatal("owner rule not deleted")
	}
}

func TestIntegrationSecretsAreWriteOnly(t *testing.T) {
	m, srv := newMock(t)
	h := newHarness(t, NewIntegrationResource(), testClient(srv.URL))
	secrets, _ := types.MapValue(types.StringType, map[string]attr.Value{"bot_token": types.StringValue("xoxb-secret")})
	model := &integrationModel{
		ID: types.StringUnknown(), Kind: types.StringValue("slack"), Name: types.StringValue("sec-alerts"),
		Enabled: types.BoolValue(true), ConfigJSON: types.StringValue(`{ "channel": "#sec",  "mention": false }`),
		Secrets: secrets, Events: strList("finding.opened", "attack_path.opened"), MinSeverity: types.StringValue("high"),
		FiltersJSON: types.StringNull(), AllowPrivate: types.BoolValue(false),
	}
	st := h.create(model)
	var got integrationModel
	noErr(t, st.Get(ctx, &got))
	id := got.ID.ValueString()
	if m.secrets[id]["bot_token"] != "xoxb-secret" {
		t.Fatal("secret not sent to the server")
	}
	if _, leaked := m.public(m.integrations[id])["secrets"]; leaked {
		t.Fatal("mock must not echo secrets")
	}
	st, exists := h.read(st)
	if !exists {
		t.Fatal("integration vanished")
	}
	noErr(t, st.Get(ctx, &got))
	if got.ConfigJSON.ValueString() != `{ "channel": "#sec",  "mention": false }` {
		t.Fatalf("config_json spelling should be preserved when semantically equal: %s", got.ConfigJSON)
	}
	var sec map[string]string
	noErr(t, got.Secrets.ElementsAs(ctx, &sec, false))
	if sec["bot_token"] != "xoxb-secret" {
		t.Fatal("secrets must stay in state after read")
	}
	// Server-side drift in config is detected.
	m.integrations[id]["config"] = map[string]any{"channel": "#other"}
	st, _ = h.read(st)
	noErr(t, st.Get(ctx, &got))
	if got.ConfigJSON.ValueString() != `{"channel":"#other"}` {
		t.Fatalf("drift not surfaced: %s", got.ConfigJSON)
	}
	model.ID = got.ID
	model.MinSeverity = types.StringValue("critical")
	st = h.update(st, model)
	noErr(t, st.Get(ctx, &got))
	if got.MinSeverity.ValueString() != "critical" || m.integrations[id]["min_severity"] != "critical" {
		t.Fatal("update not applied")
	}
	h.delete(st)
	if len(m.integrations) != 0 {
		t.Fatal("integration not deleted")
	}
}

func TestIntegrationRejectsBadJSON(t *testing.T) {
	_, srv := newMock(t)
	h := newHarness(t, NewIntegrationResource(), testClient(srv.URL))
	resp := resource.CreateResponse{State: h.empty()}
	h.r.Create(ctx, resource.CreateRequest{Plan: h.plan(&integrationModel{
		ID: types.StringUnknown(), Kind: types.StringValue("webhook"), Name: types.StringValue("x"),
		Enabled: types.BoolValue(true), ConfigJSON: types.StringValue("not json"), Secrets: types.MapNull(types.StringType),
		Events: types.ListNull(types.StringType), MinSeverity: types.StringValue("low"),
		FiltersJSON: types.StringNull(), AllowPrivate: types.BoolValue(false),
	})}, &resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected a diagnostic for invalid config_json")
	}
}

func TestFindingsDataSource(t *testing.T) {
	m, srv := newMock(t)
	for i, sev := range []string{"critical", "critical", "high", "low", "critical"} {
		status := "open"
		if i == 4 {
			status = "fixed"
		}
		m.findings = append(m.findings, map[string]any{
			"id": string(rune('a' + i)), "title": "f", "severity": sev, "status": status,
			"rule_id": "r", "asset_value": "a.example", "last_seen": "2026-11-01T00:00:00Z",
		})
	}
	ds := NewFindingsDataSource()
	var sresp datasource.SchemaResponse
	ds.Schema(ctx, datasource.SchemaRequest{}, &sresp)
	noErr(t, sresp.Diagnostics)
	var cresp datasource.ConfigureResponse
	ds.(datasource.DataSourceWithConfigure).Configure(ctx, datasource.ConfigureRequest{ProviderData: testClient(srv.URL)}, &cresp)

	cfgState := tfsdk.State{Schema: sresp.Schema, Raw: tftypes.NewValue(sresp.Schema.Type().TerraformType(ctx), nil)}
	noErr(t, cfgState.Set(ctx, &findingsModel{
		Severity: types.StringValue("critical"), Status: types.StringValue("open"), Query: types.StringNull(),
		KEV: types.BoolNull(), Limit: types.Int64Value(1), Total: types.Int64Unknown(),
		BySeverity: types.MapUnknown(types.Int64Type), Findings: types.ListUnknown(types.ObjectType{AttrTypes: findingAttrTypes}),
	}))
	resp := datasource.ReadResponse{State: tfsdk.State{Schema: sresp.Schema, Raw: cfgState.Raw.Copy()}}
	ds.Read(ctx, datasource.ReadRequest{Config: tfsdk.Config{Schema: sresp.Schema, Raw: cfgState.Raw}}, &resp)
	noErr(t, resp.Diagnostics)
	var got findingsModel
	noErr(t, resp.State.Get(ctx, &got))
	if got.Total.ValueInt64() != 2 {
		t.Fatalf("total open criticals = %d", got.Total.ValueInt64())
	}
	if len(got.Findings.Elements()) != 1 {
		t.Fatalf("limit not applied: %d rows", len(got.Findings.Elements()))
	}
	counts := map[string]int64{}
	noErr(t, got.BySeverity.ElementsAs(ctx, &counts, false))
	if counts["critical"] != 2 || counts["high"] != 1 || counts["low"] != 1 || counts["info"] != 0 {
		t.Fatalf("counts %v", counts)
	}
}
