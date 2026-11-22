package provider

import (
	"context"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/brandongraff-dev/paddock/terraform-provider-paddock/internal/client"
)

var (
	_ datasource.DataSource              = (*findingsDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*findingsDataSource)(nil)
)

// NewFindingsDataSource returns a filtered findings summary, e.g. to fail a
// pipeline when critical findings are open:
//
//	data "paddock_findings" "crit" { severity = "critical", status = "open" }
//	check "no_criticals" { assert { condition = data.paddock_findings.crit.total == 0 ... } }
func NewFindingsDataSource() datasource.DataSource { return &findingsDataSource{} }

type findingsDataSource struct{ c *client.Client }

var severities = []string{"info", "low", "medium", "high", "critical"}

var findingAttrTypes = map[string]attr.Type{
	"id": types.StringType, "title": types.StringType, "severity": types.StringType,
	"status": types.StringType, "rule_id": types.StringType, "asset_value": types.StringType,
	"last_seen": types.StringType,
}

type findingsModel struct {
	Severity   types.String `tfsdk:"severity"`
	Status     types.String `tfsdk:"status"`
	Query      types.String `tfsdk:"query"`
	KEV        types.Bool   `tfsdk:"kev"`
	Limit      types.Int64  `tfsdk:"limit"`
	Total      types.Int64  `tfsdk:"total"`
	BySeverity types.Map    `tfsdk:"counts_by_severity"`
	Findings   types.List   `tfsdk:"findings"`
}

func (d *findingsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_findings"
}

func (d *findingsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A filtered summary of findings (counts + the first `limit` rows).",
		Attributes: map[string]schema.Attribute{
			"severity": schema.StringAttribute{Optional: true, Description: "info | low | medium | high | critical"},
			"status":   schema.StringAttribute{Optional: true, Description: "open | triaged | false_positive | accepted_risk | fixed | wontfix"},
			"query":    schema.StringAttribute{Optional: true, Description: "Free-text search."},
			"kev":      schema.BoolAttribute{Optional: true, Description: "Only findings on CISA KEV-listed CVEs."},
			"limit":    schema.Int64Attribute{Optional: true, Description: "Max rows in `findings` (default 100, 0 = counts only)."},
			"total":    schema.Int64Attribute{Computed: true, Description: "Total matching findings."},
			"counts_by_severity": schema.MapAttribute{
				Computed: true, ElementType: types.Int64Type,
				Description: "Matching findings per severity (ignores the `severity` filter).",
			},
			"findings": schema.ListAttribute{
				Computed:    true,
				ElementType: types.ObjectType{AttrTypes: findingAttrTypes},
			},
		},
	}
}

func (d *findingsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.c = clientFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *findingsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m findingsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	base := url.Values{}
	if p := strPtr(m.Status); p != nil {
		base.Set("status", *p)
	}
	if p := strPtr(m.Query); p != nil {
		base.Set("q", *p)
	}
	if !m.KEV.IsNull() && !m.KEV.IsUnknown() && m.KEV.ValueBool() {
		base.Set("kev", "true")
	}

	counts := map[string]attr.Value{}
	for _, sev := range severities {
		q := url.Values{}
		for k, v := range base {
			q[k] = v
		}
		q.Set("severity", sev)
		_, total, err := d.c.ListFindings(ctx, q, 1)
		if err != nil {
			resp.Diagnostics.AddError("Listing findings failed", err.Error())
			return
		}
		counts[sev] = types.Int64Value(total)
	}

	limit := 100
	if !m.Limit.IsNull() && !m.Limit.IsUnknown() {
		limit = int(m.Limit.ValueInt64())
	}
	q := url.Values{}
	for k, v := range base {
		q[k] = v
	}
	if p := strPtr(m.Severity); p != nil {
		q.Set("severity", *p)
	}
	rows, total, err := d.c.ListFindings(ctx, q, maxInt(limit, 1))
	if err != nil {
		resp.Diagnostics.AddError("Listing findings failed", err.Error())
		return
	}
	if limit == 0 {
		rows = nil
	}
	objs := make([]attr.Value, 0, len(rows))
	for _, f := range rows {
		o, diags := types.ObjectValue(findingAttrTypes, map[string]attr.Value{
			"id": types.StringValue(f.ID), "title": types.StringValue(f.Title),
			"severity": types.StringValue(f.Severity), "status": types.StringValue(f.Status),
			"rule_id": types.StringValue(f.RuleID), "asset_value": types.StringValue(f.AssetValue),
			"last_seen": types.StringValue(f.LastSeen),
		})
		resp.Diagnostics.Append(diags...)
		objs = append(objs, o)
	}
	list, diags := types.ListValue(types.ObjectType{AttrTypes: findingAttrTypes}, objs)
	resp.Diagnostics.Append(diags...)
	bySev, diags := types.MapValue(types.Int64Type, counts)
	resp.Diagnostics.Append(diags...)

	m.Total = types.Int64Value(total)
	m.BySeverity = bySev
	m.Findings = list
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
