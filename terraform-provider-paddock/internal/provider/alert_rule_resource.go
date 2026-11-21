package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/brandongraff-dev/cybersec/terraform-provider-paddock/internal/client"
)

var (
	_ resource.Resource                = (*alertRuleResource)(nil)
	_ resource.ResourceWithConfigure   = (*alertRuleResource)(nil)
	_ resource.ResourceWithImportState = (*alertRuleResource)(nil)
)

// NewAlertRuleResource manages a surface-change alert rule (/v1/alert-rules).
func NewAlertRuleResource() resource.Resource { return &alertRuleResource{} }

type alertRuleResource struct{ c *client.Client }

type alertRuleModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Channel     types.String `tfsdk:"channel"`
	Target      types.String `tfsdk:"target"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	ChangeTypes types.List   `tfsdk:"change_types"`
	MinSeverity types.String `tfsdk:"min_severity"`
	Kinds       types.List   `tfsdk:"kinds"`
}

func (r *alertRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_alert_rule"
}

func (r *alertRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "An alert rule fired on attack-surface changes (new host, port, certificate...).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name":    schema.StringAttribute{Required: true},
			"channel": schema.StringAttribute{Required: true, Description: "log | webhook | slack"},
			"target": schema.StringAttribute{
				Optional: true, Sensitive: true,
				Description: "Webhook/Slack URL. Sensitive because incoming-webhook URLs embed a secret.",
			},
			"enabled":      schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
			"change_types": schema.ListAttribute{Optional: true, ElementType: types.StringType, Description: "Only these change types (empty = all)."},
			"min_severity": schema.StringAttribute{Optional: true, Description: "info | low | medium | high | critical"},
			"kinds":        schema.ListAttribute{Optional: true, ElementType: types.StringType, Description: "Only changes on these asset kinds."},
		},
	}
}

func (r *alertRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.c = clientFrom(req.ProviderData, &resp.Diagnostics)
}

func buildAlertRule(ctx context.Context, m alertRuleModel, diags *diag.Diagnostics) client.AlertRule {
	match := map[string]any{}
	if v := listToStrings(ctx, m.ChangeTypes, diags); v != nil {
		match["change_types"] = v
	}
	if !m.MinSeverity.IsNull() && !m.MinSeverity.IsUnknown() {
		match["min_severity"] = m.MinSeverity.ValueString()
	}
	if v := listToStrings(ctx, m.Kinds, diags); v != nil {
		match["kinds"] = v
	}
	return client.AlertRule{
		Name:    m.Name.ValueString(),
		Match:   match,
		Channel: m.Channel.ValueString(),
		Target:  strPtr(m.Target),
		Enabled: m.Enabled.IsNull() || m.Enabled.IsUnknown() || m.Enabled.ValueBool(),
	}
}

func applyAlertRule(m *alertRuleModel, a *client.AlertRule) {
	m.ID = types.StringValue(a.ID)
	m.Name = types.StringValue(a.Name)
	m.Channel = types.StringValue(a.Channel)
	m.Target = strFromPtr(a.Target)
	m.Enabled = types.BoolValue(a.Enabled)
	if v, ok := a.Match["change_types"]; ok {
		m.ChangeTypes = stringsToList(anyToStrings(v))
	} else {
		m.ChangeTypes = types.ListNull(types.StringType)
	}
	m.MinSeverity = anyToString(a.Match["min_severity"])
	if v, ok := a.Match["kinds"]; ok {
		m.Kinds = stringsToList(anyToStrings(v))
	} else {
		m.Kinds = types.ListNull(types.StringType)
	}
}

func (r *alertRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan alertRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	body := buildAlertRule(ctx, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.c.CreateAlertRule(ctx, body)
	if err != nil {
		resp.Diagnostics.AddError("Creating alert rule failed", err.Error())
		return
	}
	applyAlertRule(&plan, out)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *alertRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var st alertRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &st)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.c.GetAlertRule(ctx, st.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Reading alert rule failed", err.Error())
		return
	}
	applyAlertRule(&st, out)
	resp.Diagnostics.Append(resp.State.Set(ctx, &st)...)
}

func (r *alertRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, st alertRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &st)...)
	body := buildAlertRule(ctx, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.c.UpdateAlertRule(ctx, st.ID.ValueString(), body)
	if err != nil {
		resp.Diagnostics.AddError("Updating alert rule failed", err.Error())
		return
	}
	applyAlertRule(&plan, out)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *alertRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var st alertRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &st)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.c.DeleteAlertRule(ctx, st.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Deleting alert rule failed", err.Error())
	}
}

func (r *alertRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
