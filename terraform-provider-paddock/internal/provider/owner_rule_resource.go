package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/brandongraff-dev/cybersec/terraform-provider-paddock/internal/client"
)

var (
	_ resource.Resource                = (*ownerRuleResource)(nil)
	_ resource.ResourceWithConfigure   = (*ownerRuleResource)(nil)
	_ resource.ResourceWithImportState = (*ownerRuleResource)(nil)
)

// NewOwnerRuleResource manages an owner-routing rule (/v1/owners): which team
// owns the assets matching a pattern, so findings route to them.
func NewOwnerRuleResource() resource.Resource { return &ownerRuleResource{} }

type ownerRuleResource struct{ c *client.Client }

type ownerRuleModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	Team            types.String `tfsdk:"team"`
	Contact         types.String `tfsdk:"contact"`
	Priority        types.Int64  `tfsdk:"priority"`
	Enabled         types.Bool   `tfsdk:"enabled"`
	MatchKinds      types.List   `tfsdk:"match_kinds"`
	MatchValueRegex types.String `tfsdk:"match_value_regex"`
	MatchCIDR       types.String `tfsdk:"match_cidr"`
	MatchEnv        types.String `tfsdk:"match_metadata_env"`
	MatchTag        types.String `tfsdk:"match_tag"`
}

func (r *ownerRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_owner_rule"
}

func (r *ownerRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Routes findings on matching assets to an owning team. Lower priority wins.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name":               schema.StringAttribute{Required: true},
			"team":               schema.StringAttribute{Required: true},
			"contact":            schema.StringAttribute{Optional: true, Description: "Email/Slack handle for the team."},
			"priority":           schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(100)},
			"enabled":            schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
			"match_kinds":        schema.ListAttribute{Optional: true, ElementType: types.StringType, Description: "Asset kinds, e.g. [\"subdomain\", \"ipv4\"]."},
			"match_value_regex":  schema.StringAttribute{Optional: true, Description: "Regex over the asset value."},
			"match_cidr":         schema.StringAttribute{Optional: true},
			"match_metadata_env": schema.StringAttribute{Optional: true, Description: "metadata.env equality, e.g. \"prod\"."},
			"match_tag":          schema.StringAttribute{Optional: true},
		},
	}
}

func (r *ownerRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.c = clientFrom(req.ProviderData, &resp.Diagnostics)
}

func buildOwnerRule(ctx context.Context, m ownerRuleModel, diags *diag.Diagnostics) client.OwnerRule {
	match := map[string]any{}
	if v := listToStrings(ctx, m.MatchKinds, diags); v != nil {
		match["kinds"] = v
	}
	for key, v := range map[string]types.String{
		"value_regex": m.MatchValueRegex, "cidr": m.MatchCIDR, "metadata_env": m.MatchEnv, "tag": m.MatchTag,
	} {
		if p := strPtr(v); p != nil {
			match[key] = *p
		}
	}
	prio := int64(100)
	if !m.Priority.IsNull() && !m.Priority.IsUnknown() {
		prio = m.Priority.ValueInt64()
	}
	return client.OwnerRule{
		Name:     m.Name.ValueString(),
		Match:    match,
		Team:     m.Team.ValueString(),
		Contact:  strPtr(m.Contact),
		Priority: prio,
		Enabled:  m.Enabled.IsNull() || m.Enabled.IsUnknown() || m.Enabled.ValueBool(),
	}
}

func applyOwnerRule(m *ownerRuleModel, o *client.OwnerRule) {
	m.ID = types.StringValue(o.ID)
	m.Name = types.StringValue(o.Name)
	m.Team = types.StringValue(o.Team)
	m.Contact = strFromPtr(o.Contact)
	m.Priority = types.Int64Value(o.Priority)
	m.Enabled = types.BoolValue(o.Enabled)
	if v, ok := o.Match["kinds"]; ok {
		m.MatchKinds = stringsToList(anyToStrings(v))
	} else {
		m.MatchKinds = types.ListNull(types.StringType)
	}
	m.MatchValueRegex = anyToString(o.Match["value_regex"])
	m.MatchCIDR = anyToString(o.Match["cidr"])
	m.MatchEnv = anyToString(o.Match["metadata_env"])
	m.MatchTag = anyToString(o.Match["tag"])
}

func (r *ownerRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ownerRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	body := buildOwnerRule(ctx, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.c.CreateOwnerRule(ctx, body)
	if err != nil {
		resp.Diagnostics.AddError("Creating owner rule failed", err.Error())
		return
	}
	applyOwnerRule(&plan, out)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ownerRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var st ownerRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &st)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.c.GetOwnerRule(ctx, st.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Reading owner rule failed", err.Error())
		return
	}
	applyOwnerRule(&st, out)
	resp.Diagnostics.Append(resp.State.Set(ctx, &st)...)
}

func (r *ownerRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, st ownerRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &st)...)
	body := buildOwnerRule(ctx, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.c.UpdateOwnerRule(ctx, st.ID.ValueString(), body)
	if err != nil {
		resp.Diagnostics.AddError("Updating owner rule failed", err.Error())
		return
	}
	applyOwnerRule(&plan, out)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ownerRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var st ownerRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &st)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.c.DeleteOwnerRule(ctx, st.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Deleting owner rule failed", err.Error())
	}
}

func (r *ownerRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
