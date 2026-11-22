package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/brandongraff-dev/paddock/terraform-provider-paddock/internal/client"
)

var (
	_ resource.Resource                = (*integrationResource)(nil)
	_ resource.ResourceWithConfigure   = (*integrationResource)(nil)
	_ resource.ResourceWithImportState = (*integrationResource)(nil)
)

// NewIntegrationResource manages one integration (Slack, Jira, webhook, SIEM...)
// via /v1/integrations.
func NewIntegrationResource() resource.Resource { return &integrationResource{} }

type integrationResource struct{ c *client.Client }

type integrationModel struct {
	ID           types.String `tfsdk:"id"`
	Kind         types.String `tfsdk:"kind"`
	Name         types.String `tfsdk:"name"`
	Enabled      types.Bool   `tfsdk:"enabled"`
	ConfigJSON   types.String `tfsdk:"config_json"`
	Secrets      types.Map    `tfsdk:"secrets"`
	Events       types.List   `tfsdk:"events"`
	MinSeverity  types.String `tfsdk:"min_severity"`
	FiltersJSON  types.String `tfsdk:"filters_json"`
	AllowPrivate types.Bool   `tfsdk:"allow_private"`
}

func (r *integrationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_integration"
}

func (r *integrationResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "An integration (connector) that receives Paddock events or syncs tickets. " +
			"Secrets are write-only: the API encrypts them at rest and never returns them, so Terraform " +
			"keeps what you configured (marked sensitive) and cannot detect out-of-band secret changes.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"kind": schema.StringAttribute{
				Required: true, Description: "Connector kind, e.g. slack, teams, webhook, jira, servicenow, splunk_hec.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"name":    schema.StringAttribute{Required: true},
			"enabled": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
			"config_json": schema.StringAttribute{
				Optional: true, Description: "Non-secret settings as a JSON object: jsonencode({ channel = \"#sec\" }).",
			},
			"secrets": schema.MapAttribute{
				Optional: true, Sensitive: true, ElementType: types.StringType,
				Description: "Secret settings (tokens, webhook URLs). Write-only.",
			},
			"events": schema.ListAttribute{
				Optional: true, ElementType: types.StringType,
				Description: "Subscribed event types, e.g. [\"finding.opened\", \"attack_path.opened\"].",
			},
			"min_severity": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("low")},
			"filters_json": schema.StringAttribute{Optional: true, Description: "Optional filters as a JSON object."},
			"allow_private": schema.BoolAttribute{
				Optional: true, Computed: true, Default: booldefault.StaticBool(false),
				Description: "Deliberate opt-in to deliver to private/LAN addresses.",
			},
		},
	}
}

func (r *integrationResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.c = clientFrom(req.ProviderData, &resp.Diagnostics)
}

func buildIntegration(ctx context.Context, m integrationModel, diags *diag.Diagnostics) client.Integration {
	in := client.Integration{
		Kind:         m.Kind.ValueString(),
		Name:         m.Name.ValueString(),
		Enabled:      m.Enabled.IsNull() || m.Enabled.IsUnknown() || m.Enabled.ValueBool(),
		Config:       jsonObject(m.ConfigJSON, "config_json", diags),
		Filters:      jsonObject(m.FiltersJSON, "filters_json", diags),
		Events:       listToStrings(ctx, m.Events, diags),
		MinSeverity:  m.MinSeverity.ValueString(),
		AllowPrivate: !m.AllowPrivate.IsNull() && !m.AllowPrivate.IsUnknown() && m.AllowPrivate.ValueBool(),
	}
	if in.Events == nil {
		in.Events = []string{}
	}
	if in.MinSeverity == "" {
		in.MinSeverity = "low"
	}
	if !m.Secrets.IsNull() && !m.Secrets.IsUnknown() {
		sec := map[string]string{}
		diags.Append(m.Secrets.ElementsAs(ctx, &sec, false)...)
		in.Secrets = sec
	}
	return in
}

// applyIntegration copies server state, keeping write-only secrets and the
// practitioner's JSON spelling where semantically equal.
func applyIntegration(m *integrationModel, in *client.Integration) {
	m.ID = types.StringValue(in.ID)
	m.Kind = types.StringValue(in.Kind)
	m.Name = types.StringValue(in.Name)
	m.Enabled = types.BoolValue(in.Enabled)
	m.MinSeverity = types.StringValue(in.MinSeverity)
	m.AllowPrivate = types.BoolValue(in.AllowPrivate)
	m.ConfigJSON = jsonAttr(m.ConfigJSON, in.Config)
	m.FiltersJSON = jsonAttr(m.FiltersJSON, in.Filters)
	if len(in.Events) == 0 && (m.Events.IsNull() || m.Events.IsUnknown()) {
		m.Events = types.ListNull(types.StringType)
	} else {
		m.Events = stringsToList(in.Events)
	}
	if m.Secrets.IsUnknown() {
		m.Secrets = types.MapNull(types.StringType)
	}
}

func (r *integrationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan integrationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	body := buildIntegration(ctx, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.c.CreateIntegration(ctx, body)
	if err != nil {
		resp.Diagnostics.AddError("Creating integration failed", err.Error())
		return
	}
	if out.ID == "" {
		resp.Diagnostics.AddError("Creating integration failed", "the server did not return an id")
		return
	}
	applyIntegration(&plan, out)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *integrationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var st integrationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &st)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.c.GetIntegration(ctx, st.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Reading integration failed", err.Error())
		return
	}
	applyIntegration(&st, out)
	resp.Diagnostics.Append(resp.State.Set(ctx, &st)...)
}

func (r *integrationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, st integrationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &st)...)
	body := buildIntegration(ctx, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.c.UpdateIntegration(ctx, st.ID.ValueString(), body)
	if err != nil {
		resp.Diagnostics.AddError("Updating integration failed", err.Error())
		return
	}
	applyIntegration(&plan, out)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *integrationResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var st integrationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &st)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.c.DeleteIntegration(ctx, st.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Deleting integration failed", err.Error())
	}
}

func (r *integrationResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
