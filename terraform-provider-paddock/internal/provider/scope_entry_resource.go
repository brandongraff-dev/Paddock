package provider

import (
	"context"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/brandongraff-dev/Paddock/terraform-provider-paddock/internal/client"
)

var (
	_ resource.Resource                = (*scopeEntryResource)(nil)
	_ resource.ResourceWithConfigure   = (*scopeEntryResource)(nil)
	_ resource.ResourceWithImportState = (*scopeEntryResource)(nil)
)

// NewScopeEntryResource manages one authorized-scope allowlist entry.
func NewScopeEntryResource() resource.Resource { return &scopeEntryResource{} }

type scopeEntryResource struct{ c *client.Client }

type scopeEntryModel struct {
	ID         types.String `tfsdk:"id"`
	Kind       types.String `tfsdk:"kind"`
	Value      types.String `tfsdk:"value"`
	AuthDocRef types.String `tfsdk:"auth_doc_ref"`
	Notes      types.String `tfsdk:"notes"`
	ExpiresAt  types.String `tfsdk:"expires_at"`
	AddedBy    types.String `tfsdk:"added_by"`
	Active     types.Bool   `tfsdk:"active"`
}

func (r *scopeEntryResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_scope_entry"
}

func (r *scopeEntryResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		Description: "An entry in Paddock's authorized-scope allowlist. Nothing is ever probed outside scope. " +
			"Scope entries are immutable in the API (one reviewable row per change), so any change replaces the " +
			"entry; destroy deactivates it (the row and its audit trail are kept).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"kind": schema.StringAttribute{
				Required:      true,
				Description:   "domain | subdomain_wildcard | ipv4_cidr | ipv6_cidr | asn",
				PlanModifiers: replace,
			},
			"value":        schema.StringAttribute{Required: true, PlanModifiers: replace},
			"auth_doc_ref": schema.StringAttribute{Optional: true, Description: "Reference to the written authorization (SOW, ticket...).", PlanModifiers: replace},
			"notes":        schema.StringAttribute{Optional: true, PlanModifiers: replace},
			"expires_at":   schema.StringAttribute{Optional: true, Description: "RFC 3339 timestamp after which the entry stops matching.", PlanModifiers: replace},
			"added_by":     schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("terraform"), PlanModifiers: replace},
			"active":       schema.BoolAttribute{Computed: true},
		},
	}
}

func (r *scopeEntryResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.c = clientFrom(req.ProviderData, &resp.Diagnostics)
}

func (r *scopeEntryResource) apply(m *scopeEntryModel, e *client.ScopeEntry) {
	m.ID = types.StringValue(strconv.FormatInt(e.ID, 10))
	m.Kind = types.StringValue(e.Kind)
	m.Value = types.StringValue(e.Value)
	m.AddedBy = types.StringValue(e.AddedBy)
	m.Active = types.BoolValue(e.Active)
	// Optional inputs: keep the configured spelling (the server may canonicalize
	// timestamps); only adopt server values the practitioner left unset.
	if m.AuthDocRef.IsNull() || m.AuthDocRef.IsUnknown() {
		m.AuthDocRef = strFromPtr(e.AuthDocRef)
	}
	if m.Notes.IsNull() || m.Notes.IsUnknown() {
		m.Notes = strFromPtr(e.Notes)
	}
	if m.ExpiresAt.IsNull() || m.ExpiresAt.IsUnknown() {
		m.ExpiresAt = strFromPtr(e.ExpiresAt)
	}
}

func (r *scopeEntryResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan scopeEntryModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.c.CreateScopeEntry(ctx, client.ScopeEntry{
		Kind:       plan.Kind.ValueString(),
		Value:      plan.Value.ValueString(),
		AddedBy:    plan.AddedBy.ValueString(),
		AuthDocRef: strPtr(plan.AuthDocRef),
		Notes:      strPtr(plan.Notes),
		ExpiresAt:  strPtr(plan.ExpiresAt),
	})
	if err != nil {
		resp.Diagnostics.AddError("Creating scope entry failed", err.Error())
		return
	}
	r.apply(&plan, out)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *scopeEntryResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var st scopeEntryModel
	resp.Diagnostics.Append(req.State.Get(ctx, &st)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id, err := strconv.ParseInt(st.ID.ValueString(), 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid scope entry id", err.Error())
		return
	}
	e, err := r.c.GetScopeEntry(ctx, id)
	if client.IsNotFound(err) || (err == nil && !e.Active) {
		// Deactivated outside Terraform: treat as gone so it is re-created.
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Reading scope entry failed", err.Error())
		return
	}
	r.apply(&st, e)
	resp.Diagnostics.Append(resp.State.Set(ctx, &st)...)
}

// Update is never reached with real changes (every attribute RequiresReplace)
// but must exist; it just persists the plan.
func (r *scopeEntryResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan scopeEntryModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *scopeEntryResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var st scopeEntryModel
	resp.Diagnostics.Append(req.State.Get(ctx, &st)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id, err := strconv.ParseInt(st.ID.ValueString(), 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid scope entry id", err.Error())
		return
	}
	if err := r.c.DeleteScopeEntry(ctx, id); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Deactivating scope entry failed", err.Error())
	}
}

func (r *scopeEntryResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
