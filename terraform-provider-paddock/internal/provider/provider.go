// Package provider implements the Paddock Terraform provider: scope, alert
// rules, owner-routing rules and integrations as code, plus a findings data
// source for policy checks in pipelines.
package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/brandongraff-dev/Paddock/terraform-provider-paddock/internal/client"
)

const defaultURL = "http://localhost:8080"

var _ provider.Provider = (*paddockProvider)(nil)

type paddockProvider struct {
	version string
}

// New returns a provider factory.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &paddockProvider{version: version} }
}

type providerModel struct {
	URL    types.String `tfsdk:"url"`
	APIKey types.String `tfsdk:"api_key"`
}

func (p *paddockProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "paddock"
	resp.Version = p.version
}

func (p *paddockProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage a Paddock (defensive attack-surface management) instance as code.",
		Attributes: map[string]schema.Attribute{
			"url": schema.StringAttribute{
				Optional:    true,
				Description: "Orchestrator base URL. Defaults to $PADDOCK_URL, then " + defaultURL + ".",
			},
			"api_key": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Paddock API key (pak_...). Defaults to $PADDOCK_API_KEY. Scope/alert/owner/integration changes need an admin key.",
			},
		},
	}
}

func (p *paddockProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if cfg.URL.IsUnknown() || cfg.APIKey.IsUnknown() {
		resp.Diagnostics.AddAttributeError(path.Root("url"), "Unknown provider configuration",
			"url and api_key must be known at plan time.")
		return
	}
	url := os.Getenv("PADDOCK_URL")
	if !cfg.URL.IsNull() && cfg.URL.ValueString() != "" {
		url = cfg.URL.ValueString()
	}
	if url == "" {
		url = defaultURL
	}
	key := os.Getenv("PADDOCK_API_KEY")
	if !cfg.APIKey.IsNull() && cfg.APIKey.ValueString() != "" {
		key = cfg.APIKey.ValueString()
	}
	c := client.New(url, key, p.version)
	resp.ResourceData = c
	resp.DataSourceData = c
}

func (p *paddockProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewScopeEntryResource,
		NewAlertRuleResource,
		NewOwnerRuleResource,
		NewIntegrationResource,
	}
}

func (p *paddockProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewFindingsDataSource,
	}
}
