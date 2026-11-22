package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/brandongraff-dev/paddock/terraform-provider-paddock/internal/client"
)

// clientFrom extracts the configured API client from provider data.
func clientFrom(data any, diags *diag.Diagnostics) *client.Client {
	if data == nil {
		return nil // provider not configured yet (validation phase)
	}
	c, ok := data.(*client.Client)
	if !ok {
		diags.AddError("Unexpected provider data", fmt.Sprintf("expected *client.Client, got %T", data))
		return nil
	}
	return c
}

func strPtr(v types.String) *string {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	s := v.ValueString()
	return &s
}

func strFromPtr(p *string) types.String {
	if p == nil {
		return types.StringNull()
	}
	return types.StringValue(*p)
}

func listToStrings(ctx context.Context, l types.List, diags *diag.Diagnostics) []string {
	if l.IsNull() || l.IsUnknown() {
		return nil
	}
	var out []string
	diags.Append(l.ElementsAs(ctx, &out, false)...)
	return out
}

func stringsToList(in []string) types.List {
	if in == nil {
		return types.ListNull(types.StringType)
	}
	vals := make([]attr.Value, 0, len(in))
	for _, s := range in {
		vals = append(vals, types.StringValue(s))
	}
	l, _ := types.ListValue(types.StringType, vals)
	return l
}

func anyToStrings(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func anyToString(v any) types.String {
	if s, ok := v.(string); ok && s != "" {
		return types.StringValue(s)
	}
	return types.StringNull()
}

// jsonObject parses an optional JSON-object attribute (written with jsonencode()).
func jsonObject(v types.String, attrName string, diags *diag.Diagnostics) map[string]any {
	out := map[string]any{}
	if v.IsNull() || v.IsUnknown() || v.ValueString() == "" {
		return out
	}
	if err := json.Unmarshal([]byte(v.ValueString()), &out); err != nil {
		diags.AddError("Invalid "+attrName, attrName+" must be a JSON object (use jsonencode({...})): "+err.Error())
	}
	return out
}

// jsonAttr keeps the practitioner's spelling when the server's JSON is
// semantically equal (avoids perpetual diffs from key order/whitespace).
func jsonAttr(prior types.String, server map[string]any) types.String {
	if !prior.IsNull() && !prior.IsUnknown() {
		var p map[string]any
		if json.Unmarshal([]byte(prior.ValueString()), &p) == nil && reflect.DeepEqual(normalize(p), normalize(server)) {
			return prior
		}
	}
	if len(server) == 0 && (prior.IsNull() || prior.IsUnknown()) {
		return types.StringNull()
	}
	b, _ := json.Marshal(server)
	return types.StringValue(string(b))
}

func normalize(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}
