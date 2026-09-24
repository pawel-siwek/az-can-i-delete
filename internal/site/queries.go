package site

import (
	"context"
	"strings"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/signal"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// The Resource Graph queries of SPEC sections 5.7 and 5.7b.
const (
	// K18: the autoscale setting that drives this plan.
	autoscaleQuery = "resources | where type =~ 'microsoft.insights/autoscalesettings' " +
		"| where tolower(tostring(properties.targetResourceUri)) == '%s' " +
		"| project id, enabled = tobool(properties.enabled)"
	// K4: Advisor's recommendations for this resource.
	advisorQuery = "advisorresources | where type =~ 'microsoft.advisor/recommendations' " +
		"| where tolower(tostring(properties.resourceMetadata.resourceId)) == '%s' " +
		"| project recType = tostring(properties.recommendationTypeId)"
	// K19: an availability test calling this site's hostname.
	webTestQuery = "resources | where type =~ 'microsoft.insights/webtests' " +
		"| where properties.Request.RequestUrl has '%s' or properties.Configuration.WebTest has '%s' " +
		"| project id, frequency = toint(properties.Frequency)"
)

// configGroup reads everything the site's configuration says about who
// reaches it and how it is deployed. It also keeps the values the traffic
// rules need, because the request ceiling depends on the site's own settings.
type configGroup struct {
	alwaysOn    bool
	healthCheck bool
	capacity    int
	class       string
	read        bool
}

func (g *configGroup) run(in Input) func(context.Context) ([]verdict.Evidence, error) {
	return func(ctx context.Context) ([]verdict.Evidence, error) {
		version, err := apiVersion()
		if err != nil {
			return nil, err
		}
		web, err := in.Clients.ARM.Get(ctx, in.Target.ID+"/config/web", version)
		if err != nil && !collect.NotFound(err) {
			return nil, err
		}
		g.alwaysOn, _ = web.Properties["alwaysOn"].(bool)
		if path, _ := web.Properties["healthCheckPath"].(string); path != "" {
			g.healthCheck = true
		}
		plan := planOf(ctx, in, version)
		g.capacity, g.class = plan.capacity, hostingClass(in.Resource, plan)
		g.read = true
		return []verdict.Evidence{
			customDomains(in.Resource),
			fronted(web),
			accessRestricted(in.Resource, web),
			Catalogue.Present(SignalHostingClass, map[string]any{"hostingClass": g.class}),
		}, nil
	}
}

// listed runs one ARM list or get under its own call budget, so a slow
// sub-resource on one site leaves only its own signal unknown rather than
// every configuration signal read after it (found by the first end-to-end
// run, where one slow call took nine signals with it).
func listed(in Input, path string, read func([]collect.Resource) verdict.Evidence) func(context.Context) ([]verdict.Evidence, error) {
	return func(ctx context.Context) ([]verdict.Evidence, error) {
		version, err := apiVersion()
		if err != nil {
			return nil, err
		}
		items, err := in.Clients.ARM.List(ctx, in.Target.ID+path, version)
		if err != nil && !collect.NotFound(err) {
			return nil, err
		}
		return []verdict.Evidence{read(items)}, nil
	}
}

func sourceControlRun(in Input) func(context.Context) ([]verdict.Evidence, error) {
	return func(ctx context.Context) ([]verdict.Evidence, error) {
		version, err := apiVersion()
		if err != nil {
			return nil, err
		}
		source, err := in.Clients.ARM.Get(ctx, in.Target.ID+"/sourcecontrols/web", version)
		if err != nil && !collect.NotFound(err) {
			return nil, err
		}
		return []verdict.Evidence{sourceControl(source)}, nil
	}
}

func webTestsRun(in Input) func(context.Context) ([]verdict.Evidence, error) {
	return func(ctx context.Context) ([]verdict.Evidence, error) {
		return []verdict.Evidence{webTests(ctx, in)}, nil
	}
}

// planFacts is what the plan tells a site about its own capacity and tier.
type planFacts struct {
	capacity int
	tier     string
	reserved bool
}

// planOf reads the plan behind the site. A plan that cannot be read leaves the
// capacity at its default of one worker, which is the conservative choice: it
// makes the request ceiling smaller and live traffic easier to establish.
func planOf(ctx context.Context, in Input, version string) planFacts {
	id, _ := in.Resource.Properties["serverFarmId"].(string)
	if id == "" || in.Clients.ARM == nil {
		return planFacts{capacity: 1}
	}
	plan, err := in.Clients.ARM.Get(ctx, id, version)
	if err != nil {
		return planFacts{capacity: 1}
	}
	facts := planFacts{capacity: 1}
	if sku, ok := plan.Properties["sku"].(map[string]any); ok {
		facts.tier, _ = sku["tier"].(string)
		if capacity, ok := sku["capacity"].(float64); ok && capacity > 0 {
			facts.capacity = int(capacity)
		}
	}
	facts.reserved, _ = plan.Properties["reserved"].(bool)
	return facts
}

// hostingClass decides which execution counter exists for this site, which is
// what makes a Linux function app impossible to clear on executions alone.
func hostingClass(resource collect.Resource, plan planFacts) string {
	kind := strings.ToLower(resource.Kind)
	reserved, _ := resource.Properties["reserved"].(bool)
	linux := reserved || plan.reserved || strings.Contains(kind, "linux")
	tier := strings.ToLower(plan.tier)
	switch {
	case strings.Contains(tier, "flexconsumption"):
		return ClassFlex
	case !linux:
		return ClassWindows
	case strings.Contains(kind, "workflowapp"):
		return ClassWorkflow
	case strings.Contains(kind, "functionapp") && tier == "dynamic":
		return ClassConsumption
	case strings.Contains(kind, "functionapp"):
		return ClassDedicated
	default:
		return ClassWeb
	}
}

// customDomains reports a hostname somebody published. A custom domain points
// at this site from DNS that this tool cannot see the other end of.
func customDomains(resource collect.Resource) verdict.Evidence {
	names, _ := resource.Properties["hostNames"].([]any)
	custom := 0
	for _, item := range names {
		name, _ := item.(string)
		if name != "" && !strings.HasSuffix(strings.ToLower(name), ".azurewebsites.net") {
			custom++
		}
	}
	if custom == 0 {
		return Catalogue.Absent(SignalCustomDomain)
	}
	return Catalogue.Present(SignalCustomDomain, map[string]any{"referenceCount": custom})
}

// fronted reports a site whose access restrictions say something stands in
// front of it, such as Front Door or an application gateway.
func fronted(web collect.Resource) verdict.Evidence {
	restrictions, _ := web.Properties["ipSecurityRestrictions"].([]any)
	fronts := 0
	for _, item := range restrictions {
		rule, _ := item.(map[string]any)
		tag, _ := rule["tag"].(string)
		if strings.EqualFold(tag, "ServiceTag") || strings.EqualFold(tag, "XffProxy") {
			fronts++
			continue
		}
		if service, _ := rule["ipAddress"].(string); strings.Contains(
			strings.ToLower(service), "azurefrontdoor") {
			fronts++
		}
		headers, _ := rule["headers"].(map[string]any)
		if _, ok := headers["x-azure-fdid"]; ok {
			fronts++
		}
	}
	if fronts == 0 {
		return Catalogue.Absent(SignalFronted)
	}
	return Catalogue.Present(SignalFronted, map[string]any{"referenceCount": fronts})
}

func slotList(slots []collect.Resource) verdict.Evidence {
	if len(slots) == 0 {
		return Catalogue.Absent(SignalSlots)
	}
	return Catalogue.Present(SignalSlots, map[string]any{"slotCount": len(slots)})
}

func sourceControl(source collect.Resource) verdict.Evidence {
	repository, _ := source.Properties["repoUrl"].(string)
	if repository == "" {
		return Catalogue.Absent(SignalSourceControl)
	}
	return Catalogue.Present(SignalSourceControl, map[string]any{"configured": true})
}

// continuousDeployment reports a deployment inside the last thirty days: a
// pipeline is still shipping to this site.
func continuousDeployment(in Input, deployments []collect.Resource) verdict.Evidence {
	newest := time.Time{}
	for _, deployment := range deployments {
		for _, key := range []string{"end_time", "endTime", "start_time"} {
			value, _ := deployment.Properties[key].(string)
			parsed, err := time.Parse(time.RFC3339, value)
			if err == nil && parsed.After(newest) {
				newest = parsed.UTC()
			}
		}
	}
	if newest.IsZero() || newest.Before(in.Cutoff.AddDate(0, 0, -StoppedDays)) {
		return signal.Windowed(Catalogue.Absent(SignalCIActive), in.Cutoff, StoppedDays)
	}
	return signal.Windowed(Catalogue.Present(SignalCIActive, map[string]any{
		"daysAgo": int(in.Cutoff.Sub(newest) / (24 * time.Hour))}), in.Cutoff, StoppedDays)
}

// accessRestricted reports a site the internet cannot reach. It is
// information: unreachable is not unused, and it explains quiet metrics.
func accessRestricted(resource, web collect.Resource) verdict.Evidence {
	access, _ := resource.Properties["publicNetworkAccess"].(string)
	if strings.EqualFold(access, "Disabled") {
		return Catalogue.Present(SignalAccessRestrict, map[string]any{"how": "publicNetworkAccess"})
	}
	restrictions, _ := web.Properties["ipSecurityRestrictions"].([]any)
	for _, item := range restrictions {
		rule, _ := item.(map[string]any)
		action, _ := rule["action"].(string)
		address, _ := rule["ipAddress"].(string)
		if strings.EqualFold(action, "Deny") && (address == "Any" || address == "0.0.0.0/0") {
			return Catalogue.Present(SignalAccessRestrict, map[string]any{"how": "ipRestriction"})
		}
	}
	return Catalogue.Absent(SignalAccessRestrict)
}

// webTests reports an availability test calling this site. Its requests are
// not a person's, which is why the traffic rules have a probe shape at all.
func webTests(ctx context.Context, in Input) verdict.Evidence {
	if !in.Generic.ARGVisible {
		return Catalogue.Unknown(SignalWebTests, in.Generic.ARGUnknown)
	}
	host := defaultHost(in.Resource)
	if host == "" {
		return Catalogue.Absent(SignalWebTests)
	}
	rows, err := in.graph().Query(ctx, webTestQuery, signal.Lower(host), signal.Lower(host))
	if err != nil {
		return Catalogue.Failed(SignalWebTests, err)
	}
	if len(rows.Rows) == 0 {
		return Catalogue.Absent(SignalWebTests)
	}
	return Catalogue.Present(SignalWebTests, map[string]any{"referenceCount": len(rows.Rows)})
}

func defaultHost(resource collect.Resource) string {
	host, _ := resource.Properties["defaultHostName"].(string)
	return host
}

func count(id string, items int) verdict.Evidence {
	if items == 0 {
		return Catalogue.Absent(id)
	}
	return Catalogue.Present(id, map[string]any{"referenceCount": items})
}

// triggerGroup lists a function app's triggers. An enabled non-HTTP trigger
// means something invokes the app on its own, whatever its request count says.
type triggerGroup struct{}

func (triggerGroup) run(in Input) func(context.Context) ([]verdict.Evidence, error) {
	return func(ctx context.Context) ([]verdict.Evidence, error) {
		if !functionApp(in.Resource) {
			// A web app has no trigger list; the Required signal is satisfied
			// by there being no non-HTTP trigger to have.
			return []verdict.Evidence{
				Catalogue.Absent(SignalNonHTTP),
				Catalogue.Present(SignalHTTPOnly, map[string]any{"triggerCount": 0}),
			}, nil
		}
		version, err := apiVersion()
		if err != nil {
			return nil, err
		}
		functions, err := in.Clients.ARM.List(ctx, in.Target.ID+"/functions", version)
		if err != nil {
			if collect.NotFound(err) {
				return []verdict.Evidence{
					Catalogue.Absent(SignalNonHTTP),
					Catalogue.Present(SignalHTTPOnly, map[string]any{"triggerCount": 0}),
				}, nil
			}
			return nil, err
		}
		nonHTTP := 0
		for _, function := range functions {
			if disabled, _ := function.Properties["isDisabled"].(bool); disabled {
				continue
			}
			nonHTTP += nonHTTPBindings(function)
		}
		if nonHTTP == 0 {
			return []verdict.Evidence{
				Catalogue.Absent(SignalNonHTTP),
				Catalogue.Present(SignalHTTPOnly, map[string]any{"triggerCount": 0}),
			}, nil
		}
		return []verdict.Evidence{
			Catalogue.Present(SignalNonHTTP, map[string]any{"triggerCount": nonHTTP}),
			Catalogue.Absent(SignalHTTPOnly),
		}, nil
	}
}

// nonHTTPBindings counts the enabled triggers that fire without a request.
func nonHTTPBindings(function collect.Resource) int {
	config, _ := function.Properties["config"].(map[string]any)
	bindings, _ := config["bindings"].([]any)
	found := 0
	for _, item := range bindings {
		binding, _ := item.(map[string]any)
		kind, _ := binding["type"].(string)
		direction, _ := binding["direction"].(string)
		if !strings.HasSuffix(strings.ToLower(kind), "trigger") {
			continue
		}
		if direction != "" && !strings.EqualFold(direction, "in") {
			continue
		}
		if strings.EqualFold(kind, "httpTrigger") {
			continue
		}
		found++
	}
	return found
}

func functionApp(resource collect.Resource) bool {
	kind := strings.ToLower(resource.Kind)
	return strings.Contains(kind, "functionapp") || strings.Contains(kind, "workflowapp")
}
