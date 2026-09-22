package vm

import (
	"context"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/rules"
	"github.com/pawel-siwek/az-can-i-delete/internal/signal"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// The Resource Graph queries of SPEC section 5.2.
const (
	// K5: an Azure Backup protected item whose source is this machine.
	backupQuery = "recoveryservicesresources " +
		"| where type =~ 'microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems' " +
		"| where properties.backupManagementType == 'AzureIaasVM' " +
		"and tolower(tostring(properties.sourceResourceId)) == '%s' " +
		"| project id, state = tostring(properties.currentProtectionState), vault = tostring(properties.vaultId)"
	// K5c: a Site Recovery replicated item for this machine.
	replicationQuery = "recoveryservicesresources " +
		"| where type =~ 'microsoft.recoveryservices/vaults/replicationfabrics/replicationprotectioncontainers/replicationprotecteditems' " +
		"| where properties has '%s' | project id"
	// K13: an image or gallery image version built from this machine.
	imageQuery = "resources " +
		"| where type in~ ('microsoft.compute/images','microsoft.compute/galleries/images/versions') " +
		"| where properties has '%s' | project id, generalized = tostring(properties.storageProfile.osDisk.osState)"
	// K14: the roles this machine's own identity holds elsewhere.
	roleQuery = "authorizationresources | where type =~ 'microsoft.authorization/roleassignments' " +
		"| where tolower(tostring(properties.principalId)) == '%s' " +
		"| project scope = tostring(properties.scope)"
	// K15: the two places a private address is wired into the network itself.
	routeQuery = "resources | where type =~ 'microsoft.network/routetables' " +
		"| where properties.routes has '%s' | project id"
	dnsServerQuery = "resources | where type =~ 'microsoft.network/virtualnetworks' " +
		"| where properties.dhcpOptions.dnsServers has '%s' | project id"
)

func apiVersion() (string, error) { return rules.APIVersion(ResourceType) }

// referenceGroup runs the graph-backed reverse references and the platform
// ownership check.
type referenceGroup struct{}

func (referenceGroup) run(in Input) func(context.Context) ([]verdict.Evidence, error) {
	return func(ctx context.Context) ([]verdict.Evidence, error) {
		ids := groupSignals(SignalBackup)
		if !in.Generic.ARGVisible {
			evidence := make([]verdict.Evidence, 0, len(ids))
			for _, id := range ids {
				evidence = append(evidence, Catalogue.Unknown(id, in.Generic.ARGUnknown))
			}
			return evidence, nil
		}
		graph := in.graph()
		id := signal.Lower(in.Target.ID)
		backups, err := graph.Query(ctx, backupQuery, id)
		if err != nil {
			return nil, err
		}
		replication, err := graph.Query(ctx, replicationQuery, id)
		if err != nil {
			return nil, err
		}
		images, err := graph.Query(ctx, imageQuery, id)
		if err != nil {
			return nil, err
		}
		roles, err := identityRoles(ctx, in)
		if err != nil {
			return nil, err
		}
		protected, retained := backupEvidence(backups)
		return []verdict.Evidence{
			protected, retained,
			count(SignalASR, len(replication.Rows)),
			imageEvidence(images),
			platformOwned(in),
			roles,
		}, nil
	}
}

// backupEvidence separates a machine that is still being backed up from one
// whose protection was stopped but whose recovery points are kept.
func backupEvidence(rows collect.Rows) (protected, retained verdict.Evidence) {
	active, stopped := 0, 0
	for _, row := range rows.Rows {
		if state, _ := row["state"].(string); strings.EqualFold(state, "ProtectionStopped") {
			stopped++
			continue
		}
		active++
	}
	protected = Catalogue.Absent(SignalBackup)
	retained = Catalogue.Absent(SignalBackupRetained)
	if active > 0 {
		protected = Catalogue.Present(SignalBackup, map[string]any{"referenceCount": active})
	}
	if stopped > 0 {
		retained = Catalogue.Present(SignalBackupRetained, map[string]any{"referenceCount": stopped})
	}
	return protected, retained
}

// imageEvidence reports an image built from this machine. A generalized source
// machine is a template rather than a dependency, so it is intent.
func imageEvidence(rows collect.Rows) verdict.Evidence {
	if len(rows.Rows) == 0 {
		return Catalogue.Absent(SignalImage)
	}
	generalized := false
	for _, row := range rows.Rows {
		if state, _ := row["generalized"].(string); strings.EqualFold(state, "Generalized") {
			generalized = true
		}
	}
	evidence := Catalogue.Present(SignalImage, map[string]any{"referenceCount": len(rows.Rows)})
	if generalized {
		evidence.Tier = verdict.TierDesignIntent
		evidence.Critical = false
	}
	return evidence
}

// platformOwned reports a machine a managed platform created, by its tags or
// by its resource group's owner.
func platformOwned(in Input) verdict.Evidence {
	for key := range in.Resource.Tags {
		for _, marker := range platformTags {
			if strings.Contains(strings.ToLower(key), marker) {
				return Catalogue.Present(SignalPlatform, map[string]any{"matchedName": true})
			}
		}
	}
	if in.Generic.ManagedBy != "" {
		return Catalogue.Present(SignalPlatform, map[string]any{"matchedName": false})
	}
	return Catalogue.Absent(SignalPlatform)
}

// identityRoles reports what this machine's own identity can do elsewhere;
// deleting the machine takes those grants with it.
func identityRoles(ctx context.Context, in Input) (verdict.Evidence, error) {
	identity, _ := in.Resource.Properties["identity"].(map[string]any)
	principal, _ := identity["principalId"].(string)
	if principal == "" {
		return Catalogue.Absent(SignalIdentityRoles), nil
	}
	rows, err := in.graph().Query(ctx, roleQuery, signal.Lower(principal))
	if err != nil {
		return verdict.Evidence{}, err
	}
	if len(rows.Rows) == 0 {
		return Catalogue.Absent(SignalIdentityRoles), nil
	}
	return Catalogue.Present(SignalIdentityRoles, map[string]any{"referenceCount": len(rows.Rows)}), nil
}

func count(id string, rows int) verdict.Evidence {
	if rows == 0 {
		return Catalogue.Absent(id)
	}
	return Catalogue.Present(id, map[string]any{"referenceCount": rows})
}

// networkGroup reads the machine's interfaces, which is where its addresses
// and its backend pool memberships live.
type networkGroup struct{}

func (networkGroup) run(in Input) func(context.Context) ([]verdict.Evidence, error) {
	return func(ctx context.Context) ([]verdict.Evidence, error) {
		version, err := rules.APIVersion("Microsoft.Network/networkInterfaces")
		if err != nil {
			return nil, err
		}
		profile, _ := in.Resource.Properties["networkProfile"].(map[string]any)
		interfaces, _ := profile["networkInterfaces"].([]any)
		pools, addresses := 0, []string{}
		for _, item := range interfaces {
			body, _ := item.(map[string]any)
			id, _ := body["id"].(string)
			if id == "" {
				continue
			}
			nic, err := in.Clients.ARM.Get(ctx, id, version)
			if err != nil {
				return nil, err
			}
			configurations, _ := nic.Properties["ipConfigurations"].([]any)
			for _, configuration := range configurations {
				body, _ := configuration.(map[string]any)
				inner, _ := body["properties"].(map[string]any)
				for _, key := range []string{"loadBalancerBackendAddressPools",
					"loadBalancerInboundNatRules", "applicationGatewayBackendAddressPools"} {
					values, _ := inner[key].([]any)
					pools += len(values)
				}
				if address, _ := inner["privateIPAddress"].(string); address != "" {
					addresses = append(addresses, address)
				}
			}
		}
		network, err := networkReferences(ctx, in, addresses)
		if err != nil {
			return nil, err
		}
		return []verdict.Evidence{count(SignalPools, pools), network}, nil
	}
}

// networkReferences reports a private address wired into the network itself,
// as a route's next hop or as a virtual network's DNS server. Those survive
// the machine and break silently when it is gone.
func networkReferences(ctx context.Context, in Input, addresses []string) (verdict.Evidence, error) {
	if len(addresses) == 0 {
		return Catalogue.Absent(SignalNetworkRefs), nil
	}
	if !in.Generic.ARGVisible {
		return Catalogue.Unknown(SignalNetworkRefs, in.Generic.ARGUnknown), nil
	}
	graph := in.graph()
	found := 0
	for _, address := range addresses {
		for _, query := range []string{routeQuery, dnsServerQuery} {
			rows, err := graph.Query(ctx, query, address)
			if err != nil {
				return verdict.Evidence{}, err
			}
			found += len(rows.Rows)
		}
	}
	if found == 0 {
		return Catalogue.Absent(SignalNetworkRefs), nil
	}
	return Catalogue.Present(SignalNetworkRefs, map[string]any{"referenceCount": found}), nil
}

// The metric names of SPEC section 5.2.
var (
	cpuMetric          = "Percentage CPU"
	inboundFlowsMetric = "Inbound Flows"
	networkInMetric    = "Network In Total"
	networkOutMetric   = "Network Out Total"
	availabilityMetric = "VmAvailabilityMetric"
)

// metricGroup decides whether the machine is doing anything. All three
// thresholds have to be met before it counts as busy, and the platform's own
// availability metric has to cover the window before silence means anything.
type metricGroup struct{}

func (metricGroup) run(in Input) func(context.Context) ([]verdict.Evidence, error) {
	return func(ctx context.Context) ([]verdict.Evidence, error) {
		if in.Clients.Metrics == nil {
			return []verdict.Evidence{
				Catalogue.NotEvaluated(SignalMetrics), Catalogue.NotEvaluated(SignalMetricSilence)}, nil
		}
		cpu, err := series(ctx, in, []string{cpuMetric}, "Maximum", in.Requested)
		if err != nil {
			return nil, err
		}
		flows, err := series(ctx, in, []string{inboundFlowsMetric}, "Average", in.Requested)
		if err != nil {
			return nil, err
		}
		bytes, err := series(ctx, in, []string{networkInMetric, networkOutMetric}, "Total", in.Requested)
		if err != nil {
			return nil, err
		}
		effective := in.effective()
		availability, err := series(ctx, in, []string{availabilityMetric}, "Average", effective)
		if err != nil {
			return nil, err
		}
		busy := percentile(values(cpu, in.Requested), 95) >= CPUPercentile &&
			percentile(values(flows, in.Requested), 95) > FlowsPercentile &&
			median(daily(bytes, in.Requested)) > DailyBytesMiB*1024*1024
		live := signal.Windowed(Catalogue.Absent(SignalMetrics), in.Cutoff, in.Requested.Days)
		if busy {
			live = signal.Windowed(Catalogue.Present(SignalMetrics, map[string]any{
				"cpuPercentile":   percentile(values(cpu, in.Requested), 95),
				"flowsPercentile": percentile(values(flows, in.Requested), 95),
				"dailyBytes":      median(daily(bytes, in.Requested))}), in.Cutoff, in.Requested.Days)
		}
		return []verdict.Evidence{live, metricSilence(in, busy, availability, effective)}, nil
	}
}

// metricSilence is the Required silence signal. Azure reports a machine's
// availability whether or not anybody uses it, so a window that metric does
// not cover is a window this tool cannot call quiet.
func metricSilence(in Input, busy bool, availability []collect.MetricPoint, effective verdict.Window) verdict.Evidence {
	if busy {
		return signal.Windowed(Catalogue.Absent(SignalMetricSilence), in.Cutoff, effective.Days)
	}
	if effective.Days == 0 {
		return Catalogue.Unknown(SignalMetricSilence, &verdict.Unknown{
			Code: verdict.UnkPartial, Message: "the machine's age leaves no effective window to observe"})
	}
	days := map[time.Time]bool{}
	for _, point := range availability {
		days[point.Timestamp.UTC().Truncate(24*time.Hour)] = true
	}
	if float64(len(days)) < AvailabilityCoverage*float64(effective.Days) {
		return Catalogue.Unknown(SignalMetricSilence, &verdict.Unknown{
			Code:    verdict.UnkPartial,
			Message: "the platform's availability metric did not cover enough of the window to call it quiet"})
	}
	return signal.Windowed(Catalogue.Present(SignalMetricSilence,
		map[string]any{"quietDays": effective.Days}), in.Cutoff, effective.Days)
}

func series(ctx context.Context, in Input, names []string, aggregation string, window verdict.Window) ([]collect.MetricPoint, error) {
	if window.Days == 0 {
		return nil, nil
	}
	result, err := in.Clients.Metrics.Metrics(ctx, collect.MetricQuery{
		ResourceURI: in.Target.ID, Names: names, Aggregation: aggregation,
		Interval: "P1D", Window: window})
	if err != nil {
		return nil, err
	}
	var points []collect.MetricPoint
	for _, item := range result.Series {
		points = append(points, item.Points...)
	}
	return points, nil
}

func values(points []collect.MetricPoint, window verdict.Window) []float64 {
	var out []float64
	for _, point := range points {
		if point.Timestamp.Before(window.Start) || point.Timestamp.After(window.End) {
			continue
		}
		out = append(out, point.Value)
	}
	return out
}

// daily sums every metric in a day, so inbound and outbound bytes are one
// number per day rather than two series.
func daily(points []collect.MetricPoint, window verdict.Window) []float64 {
	byDay := map[time.Time]float64{}
	for _, point := range points {
		if point.Timestamp.Before(window.Start) || point.Timestamp.After(window.End) {
			continue
		}
		byDay[point.Timestamp.UTC().Truncate(24*time.Hour)] += point.Value
	}
	out := make([]float64, 0, len(byDay))
	for _, value := range byDay {
		out = append(out, value)
	}
	return out
}

// percentile is the nearest-rank percentile; an empty series is zero, which is
// why the availability coverage check exists separately.
func percentile(values []float64, rank int) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	index := int(math.Ceil(float64(rank)/100*float64(len(sorted)))) - 1
	return sorted[max(0, min(index, len(sorted)-1))]
}

func median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	middle := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[middle]
	}
	return (sorted[middle-1] + sorted[middle]) / 2
}
