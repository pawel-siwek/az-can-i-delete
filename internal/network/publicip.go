package network

import (
	"context"
	"strings"

	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/signal"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// The public IP signal IDs. REQUIREMENTS section 2 builds this analyzer by
// analogy to the network interface, and it is deliberately its own analyzer:
// an address may be held by a load balancer, a NAT gateway, a gateway, a
// bastion, an application gateway or a firewall, not only by an interface.
const (
	SignalPIPAssociated   = "pip.associated"
	SignalPIPNATGateway   = "pip.natgateway"
	SignalPIPDNS          = "pip.dns.records"
	SignalPIPDomainLabel  = "pip.dns.label"
	SignalPIPTraffic      = "pip.metrics.traffic"
	SignalPIPUnassociated = "pip.structural.unassociated"
	SignalPIPIdle         = "pip.unassociated.ge-30d"
)

// TrafficMetrics are the counters an address still carrying traffic reports.
var TrafficMetrics = []string{"ByteCount", "PacketCount", "SynCount"}

// PublicIPCatalogue is the public IP contract of REQUIREMENTS section 2.
var PublicIPCatalogue = signal.Catalogue{
	SignalPIPAssociated:   {Tier: verdict.TierBlocker, Critical: true, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalPIPNATGateway:   {Tier: verdict.TierBlocker, Critical: true, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalPIPDNS:          {Tier: verdict.TierHardDependency, Critical: true, Family: "reverse-ref", Confidence: "unknown", API: "ARG", ARGBacked: true},
	SignalPIPDomainLabel:  {Tier: verdict.TierDesignIntent, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalPIPTraffic:      {Tier: verdict.TierInfo, Family: "metrics", Confidence: "sampled", API: "Metrics"},
	SignalPIPUnassociated: {Tier: verdict.TierObservedIdle, Family: "structural", Confidence: "verified", API: "Rules"},
	SignalPIPIdle:         {Tier: verdict.TierObservedIdle, Family: "activity-log", Confidence: "verified", API: "ActivityLog"},
}

// PublicIPSignals is the catalogue order.
var PublicIPSignals = []string{
	SignalPIPAssociated, SignalPIPNATGateway, SignalPIPDNS, SignalPIPDomainLabel,
	SignalPIPTraffic, SignalPIPUnassociated, SignalPIPIdle,
}

func collectPublicIP(ctx context.Context, in Input) []verdict.Evidence {
	properties := in.Resource.Properties
	blockers := []verdict.Evidence{
		blocker(PublicIPCatalogue, SignalPIPAssociated, reference(properties, "ipConfiguration", "id")),
		blocker(PublicIPCatalogue, SignalPIPNATGateway, reference(properties, "natGateway", "id")),
	}
	unassociated := structural(PublicIPCatalogue, SignalPIPUnassociated, blockers)
	collected := map[string]verdict.Evidence{
		SignalPIPDNS:          PublicIPCatalogue.NotEvaluated(SignalPIPDNS),
		SignalPIPDomainLabel:  domainLabel(properties),
		SignalPIPTraffic:      traffic(ctx, in, unassociated),
		SignalPIPUnassociated: unassociated,
		SignalPIPIdle:         idle(ctx, in, PublicIPCatalogue, SignalPIPIdle, ""),
	}
	for _, evidence := range blockers {
		collected[evidence.ID] = evidence
	}
	return order(PublicIPCatalogue, PublicIPSignals, collected)
}

// domainLabel reports a stable name somebody may have published. A static
// address with a domain label is deliberate, which is design intent.
func domainLabel(properties map[string]any) verdict.Evidence {
	method, _ := properties["publicIPAllocationMethod"].(string)
	label := reference(properties, "dnsSettings", "domainNameLabel")
	if label == "" || !strings.EqualFold(method, "Static") {
		return PublicIPCatalogue.Absent(SignalPIPDomainLabel)
	}
	return PublicIPCatalogue.Present(SignalPIPDomainLabel, map[string]any{"allocation": "Static"})
}

// traffic reads the address's counters. On an address nothing is associated
// with, traffic is a contradiction worth printing; it is information and never
// decides the verdict on its own.
func traffic(ctx context.Context, in Input, unassociated verdict.Evidence) verdict.Evidence {
	if in.Clients.Metrics == nil {
		return PublicIPCatalogue.NotEvaluated(SignalPIPTraffic)
	}
	result, err := in.Clients.Metrics.Metrics(ctx, collect.MetricQuery{
		ResourceURI: in.Target.ID,
		Names:       TrafficMetrics,
		Aggregation: "Total",
		Interval:    "P1D",
		Window:      in.Requested,
	})
	if err != nil {
		return PublicIPCatalogue.Failed(SignalPIPTraffic, err)
	}
	busy := 0
	for _, series := range result.Series {
		for _, point := range series.Points {
			if point.Value > 0 {
				busy++
			}
		}
	}
	if busy == 0 {
		return signal.Windowed(PublicIPCatalogue.Absent(SignalPIPTraffic), in.Cutoff, in.Requested.Days)
	}
	evidence := PublicIPCatalogue.Present(SignalPIPTraffic, map[string]any{
		"busyPoints": busy, "contradiction": unassociated.Status == verdict.StatusPresent})
	return signal.Windowed(evidence, in.Cutoff, in.Requested.Days)
}
