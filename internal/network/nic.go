package network

import (
	"context"
	"strings"

	"github.com/pawel-siwek/az-can-i-delete/internal/signal"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// The network interface signal IDs of SPEC section 5.3.
const (
	SignalNICVM        = "nic.attached.vm"
	SignalNICPE        = "nic.attached.private-endpoint"
	SignalNICPLS       = "nic.attached.pls"
	SignalNICWorkloads = "nic.attached.hosted-workloads"
	SignalNICPool      = "nic.pool.membership"
	SignalNICAGW       = "nic.agw-ip-pool"
	SignalNICDNS       = "nic.dns.records"
	SignalNICFirewall  = "nic.firewall-rules"
	SignalNICStaticIP  = "nic.ip.static"
	SignalNICDetached  = "nic.structural.detached"
	SignalNICIdle      = "nic.detached.ge-30d"
)

// NICCatalogue is SPEC section 5.3. Every owner of a network interface is a
// blocker: ARM refuses to delete an attached interface at all.
var NICCatalogue = signal.Catalogue{
	SignalNICVM:        {Tier: verdict.TierBlocker, Critical: true, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalNICPE:        {Tier: verdict.TierBlocker, Critical: true, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalNICPLS:       {Tier: verdict.TierBlocker, Critical: true, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalNICWorkloads: {Tier: verdict.TierBlocker, Critical: true, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalNICPool:      {Tier: verdict.TierHardDependency, Critical: true, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalNICAGW:       {Tier: verdict.TierHardDependency, Critical: true, Family: "reverse-ref", Confidence: "unknown", API: "ARG", ARGBacked: true},
	SignalNICDNS:       {Tier: verdict.TierHardDependency, Critical: true, Family: "reverse-ref", Confidence: "unknown", API: "ARG", ARGBacked: true},
	SignalNICFirewall:  {Tier: verdict.TierDesignIntent, Family: "reverse-ref", Confidence: "unknown", API: "ARG"},
	SignalNICStaticIP:  {Tier: verdict.TierDesignIntent, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalNICDetached:  {Tier: verdict.TierObservedIdle, Family: "structural", Confidence: "verified", API: "Rules"},
	SignalNICIdle:      {Tier: verdict.TierObservedIdle, Family: "activity-log", Confidence: "verified", API: "ActivityLog"},
}

// NICSignals is the catalogue order.
var NICSignals = []string{
	SignalNICVM, SignalNICPE, SignalNICPLS, SignalNICWorkloads, SignalNICPool,
	SignalNICAGW, SignalNICDNS, SignalNICFirewall, SignalNICStaticIP,
	SignalNICDetached, SignalNICIdle,
}

func collectNIC(ctx context.Context, in Input) []verdict.Evidence {
	properties := in.Resource.Properties
	blockers := []verdict.Evidence{
		blocker(NICCatalogue, SignalNICVM, reference(properties, "virtualMachine", "id")),
		blocker(NICCatalogue, SignalNICPE, reference(properties, "privateEndpoint", "id")),
		blocker(NICCatalogue, SignalNICPLS, reference(properties, "privateLinkService", "id")),
		hostedWorkloads(properties),
	}
	collected := map[string]verdict.Evidence{
		SignalNICPool:     poolMembership(properties),
		SignalNICAGW:      NICCatalogue.NotEvaluated(SignalNICAGW),
		SignalNICDNS:      NICCatalogue.NotEvaluated(SignalNICDNS),
		SignalNICFirewall: NICCatalogue.NotEvaluated(SignalNICFirewall),
		SignalNICStaticIP: staticIP(properties),
	}
	for _, evidence := range blockers {
		collected[evidence.ID] = evidence
	}
	collected[SignalNICDetached] = structural(NICCatalogue, SignalNICDetached, blockers)
	// A virtual machine deleted with its interface does not always write to
	// the interface, so the resource group's own deletions count too.
	collected[SignalNICIdle] = idle(ctx, in, NICCatalogue, SignalNICIdle, "virtualmachines/delete")
	return order(NICCatalogue, NICSignals, collected)
}

func hostedWorkloads(properties map[string]any) verdict.Evidence {
	workloads := list(properties, "hostedWorkloads")
	if len(workloads) == 0 {
		return NICCatalogue.Absent(SignalNICWorkloads)
	}
	return NICCatalogue.Present(SignalNICWorkloads, map[string]any{"attachmentCount": len(workloads)})
}

// poolMembership reports membership of a load balancer, inbound NAT rule or
// application gateway backend pool. Deleting the interface removes a backend
// from something that is still serving traffic.
func poolMembership(properties map[string]any) verdict.Evidence {
	pools := 0
	for _, configuration := range list(properties, "ipConfigurations") {
		body, ok := configuration.(map[string]any)
		if !ok {
			continue
		}
		inner, ok := body["properties"].(map[string]any)
		if !ok {
			continue
		}
		for _, key := range []string{"loadBalancerBackendAddressPools", "loadBalancerInboundNatRules",
			"applicationGatewayBackendAddressPools"} {
			pools += len(list(inner, key))
		}
	}
	if pools == 0 {
		return NICCatalogue.Absent(SignalNICPool)
	}
	return NICCatalogue.Present(SignalNICPool, map[string]any{"poolCount": pools})
}

// staticIP reports an address somebody may have written into a firewall rule
// or an allow list somewhere this tool cannot see.
func staticIP(properties map[string]any) verdict.Evidence {
	static := 0
	for _, configuration := range list(properties, "ipConfigurations") {
		body, ok := configuration.(map[string]any)
		if !ok {
			continue
		}
		inner, ok := body["properties"].(map[string]any)
		if !ok {
			continue
		}
		if method, _ := inner["privateIPAllocationMethod"].(string); strings.EqualFold(method, "Static") {
			static++
		}
	}
	if static == 0 {
		return NICCatalogue.Absent(SignalNICStaticIP)
	}
	return NICCatalogue.Present(SignalNICStaticIP, map[string]any{"staticAddressCount": static})
}
