package output

import (
	"bytes"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// Tag separates key/value provenance so redaction never relies on key guessing.
type Tag struct{ Key, Value string }

// Metadata accepts only known free-form fields. App-setting values deliberately
// have no input slot. Callers must not disguise values as keys or other metadata.
type Metadata struct {
	Name           string
	ResourceGroup  string
	Callers        []string
	Tags           []Tag
	AppSettingKeys []string
}

// Scope records actual collection coverage, not inferred access.
type Scope struct {
	ARGSubscriptionsQueried []string
	ARGVisible              bool
	ActivityLogDays         int
	ResourceChangesDays     int
}

// Noise records counts against tool-owned rule IDs.
type Noise struct {
	Signal, Rule string
	Amount       float64
}

// Cordon is observed state; reporting never mutates Azure.
type Cordon struct {
	Active   bool
	Since    time.Time
	By, Mode string
}

// Input supplies a complete normalized engine input and observed report metadata.
// Build calls verdict.Evaluate, so an evaluation error cannot become a report.
type Input struct {
	ResourceID    string
	GeneratedAt   time.Time
	Replay        bool
	HostingClass  string
	Assessment    verdict.Input
	Metadata      Metadata
	Scope         Scope
	NoiseExcluded []Noise
	Cordon        Cordon
}

// Report seals a sanitized, immutable JSON representation. Its zero value is
// invalid. JSON and Value are equivalent safe MCP boundaries; Value returns a
// detached copy. No rendering entry point accepts raw collector input.
type Report struct {
	data    []byte
	verdict string
}

// JSON returns an independent copy of the sanitized representation.
func (r Report) JSON() ([]byte, error) {
	if len(r.data) == 0 {
		return nil, boundaryError()
	}
	return bytes.Clone(r.data), nil
}

// MarshalJSON preserves the sealed boundary when a Report is nested in output.
func (r Report) MarshalJSON() ([]byte, error) { return r.JSON() }

// Value returns a detached structured value without losing integer precision.
func (r Report) Value() (map[string]any, error) {
	if len(r.data) == 0 {
		return nil, boundaryError()
	}
	decoder := json.NewDecoder(bytes.NewReader(r.data))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return nil, boundaryError()
	}
	return value, nil
}

// BuildForMCP applies mandatory tag redaction before creating either MCP form.
func BuildForMCP(in Input, cfg Config) (Report, error) {
	cfg.RedactTags = true
	return Build(in, cfg)
}

// Build evaluates normalized input and emits the complete schemaVersion 2 shape.
// Undeclared scalars and sensitive containers are omitted with quarantine counts.
// Other undeclared structures and invalid declared types fail without a report.
func Build(in Input, cfg Config) (Report, error) {
	if err := validateConfig(cfg); err != nil {
		return Report{}, err
	}
	target, err := canonicalID(in.ResourceID)
	if err != nil {
		return Report{}, err
	}
	if target.ResourceType != in.Assessment.Type || !slices.Contains(resourceTypes, target.ResourceType) {
		return Report{}, boundaryError()
	}
	generated, err := utc(in.GeneratedAt)
	if err != nil {
		return Report{}, err
	}
	if !slices.Contains(hostingClasses, in.HostingClass) {
		return Report{}, boundaryError()
	}
	for _, e := range in.Assessment.Evidence {
		if !validRuleID(e.ID) {
			return Report{}, boundaryError()
		}
	}
	result, err := verdict.Evaluate(in.Assessment)
	if err != nil {
		return Report{}, boundaryError()
	}
	requested, err := windowValue(in.Assessment.Requested)
	if err != nil {
		return Report{}, err
	}
	effective, err := windowValue(result.Effective)
	if err != nil {
		return Report{}, err
	}
	age, err := ageValue(in.Assessment.Age)
	if err != nil {
		return Report{}, err
	}
	scope, err := scopeValue(in.Scope)
	if err != nil {
		return Report{}, err
	}
	cordon, err := cordonValue(in.Cordon)
	if err != nil {
		return Report{}, err
	}
	noise, err := noiseValue(in.NoiseExcluded, cfg)
	if err != nil {
		return Report{}, err
	}
	redactor := newRedactor(in, cfg.RedactTags)
	metadata := in.Metadata
	if metadata.Name == "" {
		metadata.Name = target.Name
	}
	if metadata.ResourceGroup == "" {
		metadata.ResourceGroup = target.ResourceGroup
	}
	untrusted := metadataValue(metadata, redactor, cfg.RedactTags)
	evidence := make([]any, 0, len(in.Assessment.Evidence))
	unknowns, notEvaluated := []any{}, []any{}
	steps := []string{}
	caveats := append([]string{}, cfg.Caveats...)
	byID := map[string]map[string]any{}
	for _, e := range in.Assessment.Evidence {
		p := cfg.Policies[e.ID]
		safe, err := evidenceValue(e, p, redactor)
		if err != nil {
			return Report{}, err
		}
		evidence = append(evidence, safe)
		byID[e.ID] = safe
		steps = append(steps, p.NextSteps...)
		caveats = append(caveats, p.Caveats...)
	}
	for _, id := range result.Unknowns {
		safe := byID[id]["unknown"].(map[string]any)
		unknowns = append(unknowns, withID(id, safe))
	}
	for _, id := range result.NotEvaluated {
		safe := byID[id]["notEvaluated"].(map[string]any)
		notEvaluated = append(notEvaluated, withID(id, safe))
	}
	question := ""
	if result.HumanEscalation {
		question = "Can a human resolve the reported uncertainty and verify consumers before considering deletion? Do not shorten the observation window."
		if len(result.Reasons) > 0 {
			id := strings.TrimPrefix(result.Reasons[0], "required.missing:")
			if p := cfg.Policies[id]; p.HumanQuestion != "" {
				question = p.HumanQuestion
			}
		}
	}
	value := map[string]any{
		"schemaVersion": "2", "toolVersion": cfg.ToolVersion, "rulesDate": cfg.RulesDate,
		"generatedAt": generated, "replay": in.Replay,
		"resourceId": target.ID, "resourceType": target.ResourceType, "subscriptionId": target.SubscriptionID,
		"resourceGroup": "(see untrusted.resourceGroup)", "name": "(see untrusted.name)", "hostingClass": in.HostingClass,
		"verdict": result.Verdict, "reasonClass": result.ReasonClass,
		"humanEscalation": result.HumanEscalation, "requiredHumanQuestion": question,
		"reasons": result.Reasons, "window": map[string]any{"requested": requested, "effective": effective},
		"age": age, "evidence": evidence, "unknowns": unknowns, "notEvaluated": notEvaluated,
		"coverage": map[string]any{"total": result.Coverage.Total, "evaluated": result.Coverage.Evaluated,
			"unknown": result.Coverage.Unknown, "notEvaluated": result.Coverage.NotEvaluated,
			"criticalUnknown": result.Coverage.CriticalUnknown, "age": age},
		"scope": scope, "noiseExcluded": noise, "caveats": caveats, "cordon": cordon,
		"nextSteps": steps, "limitations": append([]string{}, approvedLimitations...), "untrusted": untrusted,
	}
	// Known secret overlap at a typed identity cannot be redacted without
	// corrupting identity. Fail explicitly rather than emitting or substituting.
	if redactor.conflicts(value) {
		return Report{}, boundaryError()
	}
	data, err := json.Marshal(value)
	if err != nil {
		return Report{}, boundaryError()
	}
	return Report{data: data, verdict: result.Verdict}, nil
}

var resourceTypes = []string{
	"Microsoft.Storage/storageAccounts", "Microsoft.Compute/disks",
	"Microsoft.Network/networkInterfaces", "Microsoft.Network/publicIPAddresses",
	"Microsoft.Network/networkSecurityGroups", "Microsoft.Compute/virtualMachines",
	"Microsoft.Web/sites", "Microsoft.Web/sites/slots", "Microsoft.Web/serverfarms",
	"Microsoft.Network/virtualNetworks", "Microsoft.App/containerApps",
	"Microsoft.App/jobs", "Microsoft.App/managedEnvironments",
}

var hostingClasses = []string{"", "unknown", "not-applicable", "windows", "flex", "linux-consumption", "linux-premium-dedicated", "linux-workflow", "linux-web"}

func validateConfig(cfg Config) error {
	if !versionPattern.MatchString(cfg.ToolVersion) {
		return boundaryError()
	}
	if _, err := time.Parse(time.DateOnly, cfg.RulesDate); err != nil {
		return boundaryError()
	}
	for id, p := range cfg.Policies {
		if !validRuleID(id) {
			return boundaryError()
		}
		if err := validatePolicy(p); err != nil {
			return err
		}
	}
	for _, s := range cfg.Caveats {
		if !fixedText(s) {
			return boundaryError()
		}
	}
	return nil
}

func withID(id string, value map[string]any) map[string]any {
	out := map[string]any{"id": id}
	for key, v := range value {
		out[key] = v
	}
	return out
}

func windowValue(w verdict.Window) (map[string]any, error) {
	start, err := utc(w.Start)
	if err != nil {
		return nil, err
	}
	end, err := utc(w.End)
	if err != nil || w.Start.After(w.End) || w.Days < 0 || !slices.Contains([]string{"", "PT1M", "PT5M", "PT1H", "P1D", "FULL"}, w.Grain) {
		return nil, boundaryError()
	}
	return map[string]any{"start": start, "end": end, "days": w.Days, "grain": w.Grain}, nil
}

func ageValue(a verdict.Age) (map[string]any, error) {
	if !slices.Contains([]string{"", "none", "rp.timestamp", "resourcechanges.move", "resourcechanges.create", "activitylog.created", "deployments", "activitylog.oldest-succeeded", "activitylog.no-events"}, a.Source) {
		return nil, boundaryError()
	}
	caveats := []string{}
	if len(a.Caveats) > 0 {
		caveats = append(caveats, "Collector age caveats were omitted; consult the age evidence and collection coverage.")
	}
	return map[string]any{"lowerBoundDays": a.LowerBoundDays, "confidence": a.Confidence, "source": a.Source, "caveats": caveats}, nil
}

func scopeValue(s Scope) (map[string]any, error) {
	ids := []string{}
	for _, id := range s.ARGSubscriptionsQueried {
		if !guidPattern.MatchString(id) {
			return nil, boundaryError()
		}
		ids = append(ids, strings.ToLower(id))
	}
	if s.ActivityLogDays < 0 || s.ResourceChangesDays < 0 {
		return nil, boundaryError()
	}
	return map[string]any{"argSubscriptionsQueried": ids, "argVisible": s.ARGVisible, "activityLogDays": s.ActivityLogDays, "resourceChangesDays": s.ResourceChangesDays}, nil
}

func cordonValue(c Cordon) (map[string]any, error) {
	out := map[string]any{"active": c.Active}
	if !c.Since.IsZero() {
		ts, err := utc(c.Since)
		if err != nil {
			return nil, err
		}
		out["since"] = ts
	}
	if c.By != "" {
		if !guidPattern.MatchString(c.By) {
			return nil, boundaryError()
		}
		out["by"] = strings.ToLower(c.By)
	}
	if c.Mode != "" {
		if !slices.Contains([]string{"pna", "stop"}, c.Mode) {
			return nil, boundaryError()
		}
		out["mode"] = c.Mode
	}
	return out, nil
}

func noiseValue(items []Noise, cfg Config) ([]any, error) {
	out := []any{}
	for _, n := range items {
		_, signalKnown := cfg.Policies[n.Signal]
		_, ruleKnown := cfg.Policies[n.Rule]
		if !signalKnown || !ruleKnown || n.Amount < 0 {
			return nil, boundaryError()
		}
		amount, err := typedDetail(n.Amount, DetailPolicy{Kind: Number})
		if err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"signal": n.Signal, "rule": n.Rule, "amount": amount})
	}
	return out, nil
}

type redaction struct{ secrets []string }

func newRedactor(in Input, tags bool) redaction {
	r := redaction{}
	if tags {
		for _, tag := range in.Metadata.Tags {
			r.add(tag.Value)
		}
	}
	for _, e := range in.Assessment.Evidence {
		for k, v := range e.Untrusted {
			key := strings.ToLower(k)
			if (tags && strings.HasPrefix(key, "tagvalue")) || strings.HasPrefix(key, "appsettingvalue") {
				r.add(v)
			}
		}
		for k, v := range e.Details {
			key := strings.ToLower(k)
			if strings.Contains(key, "setting") || (tags && strings.Contains(key, "tag")) {
				r.collectValues(v, 0)
			}
		}
	}
	slices.SortFunc(r.secrets, func(a, b string) int { return len(b) - len(a) })
	return r
}

func (r *redaction) collectValues(value any, depth int) {
	if depth > 8 {
		return
	}
	switch v := value.(type) {
	case string:
		r.add(v)
	case map[string]string:
		for _, item := range v {
			r.add(item)
		}
	case map[string]any:
		if item, ok := v["value"]; ok {
			r.collectValues(item, depth+1)
		} else {
			for _, item := range v {
				r.collectValues(item, depth+1)
			}
		}
	case []any:
		for _, item := range v {
			r.collectValues(item, depth+1)
		}
	}
}

func (r *redaction) add(s string) {
	if s != "" {
		r.secrets = append(r.secrets, s)
	}
	clean := cleanRunes(s)
	if clean != "" && clean != s {
		r.secrets = append(r.secrets, clean)
	}
	truncated := sanitize(s)
	if truncated != "" && truncated != s && truncated != clean && truncated != "(URL omitted)" {
		r.secrets = append(r.secrets, truncated)
	}
}

func (r redaction) text(s string) string {
	s = cleanRunes(s)
	for _, secret := range r.secrets {
		if strings.Contains(s, secret) {
			return "(redacted)"
		}
	}
	return sanitize(s)
}

func (r redaction) conflicts(value any) bool {
	switch v := value.(type) {
	case string:
		for _, secret := range r.secrets {
			if strings.Contains(v, secret) {
				return true
			}
		}
	case []string:
		for _, item := range v {
			if r.conflicts(item) {
				return true
			}
		}
	case []any:
		for _, item := range v {
			if r.conflicts(item) {
				return true
			}
		}
	case map[string]any:
		for _, item := range v {
			if r.conflicts(item) {
				return true
			}
		}
	case map[string]string:
		for _, item := range v {
			if r.conflicts(item) {
				return true
			}
		}
	}
	return false
}

func metadataValue(m Metadata, r redaction, redactTags bool) map[string]any {
	out := map[string]any{"name": r.text(m.Name), "resourceGroup": r.text(m.ResourceGroup)}
	callers, keys, tags := []string{}, []string{}, []any{}
	for _, s := range m.Callers {
		callers = append(callers, r.text(s))
	}
	for _, s := range m.AppSettingKeys {
		keys = append(keys, settingKey(s, r))
	}
	for _, tag := range m.Tags {
		value := "(redacted)"
		if !redactTags {
			value = r.text(tag.Value)
		}
		tags = append(tags, map[string]any{"key": r.text(tag.Key), "value": value})
	}
	out["callers"], out["appSettingKeys"], out["tags"] = callers, keys, tags
	return out
}

func settingKey(s string, r redaction) string {
	if strings.ContainsAny(s, "=;\r\n") {
		return "(invalid app-setting key omitted)"
	}
	return r.text(s)
}

func legacyMetadata(values map[string]string, r redaction) (map[string]any, int) {
	out := map[string]any{}
	omitted := 0
	for key, value := range values {
		if slices.Contains([]string{"caller", "name", "resourceGroup", "hostname", "deploymentName", "childName", "unsupportedReason"}, key) {
			out[key] = r.text(value)
			continue
		}
		prefix, index, ok := strings.Cut(key, ":")
		n, err := strconv.Atoi(index)
		if !ok || err != nil || n < 0 || strconv.Itoa(n) != index {
			omitted++
			continue
		}
		switch prefix {
		case "tagKey":
			out[key] = r.text(value)
		case "appSettingKey":
			out[key] = settingKey(value, r)
		case "tagValue":
			// Legacy values lack reliable provenance. Only the typed Metadata.Tags
			// API can opt into publishing values, even outside MCP.
			omitted++
		default:
			omitted++
		}
	}
	return out, omitted
}
