package output

import (
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

func evidenceValue(e verdict.Evidence, p SignalPolicy, r redaction) (map[string]any, error) {
	details := map[string]any{}
	untrusted, omitted := legacyMetadata(e.Untrusted, r)
	quarantined := 0
	for key, value := range e.Details {
		policy, ok := p.Details[key]
		if !ok {
			lower := strings.ToLower(key)
			if !strings.Contains(lower, "setting") && !strings.Contains(lower, "tag") && !scalarDetail(value) {
				return nil, boundaryError()
			}
			quarantined++
			continue
		}
		safe, err := typedDetail(value, policy)
		if err != nil {
			return nil, err
		}
		details[key] = safe
	}
	quarantine := []any{}
	if quarantined > 0 {
		quarantine = append(quarantine, map[string]any{"field": "details", "handling": "undeclared keys and values omitted", "count": quarantined})
	}
	if omitted > 0 {
		quarantine = append(quarantine, map[string]any{"field": "untrusted", "handling": "unclassified keys and values omitted", "count": omitted})
	}
	if e.Summary != "" || len(e.NextSteps) > 0 || e.NotEvaluated != nil || (e.Unknown != nil && (e.Unknown.Message != "" || e.Unknown.ErrorCode != "")) || e.Family != "" || e.Confidence != "" || e.TierName != "" {
		quarantine = append(quarantine, map[string]any{"field": "collectorText", "handling": "replaced by tool-owned templates"})
	}
	untrusted["quarantine"] = quarantine
	summary := "Signal " + e.ID + " is " + string(e.Status) + "."
	if text := p.Summaries[e.Status]; text != "" {
		summary = text
	}
	family, confidence := p.Family, p.Confidence
	if !slices.Contains(families, e.Family) || !slices.Contains(confidences, e.Confidence) {
		return nil, boundaryError()
	}
	if family == "" {
		family = e.Family
	}
	if confidence == "" {
		confidence = e.Confidence
	}
	if family == "" {
		family = "unknown"
	}
	if confidence == "" {
		confidence = "unknown"
	}
	source, err := sourceValue(e.Source, p)
	if err != nil {
		return nil, err
	}
	resourceType := e.ResourceType
	if resourceType != "" && !slices.Contains(resourceTypes, resourceType) {
		return nil, boundaryError()
	}
	tiers := []string{"", "BLOCKER", "HARD_DEPENDENCY", "LIVE_ACTIVITY", "DESIGN_INTENT", "OBSERVED_IDLE", "INFO"}
	out := map[string]any{
		"id": e.ID, "tier": e.Tier, "tierName": tiers[e.Tier], "family": family,
		"resourceType": resourceType, "status": e.Status, "critical": e.Critical,
		"summary": summary, "details": details, "untrusted": untrusted,
		"source": source, "confidence": confidence, "nextSteps": append([]string{}, p.NextSteps...),
	}
	if e.Window != nil {
		window, err := windowValue(*e.Window)
		if err != nil {
			return nil, err
		}
		out["window"] = window
	}
	related := []string{}
	for _, id := range e.Related {
		target, err := canonicalID(id)
		if err != nil {
			return nil, err
		}
		related = append(related, target.ID)
	}
	out["related"] = related
	if e.Status == verdict.StatusUnknown {
		unknown, err := unknownValue(e.Unknown)
		if err != nil {
			return nil, err
		}
		out["unknown"] = unknown
	} else if e.Unknown != nil {
		return nil, boundaryError()
	}
	if e.Status == verdict.StatusNotEvaluated {
		n := verdict.NotEvaluated{
			Reason:      "This signal was not evaluated.",
			Consequence: "No conclusion of absence can be drawn from this signal.",
			HowToCheck:  "Ask a human to perform the documented check for this signal.",
		}
		if p.NotEvaluated != nil {
			n = *p.NotEvaluated
		}
		out["notEvaluated"] = map[string]any{"reason": n.Reason, "consequence": n.Consequence, "howToCheck": n.HowToCheck}
	} else if e.NotEvaluated != nil {
		return nil, boundaryError()
	}
	return out, nil
}

func scalarDetail(value any) bool {
	if value == nil {
		return true
	}
	if _, ok := value.(string); ok {
		return true
	}
	if _, ok := value.(bool); ok {
		return true
	}
	_, err := typedDetail(value, DetailPolicy{Kind: Number})
	return err == nil
}

func sourceValue(s verdict.Source, p SignalPolicy) (map[string]any, error) {
	api := s.API
	if api == "" {
		api = "unknown"
	}
	if !slices.Contains([]string{"unknown", "ARM", "ARG", "Metrics", "ActivityLog", "ResourceChanges", "DataPlane", "Rules", "Advisor"}, api) {
		return nil, boundaryError()
	}
	if s.APIVersion != "" && !slices.Contains(p.APIVersions, s.APIVersion) {
		return nil, boundaryError()
	}
	path := ""
	if s.Path != "" {
		target, err := canonicalID(s.Path)
		if err == nil {
			path = target.ID
		} else {
			for _, suffix := range p.SourcePathSuffixes {
				if s.Path == suffix && strings.HasPrefix(suffix, "/providers/") {
					path = suffix
					break
				}
				if strings.HasSuffix(s.Path, suffix) {
					prefix := strings.TrimSuffix(s.Path, suffix)
					base, parseErr := canonicalID(prefix)
					if parseErr == nil {
						path = base.ID + suffix
						break
					}
					parts := strings.Split(prefix, "/")
					if len(parts) == 3 && strings.EqualFold(parts[1], "subscriptions") && guidPattern.MatchString(parts[2]) {
						path = "/subscriptions/" + strings.ToLower(parts[2]) + suffix
						break
					}
				}
			}
			if path == "" {
				return nil, boundaryError()
			}
		}
	}
	return map[string]any{"api": api, "path": path, "apiVersion": s.APIVersion}, nil
}

func unknownValue(u *verdict.Unknown) (map[string]any, error) {
	if u == nil {
		return nil, boundaryError()
	}
	messages := map[verdict.UnknownCode]string{
		verdict.UnkPermission:  "The caller could not read this signal.",
		verdict.UnkNetwork:     "The collection network request failed.",
		verdict.UnkAuth:        "Authentication prevented collection.",
		verdict.UnkThrottled:   "Collection was throttled.",
		verdict.UnkTransient:   "A transient failure prevented collection.",
		verdict.UnkTimeout:     "Collection exceeded its time budget.",
		verdict.UnkPartial:     "Collection was incomplete.",
		verdict.UnkUnsupported: "This acquisition path is unsupported.",
		verdict.UnkDependency:  "A required acquisition dependency was unavailable.",
	}
	message, ok := messages[u.Code]
	if !ok || (u.HTTPStatus != 0 && (u.HTTPStatus < 100 || u.HTTPStatus > 599)) {
		return nil, boundaryError()
	}
	out := map[string]any{"code": string(u.Code), "message": message}
	// The code says what kind of failure it was; the reason says which one.
	// "A transient failure prevented collection" leaves a reader with nothing
	// to do, while "the signal produced no observation" and "the request was
	// rejected" point at different problems. Every reason is a literal written
	// in this repository — internal/conformance holds them to that — so the
	// only thing left to check here is that one has not grown into something
	// the boundary would not publish.
	if reason := strings.TrimSpace(u.Message); reason != "" && fixedText(reason) && utf8.RuneCountInString(reason) <= 160 {
		out["reason"] = reason
	}
	if u.HTTPStatus != 0 {
		out["httpStatus"] = u.HTTPStatus
	}
	return out, nil
}
