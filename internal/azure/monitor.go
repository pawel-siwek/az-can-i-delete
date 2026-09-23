package azure

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/age"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/rules"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

type metricsClient struct{ client *Client }

type metricsResponse struct {
	Value []struct {
		Name struct {
			Value string `json:"value"`
		} `json:"name"`
		Unit       string `json:"unit"`
		Timeseries []struct {
			Metadatavalues []struct {
				Name struct {
					Value string `json:"value"`
				} `json:"name"`
				Value string `json:"value"`
			} `json:"metadatavalues"`
			Data []struct {
				TimeStamp time.Time `json:"timeStamp"`
				Total     *float64  `json:"total"`
				Average   *float64  `json:"average"`
				Count     *float64  `json:"count"`
				Maximum   *float64  `json:"maximum"`
				Minimum   *float64  `json:"minimum"`
			} `json:"data"`
		} `json:"timeseries"`
	} `json:"value"`
}

// Metrics reads Azure Monitor metrics over the caller's explicit window. The
// window is a closed timespan, so a metric answer can always be attributed to
// the window the verdict was computed over.
func (c *metricsClient) Metrics(ctx context.Context, query collect.MetricQuery) (collect.MetricResult, error) {
	if len(query.Names) == 0 || len(query.Names) > collect.MaxMetricNames {
		return collect.MetricResult{}, &collect.Failure{ErrorCode: "InvalidQuery",
			Message: fmt.Sprintf("a metrics request needs between 1 and %d metric names", collect.MaxMetricNames)}
	}
	if query.Window.Start.IsZero() || query.Window.End.IsZero() {
		return collect.MetricResult{}, &collect.Failure{ErrorCode: "InvalidQuery",
			Message: "a metrics request needs an explicit window"}
	}
	values := url.Values{
		"api-version": {rules.MustOperation("metrics")},
		"metricnames": {strings.Join(query.Names, ",")},
		"timespan": {query.Window.Start.UTC().Format(time.RFC3339) + "/" +
			query.Window.End.UTC().Format(time.RFC3339)},
		"aggregation": {query.Aggregation},
	}
	if query.Interval != "" {
		values.Set("interval", query.Interval)
	}
	if query.Filter != "" {
		values.Set("$filter", query.Filter)
	}
	if query.Top > 0 {
		values.Set("top", strconv.Itoa(query.Top))
	}
	if query.OrderBy != "" {
		values.Set("orderby", query.OrderBy)
	}
	var response metricsResponse
	path := strings.TrimSuffix(query.ResourceURI, "/") + "/providers/Microsoft.Insights/metrics"
	if err := c.client.get(ctx, path, values, &response); err != nil {
		return collect.MetricResult{}, err
	}
	var result collect.MetricResult
	for _, metric := range response.Value {
		for _, series := range metric.Timeseries {
			dimensions := map[string]string{}
			for _, metadata := range series.Metadatavalues {
				dimensions[metadata.Name.Value] = metadata.Value
			}
			points := make([]collect.MetricPoint, 0, len(series.Data))
			for _, point := range series.Data {
				value, ok := firstValue(point.Total, point.Average, point.Count, point.Maximum, point.Minimum)
				if !ok {
					// A bucket without a value is a bucket Azure has no data for.
					// It is not a zero: the analyzers count observed days.
					continue
				}
				points = append(points, collect.MetricPoint{
					Timestamp: point.TimeStamp.UTC(), Value: value, Dimensions: dimensions})
			}
			result.Series = append(result.Series, collect.MetricSeries{
				Name: metric.Name.Value, Unit: metric.Unit, Dimensions: dimensions, Points: points})
		}
	}
	// Azure caps the number of dimension combinations it returns; a response
	// that fills the requested cap may be hiding series.
	result.Truncated = query.Top > 0 && len(result.Series) >= query.Top
	return result, nil
}

func firstValue(values ...*float64) (float64, bool) {
	for _, value := range values {
		if value != nil {
			return *value, true
		}
	}
	return 0, false
}

type activityLogClient struct{ client *Client }

type activityEventBody struct {
	EventTimestamp time.Time `json:"eventTimestamp"`
	ResourceID     string    `json:"resourceId"`
	Caller         string    `json:"caller"`
	OperationName  struct {
		Value string `json:"value"`
	} `json:"operationName"`
	Status struct {
		Value string `json:"value"`
	} `json:"status"`
	SubStatus struct {
		Value string `json:"value"`
	} `json:"subStatus"`
	HTTPRequest struct {
		Method string `json:"method"`
	} `json:"httpRequest"`
	Properties map[string]any    `json:"properties"`
	Claims     map[string]string `json:"claims"`
}

// Events reads the Activity Log for one resource over the requested window.
// The reported Days is the coverage actually asked for, which is what stops the
// age chain from inferring an absence of events from a short log.
func (c *activityLogClient) Events(ctx context.Context, resourceID string, window verdict.Window) (collect.ActivityLog, error) {
	if window.Start.IsZero() || window.End.IsZero() || window.Days <= 0 {
		return collect.ActivityLog{}, &collect.Failure{ErrorCode: "InvalidQuery",
			Message: "an Activity Log request needs an explicit window"}
	}
	subscription, err := subscriptionOf(resourceID)
	if err != nil {
		return collect.ActivityLog{}, err
	}
	filter := fmt.Sprintf("eventTimestamp ge '%s' and eventTimestamp le '%s' and resourceUri eq '%s'",
		window.Start.UTC().Format(time.RFC3339), window.End.UTC().Format(time.RFC3339), resourceID)
	values := url.Values{
		"api-version": {rules.MustOperation("activityLog")},
		"$filter":     {filter},
		"$select": {"eventTimestamp,resourceId,operationName,status,subStatus," +
			"caller,httpRequest,properties,claims"},
	}
	path := "/subscriptions/" + subscription + "/providers/Microsoft.Insights/eventtypes/management/values"
	bodies, complete, err := list[activityEventBody](ctx, c.client, path, values)
	if err != nil {
		return collect.ActivityLog{}, err
	}
	log := collect.ActivityLog{Days: window.Days, Truncated: !complete}
	for _, body := range bodies {
		statusCode, _ := body.Properties["statusCode"].(string)
		log.Events = append(log.Events, collect.ActivityEvent{
			ActivityEvent: age.ActivityEvent{
				ResourceID: body.ResourceID,
				Timestamp:  body.EventTimestamp.UTC(),
				Operation:  body.OperationName.Value,
				Status:     body.Status.Value,
				StatusCode: statusCode,
				SubStatus:  body.SubStatus.Value,
				HTTPMethod: body.HTTPRequest.Method,
			},
			Caller:     body.Caller,
			CallerType: callerType(body),
			AppID:      appID(body.Claims["appid"]),
		})
	}
	return log, nil
}

// callerType classifies the caller from its claims. The classification is a
// heuristic used for display only; no verdict rule depends on it.
func callerType(body activityEventBody) string {
	if idType := body.Claims["idtyp"]; idType != "" {
		if strings.EqualFold(idType, "app") {
			return "servicePrincipal"
		}
		return "user"
	}
	switch {
	case strings.Contains(body.Caller, "@"):
		return "user"
	case body.Claims["appid"] != "":
		return "servicePrincipal"
	default:
		return "unknown"
	}
}

// guid is the shape an application id must have to be kept.
var guid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// appID keeps a claim only when it is an application id. The claims are the
// caller's token, echoed back by Azure; anything else in that slot is not
// something to compare identities with.
func appID(claim string) string {
	claim = strings.ToLower(strings.TrimSpace(claim))
	if !guid.MatchString(claim) {
		return ""
	}
	return claim
}

// subscriptionOf pulls the subscription out of an ARM id. The Activity Log is
// a subscription-scoped API, so a resource outside one cannot be queried.
func subscriptionOf(resourceID string) (string, error) {
	parts := strings.Split(strings.TrimPrefix(resourceID, "/"), "/")
	if len(parts) < 2 || !strings.EqualFold(parts[0], "subscriptions") || parts[1] == "" {
		return "", &collect.Failure{ErrorCode: "InvalidResourceId",
			Message: "the Activity Log can only be read for a subscription-scoped resource"}
	}
	return parts[1], nil
}
