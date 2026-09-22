package storage

import (
	"context"
	"strings"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// The metric calls of SPEC section 5.1. M1 is the whole transaction picture by
// operation, M2 splits it by authentication and response, M3 is egress, M4 the
// object counts and M5 the file service's own operations, which is where SMB
// shows up.
const (
	transactionsMetric = "Transactions"
	egressMetric       = "Egress"
)

// countMetrics are the four object counters, each on its own service URI.
var countMetrics = map[string]string{
	"/blobServices/default":  "BlobCount",
	"/fileServices/default":  "FileCount",
	"/queueServices/default": "QueueMessageCount",
	"/tableServices/default": "TableEntityCount",
}

// record is one metric point with the dimensions the rules read.
type record struct {
	Day       time.Time
	APIName   string
	Kind      string
	Auth      string
	Response  string
	Value     float64
	FileShare bool
}

// observations is everything the metric rules are computed from. Failed is set
// when a call could not be made at all, which makes the silence signals
// unknown rather than silent.
type observations struct {
	transactions []record
	egress       []record
	counts       map[string][]record
	failures     map[string]error
}

func (o *observations) fail(name string, err error) {
	if o.failures == nil {
		o.failures = map[string]error{}
	}
	o.failures[name] = err
}

// collectMetrics issues the five metric calls. Each failure is remembered
// against its call so the rules can say which observation is missing.
func collectMetrics(ctx context.Context, in Input) observations {
	out := observations{counts: map[string][]record{}}
	account := in.Target.ID

	m1, err := metrics(ctx, in, collect.MetricQuery{
		ResourceURI: account, Names: []string{transactionsMetric},
		Filter: "ApiName eq '*' and TransactionType eq '*'", Aggregation: "Total",
		Interval: "P1D", Top: 200, OrderBy: "sum desc", Window: in.Requested})
	if err != nil {
		out.fail("M1", err)
	}
	out.transactions = append(out.transactions, m1...)

	m2, err := metrics(ctx, in, collect.MetricQuery{
		ResourceURI: account, Names: []string{transactionsMetric},
		Filter:      "Authentication eq '*' and ResponseType eq '*' and TransactionType eq 'User'",
		Aggregation: "Total", Interval: "P1D", Top: 50, Window: in.Requested})
	if err != nil {
		out.fail("M2", err)
	}
	out.transactions = append(out.transactions, m2...)

	m3, err := metrics(ctx, in, collect.MetricQuery{
		ResourceURI: account, Names: []string{egressMetric},
		Filter: "Authentication eq '*'", Aggregation: "Total", Interval: "P1D", Window: in.Requested})
	if err != nil {
		out.fail("M3", err)
	}
	out.egress = m3

	for path, name := range countMetrics {
		points, err := metrics(ctx, in, collect.MetricQuery{
			ResourceURI: account + path, Names: []string{name},
			Aggregation: "Average", Interval: "P1D", Window: in.Requested})
		if err != nil {
			out.fail("M4", err)
			continue
		}
		out.counts[name] = points
	}

	m5, err := metrics(ctx, in, collect.MetricQuery{
		ResourceURI: account + "/fileServices/default", Names: []string{transactionsMetric},
		Filter: "ApiName eq '*' and TransactionType eq 'User'", Aggregation: "Total",
		Interval: "P1D", Top: 100, Window: in.Requested})
	if err != nil {
		out.fail("M5", err)
	}
	for i := range m5 {
		m5[i].FileShare = true
		if m5[i].Kind == "" {
			m5[i].Kind = "User"
		}
	}
	out.transactions = append(out.transactions, m5...)
	return out
}

func metrics(ctx context.Context, in Input, query collect.MetricQuery) ([]record, error) {
	if in.Clients.Metrics == nil {
		return nil, &collect.Failure{ErrorCode: "NotSupported", Message: "no metrics client"}
	}
	result, err := in.Clients.Metrics.Metrics(ctx, query)
	if err != nil {
		return nil, err
	}
	var records []record
	for _, series := range result.Series {
		for _, point := range series.Points {
			records = append(records, record{
				Day:      point.Timestamp.UTC().Truncate(24 * time.Hour),
				APIName:  dimension(point.Dimensions, series.Dimensions, "apiname"),
				Kind:     dimension(point.Dimensions, series.Dimensions, "transactiontype"),
				Auth:     dimension(point.Dimensions, series.Dimensions, "authentication"),
				Response: dimension(point.Dimensions, series.Dimensions, "responsetype"),
				Value:    point.Value,
			})
		}
	}
	if result.Truncated {
		return records, collect.ErrTruncated
	}
	return records, nil
}

// dimension reads a dimension case-insensitively from the point or its series.
func dimension(values, fallback map[string]string, name string) string {
	for _, source := range []map[string]string{values, fallback} {
		for key, value := range source {
			if strings.EqualFold(key, name) {
				return value
			}
		}
	}
	return ""
}

// totals is what the rules need out of the raw records, computed once.
type totals struct {
	WritePrimeSum   float64
	WritePrimeDays  int
	WritePrimeMax   float64
	ReadSum         float64
	ReadDays        int
	PollingPerDay   map[time.Time]float64
	ActivitySum     float64
	UnclassifiedSum float64
	SystemSum       float64
	TopSystemAPI    string
	SMBSessions     float64
	AnonymousOK     float64
	NonOAuthReads   float64
	OAuthReads      float64
	EgressBytes     float64
}

// summarize applies the operation table over a window. Two same-day
// refinements from the source table are applied here: a blob property read
// counts as a read only on a day the account also served blob content, and an
// SMB create counts as a write only on a day the client also wrote.
func summarize(records []record, window verdict.Window) totals {
	out := totals{PollingPerDay: map[time.Time]float64{}}
	getBlobDays := map[time.Time]bool{}
	smbWriteDays := map[time.Time]bool{}
	for _, item := range records {
		if outside(item.Day, window) || item.Value <= 0 {
			continue
		}
		if strings.EqualFold(item.APIName, "GetBlob") {
			getBlobDays[item.Day] = true
		}
		if item.FileShare && Classify(item.APIName) == Write && !strings.EqualFold(item.APIName, "Create") {
			smbWriteDays[item.Day] = true
		}
	}
	writeDays := map[time.Time]bool{}
	readDays := map[time.Time]bool{}
	writePerDay := map[time.Time]float64{}
	systemByAPI := map[string]float64{}
	for _, item := range records {
		if outside(item.Day, window) || item.Value <= 0 {
			continue
		}
		if strings.EqualFold(item.Kind, "System") {
			out.SystemSum += item.Value
			systemByAPI[item.APIName] += item.Value
			continue
		}
		// The authentication split (M2) carries no operation name; it answers
		// the anonymous and OAuth questions instead of the class questions.
		if item.APIName == "" {
			if strings.EqualFold(item.Auth, "Anonymous") && strings.EqualFold(item.Response, "Success") {
				out.AnonymousOK += item.Value
			}
			if strings.EqualFold(item.Response, "Success") {
				if strings.EqualFold(item.Auth, "OAuth") {
					out.OAuthReads += item.Value
				} else if item.Auth != "" {
					out.NonOAuthReads += item.Value
				}
			}
			continue
		}
		class := Classify(item.APIName)
		if class == Metadata && strings.EqualFold(item.APIName, "GetBlobProperties") && getBlobDays[item.Day] {
			class = Read
		}
		if class == Metadata && strings.EqualFold(item.APIName, "Create") && item.FileShare && smbWriteDays[item.Day] {
			class = Write
		}
		if SMBSession(item.APIName) {
			out.SMBSessions += item.Value
		}
		if Activity(class) {
			out.ActivitySum += item.Value
		}
		switch class {
		case Read:
			out.ReadSum += item.Value
			readDays[item.Day] = true
		case Polling:
			out.PollingPerDay[item.Day] += item.Value
		case Other:
			out.UnclassifiedSum += item.Value
		}
		if WritePrime(item.APIName) || (class == Write && item.FileShare) {
			out.WritePrimeSum += item.Value
			writeDays[item.Day] = true
			writePerDay[item.Day] += item.Value
		}
	}
	for _, value := range writePerDay {
		out.WritePrimeMax = max(out.WritePrimeMax, value)
	}
	out.WritePrimeDays, out.ReadDays = len(writeDays), len(readDays)
	top, topValue := "", float64(0)
	for name, value := range systemByAPI {
		if value > topValue {
			top, topValue = name, value
		}
	}
	out.TopSystemAPI = top
	return out
}

func outside(day time.Time, window verdict.Window) bool {
	return day.Before(window.Start.UTC().Truncate(24*time.Hour)) || day.After(window.End.UTC())
}

// egressMiB sums the account's egress inside a window.
func egressMiB(records []record, window verdict.Window) float64 {
	total := float64(0)
	for _, item := range records {
		if !outside(item.Day, window) {
			total += item.Value
		}
	}
	return total / (1024 * 1024)
}

// countIncreaseDays counts the days an object counter grew. A growing count is
// somebody putting data in, whatever the transaction metrics say.
func countIncreaseDays(records []record, window verdict.Window) (days int, delta float64) {
	byDay := map[time.Time]float64{}
	var ordered []time.Time
	for _, item := range records {
		if outside(item.Day, window) {
			continue
		}
		if _, seen := byDay[item.Day]; !seen {
			ordered = append(ordered, item.Day)
		}
		byDay[item.Day] = item.Value
	}
	slicesSort(ordered)
	previous := float64(-1)
	for _, day := range ordered {
		value := byDay[day]
		if previous >= 0 && value > previous {
			days++
			delta += value - previous
		}
		previous = value
	}
	return days, delta
}

func slicesSort(days []time.Time) {
	for i := 1; i < len(days); i++ {
		for j := i; j > 0 && days[j].Before(days[j-1]); j-- {
			days[j], days[j-1] = days[j-1], days[j]
		}
	}
}
