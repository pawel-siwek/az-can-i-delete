package azure

import (
	"context"
	"net/url"

	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/rules"
)

type graphClient struct{ client *Client }

type graphRequest struct {
	Subscriptions []string     `json:"subscriptions"`
	Query         string       `json:"query"`
	Options       graphOptions `json:"options"`
}

type graphOptions struct {
	ResultFormat string `json:"resultFormat"`
	Top          int    `json:"$top,omitempty"`
	SkipToken    string `json:"$skipToken,omitempty"`
}

type graphResponse struct {
	TotalRecords    int64            `json:"totalRecords"`
	Count           int64            `json:"count"`
	ResultTruncated string           `json:"resultTruncated"`
	SkipToken       string           `json:"$skipToken"`
	Data            []map[string]any `json:"data"`
}

// Query runs one Resource Graph query over the caller's explicit subscription
// scope. Truncation and a skip token are reported rather than hidden: a partial
// graph answer is not proof that a dependency does not exist.
func (c *graphClient) Query(ctx context.Context, query collect.Query) (collect.Rows, error) {
	if len(query.Subscriptions) == 0 {
		return collect.Rows{}, &collect.Failure{ErrorCode: "InvalidQuery",
			Message: "a Resource Graph query needs an explicit subscription scope"}
	}
	top := query.Top
	if top <= 0 || top > collect.MaxGraphPage {
		top = collect.MaxGraphPage
	}
	request := graphRequest{
		Subscriptions: query.Subscriptions,
		Query:         query.Text,
		Options:       graphOptions{ResultFormat: "objectArray", Top: top, SkipToken: query.SkipToken},
	}
	var response graphResponse
	path := "/providers/Microsoft.ResourceGraph/resources"
	versions := url.Values{"api-version": {rules.MustOperation("resourceGraph")}}
	if err := c.client.post(ctx, path, versions, request, &response); err != nil {
		return collect.Rows{}, err
	}
	return collect.Rows{
		Rows:      response.Data,
		Truncated: response.ResultTruncated == "true",
		SkipToken: response.SkipToken,
	}, nil
}
