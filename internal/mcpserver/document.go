package mcpserver

import (
	"bytes"
	"encoding/json"
)

// document turns a typed value into the object an MCP result carries, keeping
// integers as integers: the structured content and the JSON text are then the
// same document, not two renderings of it.
func document(value any) (map[string]any, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var out map[string]any
	if err := decoder.Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}
