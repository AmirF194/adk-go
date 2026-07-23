package main

import (
	"encoding/json"
	"fmt"
	"sort"
)

func enforceStrictOpenAISchema(val any) {
	switch v := val.(type) {
	case map[string]any:
		isObject := false
		if t, ok := v["type"]; ok {
			if tStr, ok := t.(string); ok && tStr == "object" {
				isObject = true
			}
		} else if _, ok := v["properties"]; ok {
			isObject = true
		}

		if isObject {
			v["additionalProperties"] = false
			if propsVal, ok := v["properties"]; ok {
				if propsMap, ok := propsVal.(map[string]any); ok {
					var req []string
					for k := range propsMap {
						req = append(req, k)
					}
					sort.Strings(req)
					if len(req) > 0 {
						v["required"] = req
					} else {
						v["required"] = []string{} // OpenAI prefers empty array for empty properties sometimes?
					}
				}
			}
		}

		for _, child := range v {
			enforceStrictOpenAISchema(child)
		}
	case []any:
		for _, child := range v {
			enforceStrictOpenAISchema(child)
		}
	}
}

func main() {
	schemaStr := `{
		"type": "object",
		"properties": {
			"city": {"type": "string"},
			"temperature_c": {"type": "integer"}
		},
		"required": ["city"]
	}`
	var schema map[string]any
	json.Unmarshal([]byte(schemaStr), &schema)
	enforceStrictOpenAISchema(schema)
	out, _ := json.MarshalIndent(schema, "", "  ")
	fmt.Println(string(out))
}
