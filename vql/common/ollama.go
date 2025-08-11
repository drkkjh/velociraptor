// ollama.go – enhanced Velociraptor VQL plugin to interact with Ollama
// Copyright (C) 2025
// Author: Wei Li Toh <weili@example.com>
//
// Highlights:
//   • arg_parser‑based argument handling & generated docs
//   • Accepts either a pre‑materialised value (input=…) **or** a live VQL
//     sub‑query (query={ … })
//   • Row‑collection limit and optional streaming‑token handling
//   • Proper scope logging, error rows and RegisterMonitor() instrumentation

package common

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"

	"github.com/Velocidex/ordereddict"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	vfilter "www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/arg_parser"
	"www.velocidex.com/golang/vfilter/types"
)

/*******************************
 * Argument structure
 *******************************/

type OllamaPluginArgs struct {
	Input  types.Any           `vfilter:"optional,field=input,doc=Either a row‑dict or list of row‑dicts (use array() / collect())."`
	Query  vfilter.StoredQuery `vfilter:"optional,field=query,doc=Run this sub‑query and send its rows to the model."`
	Model  string              `vfilter:"optional,field=model,doc=Ollama model name (default qwen2.5:latest)."`
	Prompt string              `vfilter:"optional,field=prompt,doc=Prompt template where %INPUT% is substituted."`
	Limit  int64               `vfilter:"optional,field=limit,doc=Maximum rows to consume from query (default 100)."`
	Base   string              `vfilter:"optional,field=base_url,doc=Override OLLAMA_BASEURL env / default http://localhost:11434."`
	Stream bool                `vfilter:"optional,field=stream,doc=Return streaming tokens as they arrive (TRUE = one row per token)."`
}

/*******************************
 * JSON response structures
 *******************************/

type ollamaResponse struct {
	Done     bool   `json:"done,omitempty"`
	Response string `json:"response"`
	Error    string `json:"error,omitempty"`
}

/*******************************
 * Plugin definition
 *******************************/

type OllamaPlugin struct{}

func (self *OllamaPlugin) Info(scope vfilter.Scope, tm *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name:    "ollama",
		Doc:     "Send rows to an Ollama model and return the LLM response.",
		ArgType: tm.AddType(scope, &OllamaPluginArgs{}),
	}
}

func (self *OllamaPlugin) Call(ctx context.Context,
	scope vfilter.Scope,
	args *ordereddict.Dict) <-chan vfilter.Row {

	output := make(chan vfilter.Row)

	go func() {
		defer close(output)
		defer vql_subsystem.RegisterMonitor("ollama", args)()

		// Parse arguments
		arg := &OllamaPluginArgs{}
		if err := arg_parser.ExtractArgsWithContext(ctx, scope, args, arg); err != nil {
			scope.Log("ollama: %v", err)
			output <- errRow(err.Error())
			return
		}

		if arg.Input == nil && reflect.ValueOf(arg.Query).IsZero() {
			output <- errRow("ollama: either 'input' or 'query' must be supplied")
			return
		}

		rows, err := collectRows(ctx, scope, arg)
		if err != nil {
			output <- errRow(err.Error())
			return
		}

		model := arg.Model
		if model == "" {
			model = "qwen2.5:latest"
		}

		prompt := arg.Prompt
		if prompt == "" {
			prompt = "You are a digital forensic analyst. Analyse:\n\n%INPUT%"
		}
		prompt = strings.ReplaceAll(prompt, "%INPUT%", prettyJSON(rows))

		baseURL := arg.Base
		if baseURL == "" {
			baseURL = os.Getenv("OLLAMA_BASEURL")
			if baseURL == "" {
				baseURL = "http://localhost:11434"
			}
		}

		// Build request body
		reqBody, _ := json.Marshal(map[string]any{
			"model":  model,
			"prompt": prompt,
			"stream": arg.Stream,
		})

		req, _ := http.NewRequestWithContext(ctx, "POST", baseURL+"/api/generate", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			output <- errRow(fmt.Sprintf("HTTP error: %v", err))
			return
		}
		defer resp.Body.Close()

		if arg.Stream {
			dec := json.NewDecoder(resp.Body)
			for {
				var tok ollamaResponse
				if err := dec.Decode(&tok); err != nil {
					if errors.Is(err, io.EOF) {
						break
					}
					output <- errRow("decode stream: " + err.Error())
					return
				}
				if tok.Error != "" {
					output <- errRow("LLM error: " + tok.Error)
					return
				}
				select {
				case <-ctx.Done():
					return
				case output <- ordereddict.NewDict().
					Set("token", tok.Response).
					Set("done", tok.Done).
					Set("model_used", model):
				}
				if tok.Done {
					break
				}
			}
			return
		}

		var res ollamaResponse
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			output <- errRow("parse JSON: " + err.Error())
			return
		}
		if res.Error != "" {
			output <- errRow("LLM error: " + res.Error)
			return
		}

		output <- ordereddict.NewDict().
			Set("llm_response", res.Response).
			Set("rows_input", len(rows)).
			Set("model_used", model)
	}()

	return output
}

/*******************************
 * Helpers
 *******************************/

func errRow(msg string) vfilter.Row {
	return ordereddict.NewDict().Set("error", msg)
}

// collectRows gathers rows from either the supplied value or by executing a sub‑query.
func collectRows(ctx context.Context, scope vfilter.Scope, arg *OllamaPluginArgs) ([]map[string]any, error) {
	// If the caller provided an explicit input value, normalise it and return.
	if arg.Input != nil {
		return toRowSlice(arg.Input)
	}

	// Otherwise, execute the sub‑query.
	limit := int(arg.Limit)
	if limit == 0 {
		limit = 100
	}

	var rows []map[string]any
	for row := range arg.Query.Eval(ctx, scope) {
		odict := vfilter.RowToDict(ctx, scope, row)
		rows = append(rows, dictToMap(odict))
		if len(rows) >= limit {
			break
		}
	}
	if len(rows) == 0 {
		return nil, errors.New("query produced no rows")
	}
	return rows, nil
}

// Converts an ordereddict.Dict to a plain Go map – handy for JSON marshalling.
func dictToMap(d *ordereddict.Dict) map[string]any {
	m := make(map[string]any, d.Len())
	for _, k := range d.Keys() {
		v, _ := d.Get(k)
		m[k] = v
	}
	return m
}

// Normalise the user-supplied input value into a slice of maps.
func toRowSlice(v interface{}) ([]map[string]any, error) {
	switch t := v.(type) {

	case []interface{}:
		var out []map[string]any
		for _, r := range t {
			switch rr := r.(type) {
			case map[string]any: // already a plain map
				out = append(out, rr)

			case *ordereddict.Dict: // convert dict() → map
				out = append(out, dictToMap(rr))

			default:
				return nil, errors.New("input array elements must be dict() or map[string]any")
			}
		}
		return out, nil

	case map[string]interface{}: // single plain map
		return []map[string]any{t}, nil

	case *ordereddict.Dict: // single dict()
		return []map[string]any{dictToMap(t)}, nil

	default:
		return nil, errors.New("input must be dict() or array(); use collect() for tables")
	}
}

func prettyJSON(v interface{}) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

/*******************************
 * Registration
 *******************************/

func init() {
	vql_subsystem.RegisterPlugin(&OllamaPlugin{})
}
