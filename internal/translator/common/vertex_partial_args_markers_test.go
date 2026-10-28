package common

import (
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

func TestVertexPartialArgsAssembler_ArrayEndMarkerWireSequence(t *testing.T) {
	// The functionCall sequence reported in google/adk-go#1630 and CLIProxyAPI#6572.
	chunks := []string{
		`{"id":"vMwRX2nx","name":"describe_tables","willContinue":true}`,
		`{"partialArgs":[{"jsonPath":"$.tables[0]","stringValue":"sales_vs_budget_water","willContinue":true}],"willContinue":true}`,
		`{"partialArgs":[{"jsonPath":"$.tables[0]","stringValue":"co","willContinue":true}],"willContinue":true}`,
		`{"partialArgs":[{"jsonPath":"$.tables[0]"}],"willContinue":true}`,
		`{"partialArgs":[{"jsonPath":"$.tables[1]","stringValue":"sales_vs_budget_davey","willContinue":true}],"willContinue":true}`,
		`{"partialArgs":[{"jsonPath":"$.tables[1]"}],"willContinue":true}`,
		`{"partialArgs":[{"jsonPath":"$.tables[]"}]}`,
	}
	asm := NewVertexPartialArgsAssembler()
	var joined strings.Builder
	for i, raw := range chunks {
		delta, done := asm.PushFunctionCall(gjson.Parse(raw))
		if asm.Err() != nil {
			t.Fatalf("chunk %d: %v", i, asm.Err())
		}
		joined.WriteString(delta)
		if done != (i == len(chunks)-1) {
			t.Fatalf("chunk %d: done=%v", i, done)
		}
	}
	want := `{"tables":["sales_vs_budget_waterco","sales_vs_budget_davey"]}`
	if joined.String() != want || asm.FullArguments() != want || !gjson.Valid(joined.String()) {
		t.Fatalf("arguments=%s full=%s, want %s", joined.String(), asm.FullArguments(), want)
	}
}

func TestVertexPartialArgsAssembler_ArrayEndMarkerBeforeSibling(t *testing.T) {
	for _, pathKey := range []string{"jsonPath", "json_path"} {
		t.Run(pathKey, func(t *testing.T) {
			asm := NewVertexPartialArgsAssembler()
			chunks := []string{
				`{"partialArgs":[{"jsonPath":"$.data[0].label","stringValue":"Jan"}],"willContinue":true}`,
				`{"partialArgs":[{"` + pathKey + `":"$.data[]"}],"willContinue":true}`,
				`{"partialArgs":[{"jsonPath":"$.title","stringValue":"Revenue"}]}`,
			}
			var joined strings.Builder
			for i, raw := range chunks {
				delta, done := asm.PushFunctionCall(gjson.Parse(raw))
				if asm.Err() != nil || done != (i == len(chunks)-1) {
					t.Fatalf("chunk %d: done=%v err=%v", i, done, asm.Err())
				}
				joined.WriteString(delta)
			}
			want := `{"data":[{"label":"Jan"}],"title":"Revenue"}`
			if joined.String() != want || asm.FullArguments() != want {
				t.Fatalf("arguments=%s full=%s, want %s", joined.String(), asm.FullArguments(), want)
			}
		})
	}
}

func TestVertexPartialArgsAssembler_RejectValueBearingArrayEndPaths(t *testing.T) {
	for _, item := range []string{
		`{"jsonPath":"$.tables[]","stringValue":"not a marker"}`,
		`{"jsonPath":"$.tables[]","numberValue":0}`,
		`{"jsonPath":"$.tables[]","boolValue":false}`,
		`{"jsonPath":"$.tables[]","nullValue":null}`,
		`{"jsonPath":"$.tables[]","willContinue":true}`,
		`{"jsonPath":"$.tables[].name"}`,
		`{"jsonPath":"$.tables[bad][]"}`,
		`{"jsonPath":"[]"}`,
		`{"jsonPath":"$.tables[][]"}`,
	} {
		t.Run(item, func(t *testing.T) {
			asm := NewVertexPartialArgsAssembler()
			delta, done := asm.PushFunctionCall(gjson.Parse(`{"partialArgs":[` + item + `]}`))
			if asm.Err() == nil || done || delta != "" {
				t.Fatalf("invalid path accepted: delta=%q done=%v err=%v", delta, done, asm.Err())
			}
		})
	}
}
