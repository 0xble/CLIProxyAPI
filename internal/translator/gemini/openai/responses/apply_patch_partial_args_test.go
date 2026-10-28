package responses

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

func TestGeminiApplyPatchPartialArgsLifecycle(t *testing.T) {
	for _, terminal := range []string{`{}`, `{"partialArgs":[{"jsonPath":"$.input"}]}`} {
		t.Run(terminal, func(t *testing.T) {
			var param any
			want := "  *** Begin Patch\n*** Add File: 中.txt\n+😀\n*** End Patch\n "
			calls := []string{
				`{"id":"patch","name":"functions__apply_patch","willContinue":true}`,
				`{"partialArgs":[{"jsonPath":"$.input","stringValue":"  *** Begin Patch\n*** Add File: 中.txt\n","willContinue":true}],"willContinue":true}`,
				`{"partialArgs":[{"jsonPath":"$.input","stringValue":"+😀\n*** End Patch\n ","willContinue":true}],"willContinue":true}`,
				terminal,
			}
			var delta strings.Builder
			counts := map[string]int{}
			var itemID string
			for i, call := range calls {
				part := `{"partIndex":2,"functionCall":` + call + `}`
				events := geminiPatchReviewEvents(t, ConvertGeminiResponseToOpenAIResponses(context.Background(), "gemini", []byte(geminiPatchRequest), nil, geminiPatchReviewFrame([]string{part}, i == len(calls)-1), &param))
				for _, ev := range events {
					kind := ev.Get("type").String()
					counts[kind]++
					switch kind {
					case "response.failed":
						t.Fatalf("valid partialArgs failed: %s, error=%v", ev.Raw, param.(interface{ ToolInputError() error }).ToolInputError())
					case "response.output_item.added":
						itemID = ev.Get("item.id").String()
						if ev.Get("item.name").String() != "apply_patch" || ev.Get("item.namespace").String() != "functions" || ev.Get("item.call_id").String() != "patch" {
							t.Fatalf("wrong added identity: %s", ev.Raw)
						}
					case "response.custom_tool_call_input.delta":
						delta.WriteString(ev.Get("delta").String())
						if ev.Get("item_id").String() != itemID || ev.Get("call_id").String() != "patch" {
							t.Fatalf("delta identity changed: %s", ev.Raw)
						}
					case "response.custom_tool_call_input.done":
						if ev.Get("input").String() != want || ev.Get("item_id").String() != itemID || ev.Get("call_id").String() != "patch" {
							t.Fatalf("wrong input completion: %s", ev.Raw)
						}
					case "response.output_item.done":
						if ev.Get("item.input").String() != want || ev.Get("item.id").String() != itemID || ev.Get("item.namespace").String() != "functions" {
							t.Fatalf("wrong item completion: %s", ev.Raw)
						}
					}
				}
				if i == 1 && delta.Len() == 0 {
					t.Fatal("partial patch input was not streamed before completion")
				}
				if i < len(calls)-1 && (counts["response.custom_tool_call_input.done"] != 0 || counts["response.output_item.done"] != 0) {
					t.Fatal("partial patch completed early")
				}
			}
			events := geminiPatchReviewEvents(t, ConvertGeminiResponseToOpenAIResponses(context.Background(), "gemini", []byte(geminiPatchRequest), nil, []byte(`[DONE]`), &param))
			for _, ev := range events {
				kind := ev.Get("type").String()
				counts[kind]++
				if kind == "response.completed" && (ev.Get("response.output.#").Int() != 1 || ev.Get("response.output.0.input").String() != want || ev.Get("response.output.0.id").String() != itemID) {
					t.Fatalf("wrong final output: %s", ev.Raw)
				}
			}
			if delta.String() != want || counts["response.custom_tool_call_input.done"] != 1 || counts["response.output_item.done"] != 1 || counts["response.completed"] != 1 || counts["response.failed"] != 0 || param.(interface{ ToolInputError() error }).ToolInputError() != nil {
				t.Fatalf("inconsistent lifecycle: delta=%q counts=%v", delta.String(), counts)
			}
		})
	}
}

func TestGeminiApplyPatchPartialArgsCrossKeyEvidenceConflict(t *testing.T) {
	for _, indexKey := range []string{"partIndex", "index"} {
		for _, patchMode := range []string{"complete", "partial"} {
			for _, direction := range []string{"ordinary index patch ID", "patch index ordinary ID"} {
				for _, name := range []string{"apply_patch", "lookup", ""} {
					t.Run(strings.Join([]string{indexKey, patchMode, direction, name}, "/"), func(t *testing.T) {
						var param any
						request := []byte(geminiMixedPatchReviewRequest)
						send := func(part string) []gjson.Result {
							return geminiPatchReviewEvents(t, ConvertGeminiResponseToOpenAIResponses(context.Background(), "gemini", request, nil, geminiPatchReviewFrame([]string{part}, false), &param))
						}
						send(geminiPatchReviewPart(indexKey, 3, "ordinary", "lookup", `{"x":1}`))
						patch := geminiPatchReviewPart(indexKey, 2, "patch", "apply_patch", `{"input":"p"}`)
						if patchMode == "partial" {
							patch = fmt.Sprintf(`{"%s":2,"functionCall":{"id":"patch","name":"apply_patch","partialArgs":[{"jsonPath":"$.input","stringValue":"p","willContinue":true}],"willContinue":true}}`, indexKey)
						}
						for _, ev := range send(patch) {
							if ev.Get("type").String() == "response.failed" {
								t.Fatalf("seed patch failed: %s", ev.Raw)
							}
						}
						state := param.(*geminiToResponsesState)
						patchEvidence, ordinaryEvidence := state.FunctionEvidence["part:2"], state.FunctionEvidence["part:3"]
						if patchEvidence == nil || patchEvidence.PatchCall == nil || patchMode == "partial" && patchEvidence.PatchCall != state.ActiveStreamingPatch {
							t.Fatal("patch state was not linked to its call provenance")
						}
						index, id := 3, "patch"
						if direction == "patch index ordinary ID" {
							index, id = 2, "ordinary"
						}
						conflict := fmt.Sprintf(`{"%s":%d,"functionCall":{"id":%q,"name":%q,"partialArgs":[{"jsonPath":"$.input","stringValue":"secret","willContinue":true}],"willContinue":true}}`, indexKey, index, id, name)
						events := send(conflict)
						if len(events) != 1 || events[0].Get("type").String() != "response.failed" || events[0].Get("response.error.code").String() != "invalid_tool_arguments" || strings.Contains(events[0].Raw, "secret") {
							t.Fatalf("partial collision was not rejected before emission: %v", events)
						}
						if state.FunctionEvidence["part:2"] != patchEvidence || state.FunctionEvidence["id:patch"] != patchEvidence || state.FunctionEvidence["part:3"] != ordinaryEvidence || state.FunctionEvidence["id:ordinary"] != ordinaryEvidence || state.NextIndex != 2 {
							t.Fatal("collision rebound established call provenance")
						}
						if errInput := state.ToolInputError(); errInput == nil || !strings.Contains(errInput.Error(), "indexes") {
							t.Fatalf("missing identity error: %v", errInput)
						}
						if more := ConvertGeminiResponseToOpenAIResponses(context.Background(), "gemini", request, nil, []byte(`[DONE]`), &param); len(more) != 0 {
							t.Fatal("failed response reopened")
						}
					})
				}
			}
		}
	}
}

func TestGeminiApplyPatchPartialArgsInvalidResponseJSON(t *testing.T) {
	var param any
	part := `{"functionCall":{"id":"patch","name":"apply_patch","partialArgs":[{"jsonPath":"$.input","stringValue":"secret","willContinue":true}],"willContinue":true}}`
	raw := geminiPatchReviewFrame([]string{part}, false)
	raw = raw[:len(raw)-1]
	if gjson.ValidBytes(raw) {
		t.Fatal("fixture must be malformed JSON")
	}
	events := geminiPatchReviewEvents(t, ConvertGeminiResponseToOpenAIResponses(context.Background(), "gemini", []byte(geminiMixedPatchReviewRequest), nil, raw, &param))
	failures := 0
	for _, event := range events {
		kind := event.Get("type").String()
		if kind == "response.failed" {
			failures++
		}
		if kind == "response.output_item.added" || kind == "response.custom_tool_call_input.delta" || strings.Contains(event.Raw, "secret") {
			t.Fatalf("malformed source emitted patch input: %s", event.Raw)
		}
	}
	if failures != 1 || param.(interface{ ToolInputError() error }).ToolInputError() == nil {
		t.Fatalf("missing malformed-source failure: %v", events)
	}
}

func TestGeminiApplyPatchPartialArgsCompletedCallProvenance(t *testing.T) {
	for _, seed := range []string{
		`{"partIndex":2,"functionCall":{"id":"patch","name":"apply_patch","args":{"input":"p"}}}`,
		`{"partIndex":2,"functionCall":{"id":"patch","name":"apply_patch","partialArgs":[{"jsonPath":"$.input","stringValue":"p"}]}}`,
	} {
		for _, next := range []string{
			`{"partIndex":2,"functionCall":{"id":"patch","name":"apply_patch","partialArgs":[{"jsonPath":"$.input","stringValue":"secret","willContinue":true}],"willContinue":true}}`,
			`{"partIndex":2,"functionCall":{"id":"patch","name":"apply_patch","args":{"input":"secret"}}}`,
		} {
			t.Run(seed+"/"+next, func(t *testing.T) {
				var param any
				request := []byte(geminiMixedPatchReviewRequest)
				seedEvents := geminiPatchReviewEvents(t, ConvertGeminiResponseToOpenAIResponses(context.Background(), "gemini", request, nil, geminiPatchReviewFrame([]string{seed}, false), &param))
				completed := 0
				for _, event := range seedEvents {
					if event.Get("type").String() == "response.failed" {
						t.Fatalf("valid seed failed: %s", event.Raw)
					}
					if event.Get("type").String() == "response.custom_tool_call_input.done" {
						completed++
					}
				}
				if completed != 1 {
					t.Fatalf("seed did not complete: %v", seedEvents)
				}
				events := geminiPatchReviewEvents(t, ConvertGeminiResponseToOpenAIResponses(context.Background(), "gemini", request, nil, geminiPatchReviewFrame([]string{next}, false), &param))
				if len(events) != 1 || events[0].Get("type").String() != "response.failed" || strings.Contains(events[0].Raw, "secret") || param.(interface{ ToolInputError() error }).ToolInputError() == nil {
					t.Fatalf("completed patch was reopened or lost provenance: %v", events)
				}
			})
		}
	}
}

func TestGeminiApplyPatchPartialArgsContinuationIdentityConflict(t *testing.T) {
	for _, conflict := range []string{
		`{"partIndex":3,"functionCall":{"partialArgs":[{"jsonPath":"$.input","stringValue":"secret","willContinue":true}],"willContinue":true}}`,
		`{"partIndex":2,"functionCall":{"id":"other","partialArgs":[{"jsonPath":"$.input","stringValue":"secret","willContinue":true}],"willContinue":true}}`,
		`{"partIndex":2,"functionCall":{"name":"lookup","partialArgs":[{"jsonPath":"$.input","stringValue":"secret","willContinue":true}],"willContinue":true}}`,
	} {
		t.Run(conflict, func(t *testing.T) {
			var param any
			request := []byte(geminiMixedPatchReviewRequest)
			first := `{"partIndex":2,"functionCall":{"id":"patch","name":"apply_patch","partialArgs":[{"jsonPath":"$.input","stringValue":"p","willContinue":true}],"willContinue":true}}`
			ConvertGeminiResponseToOpenAIResponses(context.Background(), "gemini", request, nil, geminiPatchReviewFrame([]string{first}, false), &param)
			events := geminiPatchReviewEvents(t, ConvertGeminiResponseToOpenAIResponses(context.Background(), "gemini", request, nil, geminiPatchReviewFrame([]string{conflict}, false), &param))
			if len(events) != 1 || events[0].Get("type").String() != "response.failed" || strings.Contains(events[0].Raw, "secret") {
				t.Fatalf("continuation identity conflict emitted input: %v", events)
			}
			if param.(interface{ ToolInputError() error }).ToolInputError() == nil {
				t.Fatal("missing continuation identity error")
			}
		})
	}
}
