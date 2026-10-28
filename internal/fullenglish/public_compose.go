package fullenglish

// Production English composition using the authenticated in-process name
// conversion and overlay planner. Both GEKO variants are checked, while the
// currently selected bare layout remains provisional. This is not a decision
// about the translation's final wording or a proof of runtime memory safety.

import (
	"bytes"
	"encoding/json"
	"fmt"
)

func ComposeEnglish(root, cue string) (map[string][]byte, error) {
	var sink map[string][]byte
	var log bytes.Buffer
	if err := composeFullEnglishPlan(root, cue, &log, &sink); err != nil {
		return nil, err
	}
	var result imageCompositionReport
	if err := json.Unmarshal(log.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("integrated plan report invalid: %w", err)
	}
	if result.Status != "TWO_GEKO_POLICIES_PASS_OFFLINE_NOT_RUNTIME" || len(result.Policies) != 2 || sink == nil {
		for _, p := range result.Policies {
			if p.Blocker != "" {
				return nil, fmt.Errorf("%s: %s", p.Policy, p.Blocker)
			}
		}
		return nil, fmt.Errorf("normal full-English composition refused: %s: %s", result.Status, result.RuntimeBlocker)
	}
	for _, p := range result.Policies {
		if p.Status != "COMPLETE_EN_N10_N20_PLAN_PASS_OFFLINE_ONLY" {
			return nil, fmt.Errorf("unvalidated GEKO branch %s", p.Policy)
		}
	}
	return sink, nil
}
