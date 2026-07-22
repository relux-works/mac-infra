package maccore

import (
	"encoding/json"
	"testing"
)

func TestSleepPreventionProtocolRequestsContainOnlyFixedActions(t *testing.T) {
	tests := []struct {
		name   string
		action Action
		want   string
	}{
		{
			name:   "enable",
			action: ActionSleepPreventionEnable,
			want:   `{"action":"sleep_prevention_enable"}`,
		},
		{
			name:   "disable",
			action: ActionSleepPreventionDisable,
			want:   `{"action":"sleep_prevention_disable"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := json.Marshal(Request{Action: tt.action})
			if err != nil {
				t.Fatalf("json.Marshal error = %v", err)
			}
			if got := string(raw); got != tt.want {
				t.Fatalf("request JSON = %q, want %q", got, tt.want)
			}
		})
	}
}
