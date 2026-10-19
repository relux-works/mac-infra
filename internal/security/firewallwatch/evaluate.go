package firewallwatch

import (
	"context"
	"sort"
	"time"
)

type Metrics struct {
	Dataset       string                    `json:"dataset"`
	N             int                       `json:"n"`
	Accuracy      float64                   `json:"accuracy"`
	MacroF1       float64                   `json:"macro_f1"`
	DecideToNoise int                       `json:"decide_to_noise"`
	P50MS         float64                   `json:"p50_ms"`
	P95MS         float64                   `json:"p95_ms"`
	Unavailable   int                       `json:"classifier_unavailable"`
	Confusion     map[string]map[string]int `json:"confusion"`
}

func Evaluate(ctx context.Context, items []Item, classify func(context.Context, Item) Decision) Metrics {
	m := Metrics{Dataset: "synthetic; self-labelled by policy author", N: len(items), Confusion: map[string]map[string]int{}}
	for _, l := range []string{"noise", "digest", "decide"} {
		m.Confusion[l] = map[string]int{}
	}
	correct := 0
	lat := make([]time.Duration, 0, len(items))
	for _, it := range items {
		t := time.Now()
		d := classify(ctx, it)
		lat = append(lat, time.Since(t))
		m.Confusion[it.Label][d.Label]++
		if d.Label == it.Label {
			correct++
		}
		if it.Label == "decide" && d.Label == "noise" {
			m.DecideToNoise++
		}
		if d.Reason == "classifier_unavailable" {
			m.Unavailable++
		}
	}
	if len(items) == 0 {
		return m
	}
	m.Accuracy = float64(correct) / float64(len(items))
	for _, l := range []string{"noise", "digest", "decide"} {
		tp, fp, fn := m.Confusion[l][l], 0, 0
		for _, other := range []string{"noise", "digest", "decide"} {
			if other != l {
				fp += m.Confusion[other][l]
				fn += m.Confusion[l][other]
			}
		}
		if 2*tp+fp+fn > 0 {
			m.MacroF1 += float64(2*tp) / float64(2*tp+fp+fn) / 3
		}
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	m.P50MS = float64(lat[(len(lat)-1)/2]) / float64(time.Millisecond)
	m.P95MS = float64(lat[int(.95*float64(len(lat)-1))]) / float64(time.Millisecond)
	return m
}
