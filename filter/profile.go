package filter

import (
	"math"
	"sync"
	"time"
)

type RateProfile struct {
	mu            sync.Mutex
	windowStart   time.Time
	windowCount   int
	baselinePPS   float64
	minSamples    int
	sampleCount   int
	spikeMultiple float64
	minSpikePPS   float64
}

type ProfileResult struct {
	CurrentPPS  float64
	BaselinePPS float64
	SpikePPS    float64
	Alert       bool
}

type FixedThresholdProfile struct {
	mu           sync.Mutex
	windowStart  time.Time
	windowCount  int
	thresholdPPS float64
}

func NewFixedThresholdProfile(thresholdPPS float64) *FixedThresholdProfile {
	return &FixedThresholdProfile{
		thresholdPPS: thresholdPPS,
	}
}

func (p *FixedThresholdProfile) Observe(now time.Time) (float64, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.windowStart.IsZero() {
		p.windowStart = now
	}

	elapsed := now.Sub(p.windowStart).Seconds()
	if elapsed >= 1 {
		p.windowStart = now
		p.windowCount = 0
		elapsed = 0
	}

	p.windowCount++
	if elapsed <= 0 {
		return float64(p.windowCount), false
	}

	current := float64(p.windowCount) / elapsed
	return current, current > p.thresholdPPS
}

func NewRateProfile(minSamples int, spikeMultiple, minSpikePPS float64) *RateProfile {
	return &RateProfile{
		minSamples:    minSamples,
		spikeMultiple: spikeMultiple,
		minSpikePPS:   minSpikePPS,
	}
}

func (p *RateProfile) Observe(now time.Time) ProfileResult {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.windowStart.IsZero() {
		p.windowStart = now
	}

	p.windowCount++

	elapsed := now.Sub(p.windowStart).Seconds()
	if elapsed <= 0 {
		return ProfileResult{
			CurrentPPS:  float64(p.windowCount),
			BaselinePPS: p.baselinePPS,
			SpikePPS:    p.threshold(),
		}
	}

	current := float64(p.windowCount) / elapsed
	result := ProfileResult{
		CurrentPPS:  current,
		BaselinePPS: p.baselinePPS,
		SpikePPS:    p.threshold(),
	}

	if elapsed < 1 {
		if p.sampleCount >= p.minSamples && current > p.threshold() {
			result.Alert = true
		}
		return result
	}

	closedWindowPPS := float64(p.windowCount) / elapsed
	if p.sampleCount == 0 {
		p.baselinePPS = closedWindowPPS
	} else {
		p.baselinePPS = (p.baselinePPS * 0.85) + (closedWindowPPS * 0.15)
	}
	p.sampleCount++

	p.windowStart = now
	p.windowCount = 0

	result.BaselinePPS = p.baselinePPS
	result.SpikePPS = p.threshold()
	if p.sampleCount >= p.minSamples && current > p.threshold() {
		result.Alert = true
	}
	return result
}

func (p *RateProfile) threshold() float64 {
	return math.Max(p.baselinePPS*p.spikeMultiple, p.minSpikePPS)
}
