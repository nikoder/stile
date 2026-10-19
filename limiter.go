package main

import (
	"sync"
	"time"
)

// limiter is a sliding-window counter per key. It gates ceremony starts
// and counts login failures — crude, but a presence-only assertion can't
// be brute-forced online anyway; this just keeps noise and griefing down.
type limiter struct {
	mu     sync.Mutex
	window time.Duration
	events map[string][]time.Time
}

func newLimiter(window time.Duration) *limiter {
	return &limiter{window: window, events: map[string][]time.Time{}}
}

// Allow records an event for key and reports whether it stays within max
// events per window.
func (l *limiter) Allow(key string, max int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-l.window)
	kept := l.events[key][:0]
	for _, t := range l.events[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= max {
		l.events[key] = kept
		return false
	}
	l.events[key] = append(kept, now)
	return true
}

// Peek reports whether key is within max without recording an event.
func (l *limiter) Peek(key string, max int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := time.Now().Add(-l.window)
	n := 0
	for _, t := range l.events[key] {
		if t.After(cutoff) {
			n++
		}
	}
	return n < max
}
