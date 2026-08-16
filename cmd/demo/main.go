// Demo: the first end-to-end run of a Sentinel product against the real
// internet. Registers CertWatch on the scheduler, scans real hosts once, and
// prints what the future dashboard will show: decisions, not data.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/nizartuanku/certwatch/certwatch"
	"github.com/nizartuanku/certwatch/sched"
	"github.com/nizartuanku/certwatch/store"
)

func main() {
	targets := os.Args[1:]
	if len(targets) == 0 {
		targets = []string{"google.com", "github.com"}
	}

	cw := certwatch.New()
	ms := store.NewMemStore()
	engine := store.NewEngine(ms)
	s := sched.New(engine, sched.Config{ScanTimeout: 15 * time.Second})

	s.OnError = func(e sched.ScanError) {
		fmt.Printf("  ⚠ scan failed for %s: %v\n", e.Target.Canonical, e.Err)
	}

	if err := s.Register(cw); err != nil {
		panic(err)
	}
	for _, t := range targets {
		if _, err := s.AddTarget("certwatch", t); err != nil {
			fmt.Printf("  ✗ %q rejected: %v\n", t, err)
		}
	}

	fmt.Printf("CertWatch — scanning %d target(s)...\n\n", len(targets))
	start := time.Now()
	if err := s.ScanNow(context.Background(), "certwatch"); err != nil {
		panic(err)
	}

	open, _ := ms.ListOpen("certwatch")
	fmt.Printf("Scan complete in %s.\n\n", time.Since(start).Round(time.Millisecond))

	if len(open) == 0 {
		fmt.Println("✅ All clear — no findings on any target.")
		return
	}
	fmt.Printf("%d finding(s):\n\n", len(open))
	for _, r := range open {
		fmt.Printf("  [%s] %s\n", r.Severity, r.Target)
		fmt.Printf("      %s\n", r.Title)
		fmt.Printf("      → %s\n\n", r.Remediation)
	}
}
