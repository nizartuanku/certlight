// certlight is the shippable product binary: CertLight on Hexward Core.
//
//	certlight                     # serves the dashboard on 127.0.0.1:8422
//	certlight -listen :8422       # expose beyond localhost (put auth/TLS in front)
//	certlight -db certlight.db    # SQLite path (default; ":memory:" for ephemeral)
//
// The five-minute promise: run it, open the dashboard, add a host, see results.
package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3" // dev driver; release swaps to modernc.org/sqlite

	"github.com/nizartuanku/certlight/certlight"
	"github.com/nizartuanku/certlight/notify"
	"github.com/nizartuanku/certlight/sched"
	"github.com/nizartuanku/certlight/store"
	"github.com/nizartuanku/certlight/web"
)

// issuerPublicKey is baked in at build time:
//
//	go build -ldflags "-X main.issuerPublicKeyB64=<base64 from licgen init>"
//
// An empty value means every key is invalid → the product runs as the free
// edition, which is exactly right for the open-source build.
var issuerPublicKeyB64 = ""

func main() {
	listen := flag.String("listen", "127.0.0.1:8422", "dashboard listen address")
	dbPath := flag.String("db", "certlight.db", "SQLite database path")
	licFile := flag.String("license", "license.key", "license key file")
	webhook := flag.String("webhook", "", "webhook URL for notifications (all tiers)")
	syslogAddr := flag.String("syslog", "", "syslog collector host:port for findings, e.g. 127.0.0.1:5514 (point this at Loglight to correlate across products)")
	syslogNet := flag.String("syslog-network", "udp", "syslog transport: udp or tcp")
	slackURL := flag.String("slack-webhook", "", "Slack incoming-webhook URL (Pro/Team)")
	tgToken := flag.String("telegram-token", "", "Telegram bot token (Pro/Team)")
	tgChat := flag.String("telegram-chat", "", "Telegram chat id (Pro/Team)")
	interval := flag.Duration("interval", 0, "scan interval override, e.g. 1h (Pro/Team)")
	flag.Parse()

	// Storage.
	db, err := sql.Open("sqlite3", *dbPath)
	if err != nil {
		fatal("open database: " + err.Error())
	}
	st, err := store.NewSQLiteStore(db)
	if err != nil {
		fatal(err.Error())
	}
	engine := store.NewEngine(st)

	// Product module on the scheduler.
	cw := certlight.New()
	scheduler := sched.New(engine, sched.Config{IntervalOverride: *interval})
	if err := scheduler.Register(cw); err != nil {
		fatal(err.Error())
	}

	// Restore the user's saved targets BEFORE Start, so the first sweep
	// covers them immediately. Raw inputs replay through ValidateTarget —
	// one validation path whether a target arrives from the UI or the DB.
	saved, err := st.ListSavedTargets(cw.Describe().ID)
	if err != nil {
		fatal("load saved targets: " + err.Error())
	}
	for _, raw := range saved {
		if _, err := scheduler.AddTarget(cw.Describe().ID, raw); err != nil {
			fmt.Fprintf(os.Stderr, "certlight: skipping saved target %q: %v\n", raw, err)
		}
	}

	// Dashboard (constructed first: activation gates the paid flags below).
	var pub ed25519.PublicKey
	if issuerPublicKeyB64 != "" {
		if b, err := base64.StdEncoding.DecodeString(issuerPublicKeyB64); err == nil {
			pub = ed25519.PublicKey(b)
		}
	}
	server := web.NewServer(cw.Describe(), st, scheduler, pub, *licFile)
	act := server.Activation()

	// Notification channels, gated by the activation's channel allowance.
	// A disallowed flag is refused loudly at startup, never silently dropped.
	var channels []notify.Channel
	if *webhook != "" {
		channels = append(channels, &notify.WebhookChannel{URL: *webhook})
	}
	if *syslogAddr != "" {
		channels = append(channels, &notify.SyslogChannel{Addr: *syslogAddr, Network: *syslogNet})
	}
	if *slackURL != "" {
		if !act.AllowsChannel("slack") {
			fatal("-slack-webhook requires a Pro or Team license")
		}
		channels = append(channels, &notify.SlackChannel{WebhookURL: *slackURL})
	}
	if *tgToken != "" || *tgChat != "" {
		if !act.AllowsChannel("telegram") {
			fatal("-telegram-* requires a Pro or Team license")
		}
		if *tgToken == "" || *tgChat == "" {
			fatal("telegram needs both -telegram-token and -telegram-chat")
		}
		channels = append(channels, &notify.TelegramChannel{BotToken: *tgToken, ChatID: *tgChat})
	}
	if len(channels) > 0 {
		disp := notify.NewDispatcher(notify.Config{}, channels...)
		notify.BindScheduler(scheduler, disp)
		defer disp.Close()
	}

	// Custom scan interval is a paid feature.
	if *interval > 0 {
		if !act.Limits.CustomInterval {
			fatal("-interval requires a Pro or Team license")
		}
	}
	server.Targets = st // persist add/remove across restarts

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := scheduler.Start(ctx); err != nil {
		fatal(err.Error())
	}

	httpSrv := &http.Server{Addr: *listen, Handler: server.Handler()}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpSrv.Shutdown(shutdownCtx)
		scheduler.Stop()
	}()

	fmt.Printf("CertLight %s — %s edition\n", cw.Describe().Version, act.Tier)
	fmt.Printf("Dashboard: http://%s\n", *listen)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fatal(err.Error())
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "certlight: "+msg)
	os.Exit(1)
}
