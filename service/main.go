package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

//go:embed web/*
var webFS embed.FS

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	core := flag.String("core", "", "directory containing the ifda python package (auto-detected if empty)")
	workers := flag.Int("workers", 2, "number of concurrent analysis workers")
	qlen := flag.Int("queue", 128, "max queued jobs")
	dataDir := flag.String("data", "", "dir for triage state + uploads (default: OS temp)")
	authFlag := flag.Bool("auth", true, "require login (username/password) on /api/*; pass -auth=false to disable (trusted/air-gapped use only)")
	userFlag := flag.String("user", "", "seed this username's password to -pass if the account doesn't exist yet (does NOT overwrite a password already changed via the web UI — pass -reset-pass to force that)")
	passFlag := flag.String("pass", "", "password for -user")
	resetPassFlag := flag.Bool("reset-pass", false, "force -user's password to -pass even if the account already exists (e.g. to recover a forgotten password)")
	flag.Parse()

	coreDir := *core
	if coreDir == "" {
		coreDir = findCoreDir()
	}
	if coreDir == "" {
		log.Fatal("could not locate the ifda package; pass -core /path/to/repo")
	}
	coreDir = mustAbs(coreDir)
	log.Printf("ifda core dir: %s", coreDir)

	dir := *dataDir
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "ifda-service")
	}
	// Must be absolute: this path (job/report file locations) is passed as a
	// --json/--md/--sbom argument to the python subprocess, which runs with
	// cmd.Dir = coreDir, not this process's cwd (see job.go). A relative
	// -data value would resolve against the wrong directory in the child
	// process and the analyze() call would fail writing its own output.
	dir = mustAbs(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatal(err)
	}
	log.Printf("data dir: %s", dir)

	analyzerVersion := detectAnalyzerVersion(coreDir)
	log.Printf("ifda analyzer version: %q", analyzerVersion)
	store, err := NewStore(filepath.Join(dir, "jobs"), analyzerVersion)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("loaded %d job(s) from history", len(store.List()))
	reportDB, err := NewReportDB(filepath.Join(dir, "reports.db"))
	if err != nil {
		log.Fatal(err)
	}
	triage := NewTriageStore(filepath.Join(dir, "triage.json"))
	worker := NewWorker(store, coreDir, *workers, *qlen, reportDB, triage)
	ghidra := checkGhidra(coreDir)
	log.Printf("ghidra decompile enrichment available: %v", ghidra)

	var authStore *AuthStore
	if *authFlag {
		authStore = NewAuthStore(filepath.Join(dir, "users.json"))
		switch {
		case *userFlag != "" && *passFlag != "" && *resetPassFlag:
			authStore.SetPassword(*userFlag, *passFlag)
			log.Printf("auth ENABLED — login required; FORCE-RESET credentials for user %q (-reset-pass)", *userFlag)
		case *userFlag != "" && *passFlag != "" && authStore.HasUser(*userFlag):
			// Deliberately does NOT overwrite: -user/-pass on every launch (e.g.
			// a systemd unit or docker-compose command line) would otherwise
			// silently revert any password the user picked via the web UI's
			// "change password" feature on every restart. Pass -reset-pass to
			// force it when that's actually what's wanted (e.g. recovering a
			// forgotten password).
			log.Printf("auth ENABLED — login required; -user/-pass ignored: %q already has a password "+
				"(possibly changed via the web UI) — pass -reset-pass to force it back to -pass", *userFlag)
		case *userFlag != "" && *passFlag != "":
			authStore.SetPassword(*userFlag, *passFlag)
			log.Printf("auth ENABLED — login required; seeded credentials for new user %q", *userFlag)
		case !authStore.HasUsers():
			pass := randHex(12)
			authStore.SetPassword("admin", pass)
			log.Printf("auth ENABLED — login required; generated account: admin / %s", pass)
		default:
			log.Printf("auth ENABLED — login required; using existing credentials in %s", filepath.Join(dir, "users.json"))
		}
	} else {
		log.Printf("auth disabled (-auth=false) — /api/* is open to anyone who can reach %s", *addr)
	}
	api := NewAPI(store, worker, triage, reportDB, filepath.Join(dir, "uploads"), coreDir, ghidra, authStore)

	mux := http.NewServeMux()
	api.Routes(mux)

	// Serve the embedded single-page frontend at /. embed.FS reports a zero
	// ModTime for every file, so http.FileServer never emits a Last-Modified
	// (net/http only sets it for a non-zero modtime) -- without any
	// validator, a browser that decides to cache the response at all can
	// end up serving it back indefinitely across restarts/rebuilds, with no
	// conditional GET to ever notice a newer build exists. no-cache forces
	// a revalidation round-trip on every load, so a UI fix always actually
	// shows up on the next page load instead of possibly being invisible
	// until the user manually hard-refreshes.
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatal(err)
	}
	staticFS := http.FileServer(http.FS(sub))
	mux.Handle("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		staticFS.ServeHTTP(w, r)
	}))

	log.Printf("ifda service listening on %s (workers=%d)", *addr, *workers)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatal(err)
	}
}

// findCoreDir walks up from the cwd looking for the ifda package so the
// service can be launched from anywhere in the repo.
func findCoreDir() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "ifda", "__init__.py")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// checkGhidra probes the core once at startup for whether the Ghidra
// decompile enrichment (--decompile) will actually do anything, so the
// frontend can hint accordingly instead of a job silently no-op'ing.
func checkGhidra(coreDir string) bool {
	cmd := exec.Command("python3", "-c",
		"import sys; from ifda.re.decompile import ghidra_available; sys.exit(0 if ghidra_available() else 1)")
	cmd.Dir = coreDir
	return cmd.Run() == nil
}

// detectAnalyzerVersion reads ifda.__version__ so it can be mixed into the
// job dedup cache key (see Store.dedupKey): without this, a re-submitted,
// byte-identical target silently reuses a report an older ifda build
// produced, hiding any analyzer feature/fix shipped since. Empty on failure
// (python3/ifda not importable) degrades to the old size+mtime-only key
// rather than failing startup over it.
func detectAnalyzerVersion(coreDir string) string {
	cmd := exec.Command("python3", "-c", "import ifda; print(ifda.__version__)")
	cmd.Dir = coreDir
	out, err := cmd.Output()
	if err != nil {
		log.Printf("warning: could not detect ifda version (dedup cache won't invalidate on analyzer upgrades): %v", err)
		return ""
	}
	return strings.TrimSpace(string(out))
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func mustAbs(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		log.Fatal(err)
	}
	return abs
}
