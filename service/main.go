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
	"path/filepath"
)

//go:embed web/*
var webFS embed.FS

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	core := flag.String("core", "", "directory containing the ifda python package (auto-detected if empty)")
	workers := flag.Int("workers", 2, "number of concurrent analysis workers")
	qlen := flag.Int("queue", 128, "max queued jobs")
	dataDir := flag.String("data", "", "dir for triage state + uploads (default: OS temp)")
	flag.Parse()

	coreDir := *core
	if coreDir == "" {
		coreDir = findCoreDir()
	}
	if coreDir == "" {
		log.Fatal("could not locate the ifda package; pass -core /path/to/repo")
	}
	log.Printf("ifda core dir: %s", coreDir)

	dir := *dataDir
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "ifda-service")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatal(err)
	}
	log.Printf("data dir: %s", dir)

	store := NewStore()
	worker := NewWorker(store, coreDir, *workers, *qlen)
	triage := NewTriageStore(filepath.Join(dir, "triage.json"))
	api := NewAPI(store, worker, triage, filepath.Join(dir, "uploads"))

	mux := http.NewServeMux()
	api.Routes(mux)

	// Serve the embedded single-page frontend at /.
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatal(err)
	}
	mux.Handle("GET /", http.FileServer(http.FS(sub)))

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

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
