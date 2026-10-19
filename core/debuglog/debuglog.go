/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 110: the debug mode.
 *
 * The ring log keeps the last 2048 lines, and a long run of tests does not
 * fit in it: by the time the log is read, the start that went wrong has
 * been written over. The debug mode keeps its own file next to log.bin,
 * Data\debug\debug-DATE-NN.log, with no limit on lines. A part is closed at
 * 50 MB and only the 5 newest parts are kept, so the folder never grows
 * past about 250 MB.
 *
 * It is built so that a feature can be added or taken out without touching
 * the rest of the program:
 *
 *   switch.go    the one constant that turns the whole mode on or off
 *   debuglog.go  this file: the file, Printf, Fire, Listen, Register
 *   debug_*.go   one feature each. A feature registers itself in init()
 *                and listens to named points. Deleting its file removes
 *                the feature and nothing else has to change.
 *
 * The rest of the program only calls Start once per process and Fire at a
 * few points. Nothing here may stop the program: every feature runs behind
 * recover, and a file that cannot be written is simply not written.
 */

package debuglog

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

const (
	partLimit      = 50 << 20
	keepParts      = 5
	sizeCheckEvery = 200
	openRetryAfter = 10 * time.Second
)

type feature struct {
	name    string
	enabled bool
	start   func()
}

var (
	mu        sync.Mutex
	started   bool
	tag       string
	dir       string
	file      *os.File
	fileDay   string
	filePart  int
	sinceSize int
	openFail  time.Time
	features  []feature
	hooks     = map[string][]func(args ...any){}
)

// Register is called from init() of a feature file. enabled lets one
// feature be switched off with one word, without deleting its file.
func Register(name string, enabled bool, start func()) {
	mu.Lock()
	features = append(features, feature{name: name, enabled: enabled, start: start})
	mu.Unlock()
}

// Listen makes fn run every time the named point is fired. Features call
// it from their start function, so a feature that is off listens to
// nothing.
func Listen(point string, fn func(args ...any)) {
	mu.Lock()
	hooks[point] = append(hooks[point], fn)
	mu.Unlock()
}

// Start opens the debug file of this process and starts every feature
// that is on. processTag is the same tag the ring log uses, MGR or TUN.
// It is called once, right after the ring log is up.
func Start(processTag string) {
	if !On {
		return
	}
	mu.Lock()
	if started {
		mu.Unlock()
		return
	}
	root, err := conf.RootDirectory(true)
	if err != nil {
		mu.Unlock()
		log.Printf("[WarpAm] The debug mode has no data folder, so it stays off: %v", err)
		return
	}
	dir = filepath.Join(root, "debug")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		mu.Unlock()
		log.Printf("[WarpAm] The debug folder %s could not be made, so the debug mode stays off: %v", dir, err)
		return
	}
	tag = processTag
	started = true
	list := append([]feature(nil), features...)
	mu.Unlock()

	removeOldParts()
	sort.Slice(list, func(i, j int) bool { return list[i].name < list[j].name })
	var on, off []string
	for _, f := range list {
		if f.enabled {
			on = append(on, f.name)
		} else {
			off = append(off, f.name)
		}
	}
	log.Printf("[WarpAm] Debug mode is on: the full log goes to %s", dir)
	Printf("debug mode on, pid %d, features on: [%s], off: [%s]", os.Getpid(), strings.Join(on, ", "), strings.Join(off, ", "))
	for _, f := range list {
		if !f.enabled {
			continue
		}
		f := f
		safe("start of "+f.name, f.start)
	}
}

// Running answers whether the debug mode works in this process.
func Running() bool {
	if !On {
		return false
	}
	mu.Lock()
	defer mu.Unlock()
	return started
}

// Fire runs every feature that listens to the point. With the mode off it
// costs one comparison.
func Fire(point string, args ...any) {
	if !On || !Running() {
		return
	}
	mu.Lock()
	list := append([](func(args ...any)){}, hooks[point]...)
	mu.Unlock()
	for _, fn := range list {
		fn := fn
		safe(point, func() { fn(args...) })
	}
}

// Printf writes one line into the debug file only. The lines carry DBG,
// so they are told apart from the copy of the ordinary log at a glance.
func Printf(format string, args ...any) {
	if !On || !Running() {
		return
	}
	writeLine(time.Now(), log.Prefix()+"DBG "+fmt.Sprintf(format, args...))
}

// Go runs fn in its own goroutine behind recover.
func Go(name string, fn func()) {
	if !On || !Running() {
		return
	}
	go safe(name, fn)
}

func safe(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			writeLine(time.Now(), fmt.Sprintf("DBG the feature at %s failed and was left: %v", name, r))
		}
	}()
	fn()
}

func writeLine(ts time.Time, text string) {
	text = strings.TrimRight(text, "\r\n")
	line := ts.Format("2006-01-02 15:04:05.000") + " [" + tag + "] " + text + "\r\n"
	mu.Lock()
	defer mu.Unlock()
	f := currentPartLocked(ts)
	if f == nil {
		return
	}
	_, _ = f.WriteString(line)
}

func partPath(day string, part int) string {
	return filepath.Join(dir, fmt.Sprintf("debug-%s-%02d.log", day, part+1))
}

// currentPartLocked returns the file to write into. Several processes
// write into the same part, each with its own handle opened for append,
// so every line lands whole. Whoever sees the part pass the limit moves on
// to the next one, and the others follow at their next size check.
func currentPartLocked(ts time.Time) *os.File {
	day := ts.Format("2006-01-02")
	if file != nil && day == fileDay {
		sinceSize++
		if sinceSize < sizeCheckEvery {
			return file
		}
		sinceSize = 0
		if st, err := file.Stat(); err != nil || st.Size() < partLimit {
			return file
		}
		file.Close()
		file = nil
		filePart++
	} else if file != nil {
		file.Close()
		file = nil
	}
	if day != fileDay {
		fileDay = day
		filePart = 0
	}
	if !openFail.IsZero() && time.Since(openFail) < openRetryAfter {
		return nil
	}
	for ; filePart < 100; filePart++ {
		path := partPath(day, filePart)
		if st, err := os.Stat(path); err == nil && st.Size() >= partLimit {
			continue
		}
		// The same descriptor as log.bin, so whoever may read the log may
		// read this file too.
		_ = conf.ChainEnsureFile(path)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
		if err != nil {
			openFail = time.Now()
			return nil
		}
		openFail = time.Time{}
		file = f
		sinceSize = 0
		return f
	}
	openFail = time.Now()
	return nil
}

func removeOldParts() {
	matches, err := filepath.Glob(filepath.Join(dir, "debug-*.log"))
	if err != nil || len(matches) <= keepParts {
		return
	}
	// The names sort by date and part, so the oldest come first.
	sort.Strings(matches)
	for _, path := range matches[:len(matches)-keepParts] {
		_ = os.Remove(path)
	}
}
