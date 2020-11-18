// Copyright (C) 2020-2021,  0xN3utr0n

// Kanis is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Kanis is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Kanis. If not, see <http://www.gnu.org/licenses/>.

package ftrace

import (
	"bufio"
	"io/ioutil"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/0xN3utr0n/Kanis/logger"
	"github.com/0xN3utr0n/Kanis/rulengine/event"
)

const (
	kpipePath    string = "/sys/kernel/debug/tracing/trace_pipe"
	setEventPath string = "/sys/kernel/debug/tracing/set_event"
	keventPath   string = "/sys/kernel/debug/tracing/kprobe_events"
)

// Ftracer contains information about the current Ftrace system.
type Ftracer struct {
	// List of successfully enabled kprobes.
	tracedFuncs map[string]*kProbe
	// Protection bytes against malformed input.
	cookie string
	kpipe  *os.File
}

var log *logger.Logger

// New creates a new ftrace instance.
func New(main *logger.Logger) *Ftracer {
	log = main

	pipefd, err := os.Open(kpipePath)
	if err != nil {
		log.ErrorS(err, "EventReader")
		os.Exit(1)
	}

	randbyte := newCookie()

	log.InfoS("Function Tracing Subsystem - Enabled", "EventReader")

	return &Ftracer{
		kpipe:  pipefd,
		cookie: string(randbyte[:]),
	}
}

// Halt handles gracefully unexpected errors and disables
// the tracing system.
func (myftrace *Ftracer) Halt() {
	sig := logger.KillHandler()
	<-sig // Wait for a SIGINT or SIGTERM

	for _, function := range myftrace.tracedFuncs {
		(*function).action(stop) // Disable all kprobes
		log.DebugS("FTrace: Removed - "+(*function).name, "EventReader")
	}

	// Disable ftrace
	if err := ioutil.WriteFile(keventPath, []byte(" "), 0644); err != nil {
		log.ErrorS(err, "EventReader")
	}
	if err := ioutil.WriteFile(setEventPath, []byte(" "), 0644); err != nil {
		log.ErrorS(err, "EventReader")
	}

	log.InfoS("Function Tracing Subsystem - Disabled", "EventReader")
	os.Exit(0)
}

// Init starts the eventReader and EventDecoder.
func (myftrace *Ftracer) Init() <-chan *event.Event {
	go myftrace.Halt()

	myftrace.initTracepoints()
	myftrace.initKProbes()

	return myftrace.EventDecoder(myftrace.EventReader())
}

// EventReader reads raw events from "trace_pipe" file, which
// are then forwarded to the decoder.
func (myftrace *Ftracer) EventReader() <-chan string {
	stop := logger.KillHandler()

	// unix.Fadvise(int(myftrace.kpipe.Fd()), 0, 0, unix.FADV_SEQUENTIAL)

	reader := bufio.NewReader(myftrace.kpipe)
	scanner := bufio.NewScanner(reader)
	eventChan := make(chan string, xlQueueSize)

	go func() {
		for {
			scanner.Scan()
			if err := scanner.Err(); err != nil {
				// From time to time a random EINTR arises.
				if strings.Contains(err.Error(), "interrupted system call") {
					// Scanner does not reset the error field.
					scanner = bufio.NewScanner(reader)
					continue
				}

				select {
				case <-stop: // If we receive a SIGINT or SIGTERM, die silently.
					return
				default:
					log.FatalS(err, "EventReader") // If it's an unexpected error, exit gracefully.
					return
				}
			}

			if line := scanner.Text(); line != "" {
				eventChan <- line
			} else {
				log.WarnS("Failed to read event.", "EventReader")
			}
		}
	}()

	return eventChan
}

// fixSyscallParams Fixes the kprobes params for newer kernel versions.
func fixSyscallParams(function, params string) string {
	if strings.Contains(function, "__x64_sys") == false {
		return params
	}

	// Since version 4.17, the way the kernel passes arguments to the syscalls
	// changed. From then on, a regs structure pointer
	// is passed instead of the regs itself.
	regs := strings.ReplaceAll(params, "%di", "+112(%di)")
	regs = strings.ReplaceAll(regs, "%si", "+104(%di)")
	regs = strings.ReplaceAll(regs, "%r10", "+56(%di)")

	return regs
}

// newCookie generates 2 random bytes in order to safely parse
// ftrace events. touch "\"arg2xx_str=\"hello\""
func newCookie() [2]byte {
	cookieDic := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	rand.Seed(time.Now().UTC().UnixNano())
	len := int64(len(cookieDic))

	return [2]byte{cookieDic[rand.Int63()%len],
		cookieDic[rand.Int63()%len]}
}
