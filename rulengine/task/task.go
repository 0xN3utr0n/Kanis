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

package task

import (
	"sync"

	"github.com/0xN3utr0n/Kanis/rulengine/elf"
	"golang.org/x/sys/unix"
)

// Task stores basic information about a specific system task/process.
// For safe concurrent access, use the Setters and Getters.
type Task struct {
	vpid     int
	comm     string
	argv     []string
	ppid     int // TODO: insert into db
	cwd      string
	bin      *elf.Elf
	flags    uint64
	signals  []bool
	tracer   int
	tracees  TraceeList
	score    int // danger score
	lastFork int // TODO: insert into db
	mutex    sync.RWMutex
}

type Tracee struct {
	Pid        int
	Operations int
	Last       int // Most recent ptrace operation done.
}

type TraceeList map[int]Tracee

// MaxSignals Maximun number of monitored signals per task.
const MaxSignals = 17

// Fetch Returns the event's corresponding task object.
func Fetch(pid int, name string, tasks *List) (*Task, bool) {
	var proc bool

	if ok := tasks.Get(pid); ok == nil {
		// Fallback into /proc/
		t, err := createTask(name, pid)
		if err != nil || t == nil {
			return nil, false
		}

		proc = true
		tasks.Insert(pid, t)
	}

	return tasks.Get(pid), proc
}

func (current *Task) SetVPid(vpid int) {
	current.mutex.Lock()
	current.vpid = vpid
	current.mutex.Unlock()
}

func (current *Task) SetComm(comm string) {
	current.mutex.Lock()
	current.comm = comm
	current.mutex.Unlock()
}

func (current *Task) SetArgv(argv []string) {
	current.mutex.Lock()
	current.argv = argv
	current.mutex.Unlock()
}

func (current *Task) SetCwd(cwd string) {
	current.mutex.Lock()
	current.cwd = cwd
	current.mutex.Unlock()
}

func (current *Task) SetPPid(ppid int) {
	current.mutex.Lock()
	current.ppid = ppid
	current.mutex.Unlock()
}

func (current *Task) SetFlags(flags uint64) {
	current.mutex.Lock()
	current.flags = flags
	current.mutex.Unlock()
}

func (current *Task) SetSignal(signal int) {
	current.mutex.Lock()
	if len(current.signals) == 0 {
		current.signals = make([]bool, MaxSignals)
	}
	current.signals[signal] = true
	current.mutex.Unlock()
}

func (current *Task) SetElf(bin *elf.Elf) {
	current.mutex.Lock()
	current.bin = bin
	current.mutex.Unlock()
}

func (current *Task) SetTracer(tracer int) {
	current.mutex.Lock()
	current.tracer = tracer
	current.mutex.Unlock()
}

func (current *Task) SetTracee(tpid int, tracee Tracee) {
	current.mutex.Lock()
	if tracee.Last == unix.PTRACE_DETACH {
		delete(current.tracees, tracee.Pid)
	} else {
		if current.tracees == nil {
			current.tracees = make(TraceeList)
		}
		current.tracees[tpid] = tracee
	}
	current.mutex.Unlock()
}

func (current *Task) SetLastFork(fork int) {
	current.mutex.Lock()
	current.lastFork = fork
	current.mutex.Unlock()
}

func (current *Task) GetVPid() int {
	current.mutex.RLock()
	vpid := current.vpid
	current.mutex.RUnlock()

	return vpid
}

func (current *Task) GetComm() string {
	current.mutex.RLock()
	comm := current.comm
	current.mutex.RUnlock()

	return comm
}

func (current *Task) GetArgv() []string {
	current.mutex.RLock()
	argv := current.argv
	current.mutex.RUnlock()

	return argv
}

func (current *Task) GetCwd() string {
	current.mutex.RLock()
	cwd := current.cwd
	current.mutex.RUnlock()

	return cwd
}

func (current *Task) GetPPid() int {
	current.mutex.RLock()
	ppid := current.ppid
	current.mutex.RUnlock()

	return ppid
}

func (current *Task) GetFlags() uint64 {
	current.mutex.RLock()
	flags := current.flags
	current.mutex.RUnlock()

	return flags
}

func (current *Task) GetSignal(signal int) bool {
	var status bool
	current.mutex.RLock()
	if len(current.signals) > 0 {
		status = current.signals[signal]
	}
	current.mutex.RUnlock()

	return status
}

func (current *Task) GetElf() *elf.Elf {
	current.mutex.RLock()
	bin := current.bin
	current.mutex.RUnlock()

	return bin
}

func (current *Task) GetTracer() int {
	current.mutex.RLock()
	tracer := current.tracer
	current.mutex.RUnlock()

	return tracer
}

func (current *Task) GetTracee(tpid int) Tracee {
	current.mutex.RLock()
	tracee := current.tracees[tpid]
	current.mutex.RUnlock()

	return tracee
}

func (current *Task) GetLastFork() int {
	current.mutex.RLock()
	fork := current.lastFork
	current.mutex.RUnlock()

	return fork
}

func (current *Task) GetScore() int {
	current.mutex.RLock()
	score := current.score
	current.mutex.RUnlock()

	return score
}

func (current *Task) IsThread() bool {
	var status bool

	if (current.GetFlags() & unix.CLONE_VM) != 0 {
		status = true
	}

	return status
}

func (current *Task) UpdateScore(score int) {
	current.mutex.Lock()
	if current.score < score {
		current.score = score
	} else if score > 0 {
		current.score++
	}
	current.mutex.Unlock()
}
