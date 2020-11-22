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

package threat

import (
	"strconv"

	"github.com/0xN3utr0n/Kanis/rulengine/elf"
	"github.com/0xN3utr0n/Kanis/rulengine/task"
	"golang.org/x/sys/unix"
)

const (
	// Danger levels
	benign   = iota
	low      = iota
	moderate = iota + 1
	high     = iota + 2
	extreme  = iota + 2
)

func (grp *Group) detectUnexpectedTracer(tracee *task.Tracee) {
	defer grp.wg.Done()

	if tracee.Last == unix.PTRACE_TRACEME {
		ppid := strconv.Itoa(grp.ctx.Current.GetPPid())
		logThreat("Traceme Protection", low, ppid, grp)
		grp.ctx.Current.UpdateScore(low)
		return
	}

	if tracee.Last == unix.PTRACE_POKETEXT && tracee.Pid == grp.ctx.PID {
		logThreat("Self-Tracing Protection", low, strconv.Itoa(grp.ctx.PID), grp)
		grp.ctx.Current.UpdateScore(low)
		return
	}
}

func (grp *Group) detectProcessInjection(tracee *task.Tracee) {
	defer grp.wg.Done()

	if tracee.Last != unix.PTRACE_POKETEXT {
		return
	}

	target := grp.ctx.List.Get(tracee.Pid)
	if target == nil || target.GetPPid() == grp.ctx.PID {
		return
	}

	logThreat("Process Injection", moderate, strconv.Itoa(tracee.Pid), grp)
	grp.ctx.Current.UpdateScore(moderate)
	target.UpdateScore(moderate)
}

func (grp *Group) detectTwoWayTracing() {
	defer grp.wg.Done()

	if grp.ctx.Current.GetTracer() == 0 {
		return
	}

	tracer := grp.ctx.List.Get(grp.ctx.Current.GetTracer())
	if tracer == nil || tracer.GetTracer() != grp.ctx.PID {
		return
	}

	pid := strconv.Itoa(grp.ctx.Current.GetTracer())
	logThreat("Two-Way-Tracing Protection", low, pid, grp)
	grp.ctx.Current.UpdateScore(low)
	tracer.UpdateScore(low)
}

func (grp *Group) detectSigTrapHandler(signal unix.Signal) {
	defer grp.wg.Done()

	// Careful, there're some legitimate uses for this signal.
	if signal != unix.SIGTRAP || grp.ctx.Current.GetScore() == benign {
		return
	}

	logThreat("SIGTRAP-Handler Protection", low, "", grp)
	grp.ctx.Current.UpdateScore(low)
}

func (grp *Group) detectBinaryPacking(bin *elf.Elf) {
	defer grp.wg.Done()

	if bin.StaticallyLinked() == false {
		return
	}

	if packed, _ := bin.PackedSegment(); packed == false {
		grp.ctx.Current.UpdateScore(low)
		bin.UpdateScore(elf.Dangerous)
		return
	}

	logThreat("Software Packing", moderate, bin.Rpath, grp)
	grp.ctx.Current.UpdateScore(moderate)
	bin.UpdateScore(elf.Dangerous)
}

func (grp *Group) detectBinaryParasite(bin *elf.Elf) {
	defer grp.wg.Done()

	if bin.DinamicallyLinked() == false {
		return
	}

	addrs := bin.GetInitArray()
	addrs = append(addrs, bin.Fd.Entry) // Analyze the Entrypoint too.

	for _, a := range addrs {
		if bin.DetectControlFlowHijacking(a) == true {
			logThreat("Execution Flow Hijacking", moderate, bin.Rpath, grp)
			grp.ctx.Current.UpdateScore(moderate)
			bin.UpdateScore(elf.Dangerous)
			return
		}
	}

	grp.ctx.Current.UpdateScore(low)
	bin.UpdateScore(elf.Dangerous)
}

func (grp *Group) detectMasquerading(bin *elf.Elf) {
	defer grp.wg.Done()

	file := elf.CleanPath(grp.ctx.Current.GetComm())

	// For instance: '[mymalware]'
	if file[0] == '[' && grp.ctx.Current.GetPPid() != 2 {
		logThreat("Kernel Thread Masquerading", low, bin.Rpath, grp)
		grp.ctx.Current.UpdateScore(low)
		bin.UpdateScore(elf.Dangerous)
		return
	}

	// For instance: 'mymalware.txt '
	ext, ok := elf.ValidExtension(file)
	if size := len(ext); ok == false && ext[size-1] == ' ' {
		logThreat("Space After Filename Masquerading", low, bin.Rpath, grp)
		grp.ctx.Current.UpdateScore(low)
		bin.UpdateScore(elf.Dangerous)
		return
	}
}

func (grp *Group) detectExecutableDeletion(path string) {
	defer grp.wg.Done()

	var ok bool
	current := grp.ctx.Current

	if path != current.GetComm() {
		for { // Search for any parent process who owns the executable
			ppid := current.GetPPid()
			current = grp.ctx.List.Get(ppid)
			if current == nil || ppid <= 2 {
				break
			}
			if path == current.GetComm() {
				ok = true
				break
			}
		}
	} else {
		ok = true
	}

	if ok == true {
		logThreat("Executable Deletion", low, path, grp)
		grp.ctx.Current.UpdateScore(low)
	}
}
