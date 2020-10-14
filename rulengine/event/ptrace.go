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

package event

import (
	"strconv"

	"github.com/0xN3utr0n/Kanis/rulengine/task"
	"golang.org/x/sys/unix"
)

// ProcessPtrace Processes incoming PTRACE events for a given task.
func (ctx *Context) ProcessPtrace(evt *Event) (*task.Tracee, error) {
	r, err := strconv.Atoi(evt.RetValue[0])
	if err != nil {
		return nil, err
	} else if r < 0 {
		ctx.Debug(evt.Function, "Failed function call")
		return nil, nil
	}

	args := evt.Args.([]string)
	if len(args) != 2 {
		return nil, nil
	}

	flags, err := strconv.Atoi(args[0])
	if err != nil {
		return nil, err
	}

	// tracee PID
	tpid, err := strconv.Atoi(args[1])
	if err != nil {
		return nil, err
	} else if flags == unix.PTRACE_TRACEME {
		tpid = ctx.PID
	}

	target := ctx.List.Get(tpid)
	if target == nil {
		return nil, nil
	}

	var action string
	tracee := ctx.Current.GetTracee(tpid)

	switch flags {
	case unix.PTRACE_TRACEME:
		ctx.Current.SetTracer(ctx.Current.GetPPid())
		action = "TRACEME"

	case unix.PTRACE_ATTACH, unix.PTRACE_SEIZE:
		tracee.Last = unix.PTRACE_ATTACH
		tracee.Pid = tpid
		target.SetTracer(ctx.PID)
		action = "ATTACH"

	case unix.PTRACE_DETACH:
		target.SetTracer(0)
		action = "DETACH"

	case unix.PTRACE_POKETEXT, unix.PTRACE_POKEDATA:
		tracee.Last = unix.PTRACE_POKETEXT
		action = "WRITE-DATA"
		// Avoid duplicated events
		if (tracee.Operations & tracee.Last) != 0 {
			return nil, nil
		}

	default:
		return nil, nil
	}

	tracee.Operations |= tracee.Last
	ctx.Current.SetTracee(tpid, tracee)

	logPtrace(tpid, action, ctx)

	return &tracee, nil
}

// ProcessPvmWritev Processes incoming PROC_VM_WRITERV events for a given task.
func (ctx *Context) ProcessPvmWritev(evt *Event) (*task.Tracee, error) {
	r, err := strconv.Atoi(evt.RetValue[0])
	if err != nil {
		return nil, err
	} else if r < 0 {
		ctx.Debug(evt.Function, "Failed function call")
		return nil, nil
	}

	args := evt.Args.([]string)

	tpid, err := strconv.Atoi(args[0])
	if err != nil {
		return nil, err
	}

	tracee := ctx.Current.GetTracee(tpid)

	tracee.Operations |= unix.PTRACE_POKETEXT
	tracee.Last = unix.PTRACE_POKETEXT
	tracee.Pid = tpid

	ctx.Current.SetTracee(tpid, tracee)

	logPtrace(tpid, "WRITE-DATA", ctx)

	return &tracee, nil
}
