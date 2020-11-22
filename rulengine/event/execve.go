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
	"errors"
	"strconv"

	"github.com/0xN3utr0n/Kanis/rulengine/elf"
	"github.com/0xN3utr0n/Kanis/rulengine/task"
)

// ProcessExecve Processes incoming EXECVE events for a given task.
// Used to retrieve the task's executable and commandline arguments.
func (ctx *Context) ProcessExecve(evt *Event) (bool, error) {
	r, err := strconv.Atoi(evt.RetValue[0])
	if err != nil {
		return false, err
	} else if r != 0 {
		ctx.Debug(evt.Function, "Failed function call")
		return false, nil
	}

	// arg[0] = Contains the executable's path.
	// arg[n] = Additional arguments.
	argv := evt.Args.([]string)

	if argv[0] == "/proc/self/exe" {
		argv[0] = ctx.Current.GetComm()
	} else {
		argv[0] = processExecveArgv(argv[0], evt.Comm, ctx)[0]
	}

	logExecve(ctx, argv)

	ctx.Current.SetComm(argv[0])
	ctx.Current.SetArgv(argv)

	e, err := elf.New(argv[0])
	if err != nil || e == nil {
		return false, err
	}

	ctx.Current.SetElf(e)

	return true, nil
}

// ProcessSchedExecve Processes incoming sched_process_exec events for a given task.
// It's a backup event for cases where the corresponding EXECVE event is missed.
// Used to retrieve the task's executable and commandline arguments.
func (ctx *Context) ProcessSchedExecve(evt *Event) (bool, error) {

	// args[0] = Contains the executable's path.
	// args[1] = PID of the task who will be assigned to the new executable. (current)
	// args[2] = PID of the task who made the sys_execve() call. (Already dead)
	args := evt.Args.([]string)
	if len(args) != 3 {
		return false, errors.New("Invalid arguments - " + evt.Function)
	}

	oldPid, err := strconv.Atoi(args[2])
	if err != nil || oldPid <= 1 {
		return false, err
	}

	// This is the usual behavior: Current task is sys_execve() caller.
	if oldPid == ctx.PID {
		return false, nil
	}

	var argv []string

	// Delete the caller task.
	t := &Context{ctx.List.Get(oldPid), ctx.List, oldPid}
	t.ProcessExit(&Event{Args: interface{}([]string{"0"})})

	argv = processExecveArgv(argv[0], evt.Comm, ctx)

	logExecve(ctx, argv)

	ctx.Current.SetComm(argv[0])
	ctx.Current.SetArgv(argv)

	e, err := elf.New(argv[0])
	if err != nil || e == nil {
		return false, err
	}

	ctx.Current.SetElf(e)

	return true, nil
}

// processExecveArgv Tries different methods in order to obtain the task's command-line arguments.
func processExecveArgv(comm, name string, ctx *Context) []string {
	argv := []string{""}
	proc := true

	// Don't bother reading '/proc/' if 'comm' has a valid executable path.
	if comm != "" {
		comm, _ = absFilePath(ctx.Current, comm)
		if comm != "" {
			proc = false
		}
	}

	if proc == true {
		if a, ok := task.FetchExecutable(nil, ctx.PID, name); ok == true {
			argv = a
			comm = a[0]
		} else {
			comm = name // As a last resort use the process' name. (Appears in every ftrace event)
		}

		comm, _ = absFilePath(ctx.Current, comm)
		if comm == "" {
			comm = name
		}
	}

	argv[0] = comm

	return argv
}
