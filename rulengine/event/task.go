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
	"fmt"
	"strconv"

	"github.com/0xN3utr0n/Kanis/rulengine/database"
	"github.com/0xN3utr0n/Kanis/rulengine/elf"
	"github.com/0xN3utr0n/Kanis/rulengine/task"
	"golang.org/x/sys/unix"
)

const (
	newPidNS = -2 // New PID Namespace created by SyS_unshare
)

// ProcessFork Processes incoming FORK events for a given task.
func (ctx *Context) ProcessFork(evt *Event) error {
	lpid := ctx.Current.GetLastFork()

	fork := ctx.List.Get(lpid)
	if fork == nil {
		return nil
	}

	var err error
	defer func() {
		if err != nil {
			ctx.List.Delete(lpid)
		}
	}()

	// The new Child's PID (Virtual PID for those whithin a namespace)
	retPid, err := strconv.Atoi(evt.RetValue[0])
	if err != nil {
		return err
	} else if retPid < 0 {
		return fmt.Errorf("Failed %s: %d", evt.Function, retPid)
	}

	vpid := ctx.Current.GetVPid()
	ppid := ctx.Current.GetPPid()
	tracer := ctx.Current.GetTracer()
	flags := fork.GetFlags()

	if ((flags & unix.CLONE_NEWPID) != 0) || vpid == newPidNS {
		fork.SetVPid(1)
	} else if vpid != 0 || retPid != lpid {
		// By default child is in the same pid namespace as current
		fork.SetVPid(retPid)
	}
	if ((flags & unix.CLONE_PARENT) != 0) ||
		((flags & unix.CLONE_THREAD) != 0) {
		fork.SetPPid(ppid)
	}
	if ((flags & unix.CLONE_PTRACE) != 0) && tracer > 0 {
		fork.SetTracer(tracer)
	}

	fork.SetArgv(ctx.Current.GetArgv())
	fork.SetCwd(ctx.Current.GetCwd())
	fork.SetFlags(flags)
	fork.SetCreds(ctx.Current.GetCreds())

	logFork(fork, ctx)

	return nil
}

// ProcessNewTask Processes incoming task_newtask events for a given task.
// Runs before ProcessFork(), and creates the basic structures for the new child task.
func (ctx *Context) ProcessNewTask(evt *Event) error {
	args := evt.Args.([]string)
	if len(args) < 3 {
		return errors.New("Invalid arguments - " + evt.Function)
	}

	// Real PID of the new child (even for those within other namespaces).
	fork, err := strconv.Atoi(args[0])
	if err != nil {
		return err
	}

	// CLONE_ flags
	flags, err := strconv.ParseUint(args[len(args)-2], 16, 64)
	if err != nil {
		return err
	}

	child := new(task.Task)
	child.SetComm(ctx.Current.GetComm())
	child.SetPPid(ctx.PID)
	child.SetFlags(flags)
	child.UpdateScore(ctx.Current.GetScore())

	ctx.List.Insert(fork, child)
	ctx.Current.SetLastFork(fork)

	return nil
}

// ProcessExit Processes incoming EXIT events for a given task.
// It also deletes all related structures.
func (ctx *Context) ProcessExit(evt *Event) error {
	if ctx.Current.IsThread() == false {
		if ctx.Current.IsDead(ctx.PID) == false {
			return nil
		}
	}

	if err := database.DeleteAllFileDescriptors(ctx.PID); err != nil {
		return err
	}

	ctx.List.Delete(ctx.PID)

	logExit(evt.Args.([]string)[0], ctx)

	return nil
}

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

	file, err := elf.GetAbsFilePath(ctx.Current.GetCwd(), argv[0])
	if err != nil {
		if a, ok := task.FetchExecutable(nil, ctx.PID, evt.Args.([]string)[0]); ok == true {
			file = a[0]
		}
	}

	argv[0] = file

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

	// In most cases it will be the real caller.
	if oldPid == ctx.PID {
		return false, nil
	}

	var argv []string

	// Delete the caller task.
	t := &Context{ctx.List.Get(oldPid), ctx.List, oldPid}
	t.ProcessExit(&Event{Args: interface{}([]string{"0"})})

	if a, ok := task.FetchExecutable(nil, ctx.PID, evt.Args.([]string)[0]); ok == true {
		argv = a
	} else {
		argv[0] = args[0]
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

// ProcessUnshare Processes incoming UNSHARE events for a given task.
// Used to detect the creation of new PID Namespaces.
func (ctx *Context) ProcessUnshare(evt *Event) error {
	r, err := strconv.Atoi(evt.RetValue[0])
	if err != nil {
		return err
	} else if r != 0 {
		ctx.Debug(evt.Function, "Failed function call")
		return nil
	}

	args := evt.Args.([]string)
	flags, err := strconv.Atoi(args[0])
	if err != nil {
		return err
	}

	if (flags & unix.CLONE_NEWPID) != 0 {
		ctx.Current.SetVPid(newPidNS)
	}

	return nil
}

// ProcessSigaction Processes incoming SIGACTION events for a given task.
func (ctx *Context) ProcessSigaction(evt *Event) (unix.Signal, error) {
	r, err := strconv.Atoi(evt.RetValue[0])
	if err != nil {
		return 0, err
	} else if r < 0 {
		ctx.Debug(evt.Function, "Failed function call")
		return 0, nil
	}

	args := evt.Args.([]string)
	if len(args) != 2 {
		return 0, nil
	}

	signal, err := strconv.Atoi(args[0])
	if err != nil {
		return 0, err
	}

	// Discard if it's SIG_DFL or SIG_IGN
	if len(args[1]) == 1 {
		return 0, nil
	}

	// Interesting signals are between 0 and 16
	if signal >= task.MaxSignals || ctx.Current.GetSignal(signal) {
		return 0, nil
	}

	ctx.Current.SetSignal(signal)
	s := unix.Signal(signal)

	logSigaction(s.String(), ctx)

	return s, nil
}

// ProcessCommitCreds Processes incoming COMMIT_CREDS events for a given task.
// Used to retrieve the task's uid, gid, eid and egid.
func (ctx *Context) ProcessCommitCreds(evt *Event) error {
	r, err := strconv.Atoi(evt.RetValue[0])
	if err != nil {
		return err
	} else if r < 0 {
		ctx.Debug(evt.Function, "Failed function call")
		return nil
	}

	args := evt.Args.([]string)
	if len(args) != 4 {
		return nil
	}

	var creds [4]string
	copy(creds[:], args)
	ctx.Current.SetCreds(creds)

	return nil
}
