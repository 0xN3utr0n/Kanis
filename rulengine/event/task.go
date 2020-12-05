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
	"github.com/0xN3utr0n/Kanis/rulengine/task"
	"golang.org/x/sys/unix"
)

const (
	newPidNS = -2 // New PID Namespace created by SyS_unshare
)

// ProcessFork Processes incoming FORK events for a given task.
func (ctx *Context) ProcessFork(evt *Event) (interface{}, error) {
	lpid := ctx.Current.GetLastFork()

	fork := ctx.List.Get(lpid)
	if fork == nil {
		return nil, nil
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
		return nil, err
	} else if retPid < 0 {
		return nil, fmt.Errorf("Failed %s: %d", evt.Function, retPid)
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

	logFork(fork, ctx)

	return nil, nil
}

// ProcessNewTask Processes incoming task_newtask events for a given task.
// Runs before ProcessFork(), and creates the basic structures for the new child task.
func (ctx *Context) ProcessNewTask(evt *Event) (interface{}, error) {
	args := evt.Args.([]string)
	if len(args) < 3 {
		return nil, errors.New("Invalid arguments - " + evt.Function)
	}

	// Real PID of the new child (even for those within other namespaces).
	fork, err := strconv.Atoi(args[0])
	if err != nil {
		return nil, err
	}

	// CLONE_ flags
	flags, err := strconv.ParseUint(args[len(args)-2], 16, 64)
	if err != nil {
		return nil, err
	}

	child := new(task.Task)
	child.SetPPid(ctx.PID)
	child.SetComm(ctx.Current.GetComm())
	child.SetArgv(ctx.Current.GetArgv())
	child.SetCwd(ctx.Current.GetCwd())
	child.SetCreds(ctx.Current.GetCreds())
	child.SetFlags(flags)
	child.SetNamespaces(ctx.Current.GetNamespaces())
	child.SwitchNamespace(flags)
	child.UpdateScore(ctx.Current.GetScore())

	ctx.List.Insert(fork, child)
	ctx.Current.SetLastFork(fork)

	return nil, nil
}

// ProcessExit Processes incoming EXIT events for a given task.
// It also deletes all related structures.
func (ctx *Context) ProcessExit(evt *Event) (interface{}, error) {
	if ctx.Current.IsThread() == false {
		if ctx.Current.IsDead(ctx.PID) == false {
			return nil, nil
		}
	}

	if err := database.DeleteAllFileDescriptors(ctx.PID); err != nil {
		return nil, err
	}

	ctx.List.Delete(ctx.PID)

	logExit(evt.Args.([]string)[0], ctx)

	return nil, nil
}

// ProcessSigaction Processes incoming SIGACTION events for a given task.
func (ctx *Context) ProcessSigaction(evt *Event) (interface{}, error) {
	var s unix.Signal

	r, err := strconv.Atoi(evt.RetValue[0])
	if err != nil {
		return s, err
	} else if r < 0 {
		ctx.Debug(evt.Function, "Failed function call")
		return s, nil
	}

	args := evt.Args.([]string)
	if len(args) != 2 {
		return s, nil
	}

	signal, err := strconv.Atoi(args[0])
	if err != nil {
		return s, err
	}

	// Discard if it's SIG_DFL or SIG_IGN
	if len(args[1]) == 1 {
		return s, nil
	}

	// Interesting signals are between 0 and 16
	if signal >= task.MaxSignals || ctx.Current.GetSignal(signal) {
		return s, nil
	}

	ctx.Current.SetSignal(signal)
	s = unix.Signal(signal)

	logSigaction(s.String(), ctx)

	return s, nil
}

// ProcessCommitCreds Processes incoming COMMIT_CREDS events for a given task.
// Used to retrieve the task's uid, gid, eid and egid.
func (ctx *Context) ProcessCommitCreds(evt *Event) (interface{}, error) {
	r, err := strconv.Atoi(evt.RetValue[0])
	if err != nil {
		return nil, err
	} else if r < 0 {
		ctx.Debug(evt.Function, "Failed function call")
		return nil, nil
	}

	args := evt.Args.([]string)
	if len(args) != 4 {
		return nil, nil
	}

	var creds [4]string
	copy(creds[:], args)
	ctx.Current.SetCreds(creds)

	return nil, nil
}
