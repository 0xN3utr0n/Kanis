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

package rulengine

import (
	"errors"

	"github.com/0xN3utr0n/Kanis/logger"
	"github.com/0xN3utr0n/Kanis/rulengine/database"
	"github.com/0xN3utr0n/Kanis/rulengine/event"
	"github.com/0xN3utr0n/Kanis/rulengine/task"
	"github.com/0xN3utr0n/Kanis/rulengine/threat"
)

const (
	baseNumTasks = 500 // Base number of tasks
)

var (
	log *logger.Logger
)

func Run(RuleIn <-chan *event.Event, main *logger.Logger, showEvents bool, stdout bool) {
	log = main

	if err := event.EnableMonitoring(showEvents, stdout); err != nil {
		log.FatalS(err, "RuleEngine")
	}

	if err := threat.EnableMonitoring(stdout); err != nil {
		log.FatalS(err, "RuleEngine")
	}

	if err := database.CreateFileDescriptorTable(); err != nil {
		log.FatalS(err, "RuleEngine")
	}

	tasks := task.NewList(baseNumTasks)

	// TODO: add a worker pool
	worker(RuleIn, tasks)
}

func worker(RuleIn <-chan *event.Event, tasks *task.List) {

	for {
		evt := <-RuleIn

		ctx, src := event.SwitchContext(evt, tasks)
		if ctx.Current == nil {
			continue
		}

		if event.Filter(evt, ctx, src) == true {
			continue
		}

		switch evt.Function {
		case "EXECVE":
			if analyse, err := ctx.ProcessExecve(evt); err != nil {
				ctx.Error(evt.Function, err)
			} else if analyse == true {
				threat.ExecveAnalysis(ctx)
			}

		case "sched_process_exec":
			if analyse, err := ctx.ProcessSchedExecve(evt); err != nil {
				ctx.Error(evt.Function, err)
			} else if analyse == true {
				threat.ExecveAnalysis(ctx)
			}

		case "FORK":
			if err := ctx.ProcessFork(evt); err != nil {
				ctx.Error(evt.Function, err)
			}

		case "task_newtask":
			if err := ctx.ProcessNewTask(evt); err != nil {
				ctx.Error(evt.Function, err)
			}

		case "EXIT":
			if err := ctx.ProcessExit(evt); err != nil {
				ctx.Error(evt.Function, err)
			}

		case "UNSHARE":
			if err := ctx.ProcessUnshare(evt); err != nil {
				ctx.Error(evt.Function, err)
			}

		case "COMMIT_CREDS":
			if err := ctx.ProcessCommitCreds(evt); err != nil {
				ctx.Error(evt.Function, err)
			}

		case "PTRACE":
			if tracee, err := ctx.ProcessPtrace(evt); err != nil {
				ctx.Error(evt.Function, err)
			} else if tracee != nil {
				threat.PtraceAnalysis(tracee, ctx)
			}

		case "PROC_VM_WRITERV":
			if tracee, err := ctx.ProcessPvmWritev(evt); err != nil {
				ctx.Error(evt.Function, err)
			} else if tracee != nil {
				threat.PtraceAnalysis(tracee, ctx)
			}

		case "SIGACTION":
			if signal, err := ctx.ProcessSigaction(evt); err != nil {
				ctx.Error(evt.Function, err)
			} else if signal > 0 {
				threat.SignalAnalysis(signal, ctx)
			}

		case "CHDIR":
			if err := ctx.ProcessChdir(evt); err != nil {
				ctx.Error(evt.Function, err)
			}

		case "OPEN":
			if err := ctx.ProcessOpen(evt); err != nil {
				ctx.Error(evt.Function, err)
			}

		case "CLOSE":
			if bin, err := ctx.ProcessClose(evt); err != nil {
				ctx.Error(evt.Function, err)
			} else if bin != nil {
				threat.BinaryAnalysis(bin, ctx)
			}

		case "UNLINK":
			if path, err := ctx.ProcessUnlink(evt); err != nil {
				ctx.Error(evt.Function, err)
			} else if path != "" {
				threat.UnlinkAnalysis(path, ctx)
			}

		case "RENAME":
			if bin, err := ctx.ProcessRename(evt); err != nil {
				ctx.Error(evt.Function, err)
			} else if bin != nil {
				threat.BinaryAnalysis(bin, ctx)
			}

		default:
			ctx.Error(evt.Function,
				errors.New("Received unexpected function event"))
		}
	}
}
