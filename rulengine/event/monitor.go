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
	"github.com/0xN3utr0n/Kanis/logger"
	"github.com/0xN3utr0n/Kanis/rulengine/task"
	"github.com/rs/zerolog"
)

var (
	monitor  *logger.Logger
	rulesptr Rules
)

const (
	eventFile = "/var/kanis/events.log"
)

func EnableMonitoring(showEvents string, console bool, rules Rules) error {
	if showEvents == "" {
		return nil
	}

	var err error
	monitor, err = logger.New(eventFile, console)
	if err != nil {
		return err
	}

	if err = checkRuleMonitoring(rules, showEvents); err != nil {
		return err
	}

	rulesptr = rules

	return nil
}

func logFork(child *task.Task, ctx *Context) {
	if monitor == nil || rulesptr["FORK"].log == false {
		return
	}

	var typeTask string

	if child.IsThread() == true {
		typeTask = "Thread"
	} else {
		typeTask = "Process"
	}

	log := monitor.Info("RuleEngine").Dict("Child", zerolog.Dict().
		Int("Pid", ctx.Current.GetLastFork()).
		Int("VPid", child.GetVPid()).
		Str("Task", typeTask)).Str("Type", "Event")

	Send("FORK", ctx.PID, "", ctx.Current, log)
}

func logExit(arg string, ctx *Context) {
	if monitor != nil && rulesptr["EXIT"].log == true {
		log := monitor.Info("RuleEngine").
			Str("Value", arg).
			Str("Type", "Event")

		Send("EXIT", ctx.PID, "", ctx.Current, log)
	}
}

func logExecve(ctx *Context, newArgv []string) {
	if monitor != nil && rulesptr["EXECVE"].log == true {
		cp := []string{basePath(ctx.Current, newArgv[0])}
		log := monitor.Info("RuleEngine").
			Strs("Argv", append(cp, newArgv[1:]...)).
			Str("Type", "Event")

		Send("EXECVE", ctx.PID, "", ctx.Current, log)
	}
}

func logPtrace(tracee int, action string, ctx *Context) {
	if monitor != nil && rulesptr["PTRACE"].log == true {
		log := monitor.Info("RuleEngine").
			Int("Tracee", tracee).
			Str("Type", "Event")

		Send("PTRACE."+action, ctx.PID, "", ctx.Current, log)
	}
}

func logSigaction(signal string, ctx *Context) {
	if monitor != nil && rulesptr["SIGACTION"].log == true {
		log := monitor.Info("RuleEngine").
			Str("Signal", signal).
			Str("Type", "Event")

		Send("SIGACTION", ctx.PID, "", ctx.Current, log)
	}
}

func logOpen(path string, ctx *Context) {
	if monitor != nil && rulesptr["OPEN"].log == true {
		log := monitor.Info("RuleEngine").
			Str("File", basePath(ctx.Current, path)).
			Str("Type", "Event")

		Send("OPEN", ctx.PID, "", ctx.Current, log)
	}
}

func logClose(path string, ctx *Context) {
	if monitor != nil && rulesptr["CLOSE"].log == true {
		log := monitor.Info("RuleEngine").
			Str("File", basePath(ctx.Current, path)).
			Str("Type", "Event")

		Send("CLOSE", ctx.PID, "", ctx.Current, log)
	}
}

func logUnlink(path string, ctx *Context) {
	if monitor != nil && rulesptr["UNLINK"].log == true {
		log := monitor.Info("RuleEngine").
			Str("File", basePath(ctx.Current, path)).
			Str("Type", "Event")

		Send("UNLINK", ctx.PID, "", ctx.Current, log)
	}
}

func logRename(src, dst string, ctx *Context) {
	if monitor != nil && rulesptr["RENAME"].log == true {
		log := monitor.Info("RuleEngine").
			Str("Old", basePath(ctx.Current, src)).
			Str("New", basePath(ctx.Current, dst)).
			Str("Type", "Event")

		Send("RENAME", ctx.PID, "", ctx.Current, log)
	}
}

func logMount(path string, msg string, ctx *Context) {
	if monitor != nil && rulesptr["MOUNT"].log == true {
		log := monitor.Info("RuleEngine").Dict("Mount", zerolog.Dict().
			Str("Path", path).Str("Type", msg)).Str("Type", "Event")

		Send("MOUNT", ctx.PID, "", ctx.Current, log)
	}
}

func (ctx *Context) Warn(function string, msg string) {
	if monitor != nil && rulesptr[function].log == true {
		Send(function, ctx.PID, msg, ctx.Current, monitor.Warn("RuleEngine"))
	}
}

func (ctx *Context) Debug(function string, msg string) {
	if monitor != nil && rulesptr[function].log == true {
		Send(function, ctx.PID, msg, ctx.Current, monitor.Debug("RuleEngine"))
	}
}

func (ctx *Context) Error(function string, err error) {
	if monitor != nil && rulesptr[function].log == true {
		Send(function, ctx.PID, "", ctx.Current, monitor.Error(err, "RuleEngine"))
	}
}

func Send(event string, pid int, msg string, current *task.Task, log *zerolog.Event) {
	var (
		typeTask string
		name     string
	)

	if current.IsThread() == true {
		typeTask = "Thread"
	} else {
		typeTask = "Process"
	}

	if len(event) > 0 {
		log.Str("Event", event)
	}

	if current.IsInContainer() == true {
		name, _ = current.NamespaceData(task.UtsNs)
		if len(name) == 0 {
			name = "Unknown"
		}
	} else if len(name) == 0 {
		name = "None"
	}

	creds := current.GetCreds()

	log.Dict("Current", zerolog.Dict().
		Str("Comm", basePath(current, current.GetComm())).
		Int("Pid", pid).
		Int("VPid", current.GetVPid()).
		Str("Task", typeTask).
		Str("Container", name).
		Dict("UIDS", zerolog.Dict().
			Str("uid", creds[0]).
			Str("gid", creds[1]).
			Str("euid", creds[2]).
			Str("egid", creds[3])).
		Int("Danger", current.GetScore())).Msg(msg)
}
