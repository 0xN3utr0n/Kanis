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
	"github.com/0xN3utr0n/Kanis/scanner"
)

const (
	baseNumTasks = 500 // Base number of tasks
)

var (
	log *logger.Logger
)

// Run launches the Rule Engine.
func Run(RuleIn <-chan *event.Event, main *logger.Logger, showEvents string, stdout bool) {
	log = main

	rules := selectRules("ftrace")

	if err := event.EnableMonitoring(showEvents, stdout, rules); err != nil {
		log.FatalS(err, "RuleEngine")
	}

	if err := threat.EnableMonitoring(stdout); err != nil {
		log.FatalS(err, "RuleEngine")
	}

	if err := database.CreateFileDescriptorTable(); err != nil {
		log.FatalS(err, "RuleEngine")
	}

	if err := database.CreateNameSpacesTable(); err != nil {
		log.FatalS(err, "RuleEngine")
	}

	if err := scanner.StartYara(); err != nil {
		log.FatalS(err, "RuleEngine")
	}

	tasks := task.NewList(baseNumTasks)

	// TODO: add a worker pool
	worker(RuleIn, tasks, rules)
}

func worker(RuleIn <-chan *event.Event, tasks *task.List, rules event.Rules) {
	for {
		evt := <-RuleIn

		ctx, src := event.SwitchContext(evt, tasks)
		if ctx.Current == nil {
			continue
		}

		if event.Filter(evt, ctx, src) == true {
			continue
		}

		if rules[evt.Function] == nil {
			ctx.Error(evt.Function,
				errors.New("Received unexpected function event"))
			continue
		}

		ioc, err := rules[evt.Function].ProcessEvent(ctx, evt)
		if err != nil {
			ctx.Error(evt.Function, err)
		} else if rules[evt.Function].RequiresYara {
			threat.YaraAnalysis(ctx)
		}

		// If there is a valid indicator of compromise, analyse it.
		if ioc != nil {
			rules[evt.Function].ThreatAnalysis(ioc, ctx)
		}
	}
}

// select let's you choose which kind of rules
// the ruleEngine must use. (ftrace or eBPF)
func selectRules(engine string) event.Rules {
	// The current engine only supports ftrace events.
	// eBPF support is in the roadmap.
	if engine == "ftrace" {
		return ftraceRules
	}

	return nil
}
