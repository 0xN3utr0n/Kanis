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
	"os"
	"strings"

	"github.com/0xN3utr0n/Kanis/rulengine/task"
)

// Event contains a parsed event along with
// some metadata.
type Event struct {
	Comm     string
	PID      int
	Function string
	Args     interface{}
	RetValue []string
}

// Context contains an event context.
// Useful for the multi-threaded RuleEngine, since
// each worker will have it's own event context.
type Context struct {
	Current *task.Task
	List    *task.List
	PID     int
}

func SwitchContext(evt *Event, tasks *task.List) (*Context, bool) {
	current, src := task.Fetch(evt.PID, evt.Args.([]string)[0], tasks)
	return &Context{current, tasks, evt.PID}, src
}

// Filter Discards events that match against some basic rules.
func Filter(evt *Event, ctx *Context, proc bool) bool {
	var status bool

	if strings.Contains(evt.Function, "EXIT") == true {
		return false
	}

	// init process generates too much noise.
	if evt.PID == 1 {
		status = true

	} else if kanis, err := os.Readlink("/proc/self/exe"); err == nil &&
		ctx.Current.GetComm() == kanis {
		status = true

	} else if proc == true {
		// Tasks that already existed even before kanis started.
		if ctx.Current.GetPPid() == 2 {
			status = true
		} else if strings.Contains(evt.Function, "FORK") == true {
			status = true
		}
	}

	return status
}
