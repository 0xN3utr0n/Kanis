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

package ftrace

import "os"

// Currently only Basic tracepoints are supported.
// TODO: Enhance the library an add support for filters.

type tracepoint struct {
	name     string
	optional bool
}

var tracepoints = []tracepoint{
	tracepoint{
		"task:task_newtask",
		false,
	},
	tracepoint{
		"sched:sched_process_exec",
		false,
	},
}

func (kfunc *tracepoint) enable(eventfd *os.File) error {
	if _, err := eventfd.WriteString(kfunc.name); err != nil {
		return err
	}

	return nil
}

func (myftrace *Ftracer) initTracepoints() {
	eventfd, err := os.OpenFile(setEventPath, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.FatalS(err, "EventReader")
	}

	defer eventfd.Close()

	for i := 0; i < len(tracepoints); i++ {
		if err := tracepoints[i].enable(eventfd); err != nil {
			if tracepoints[i].optional == true {
				log.ErrorS(err, "EventReader")
				continue
			}
			log.FatalS(err, "EventReader")
		}

		log.DebugS("Ftrace: Added - "+tracepoints[i].name, "EventReader")
	}
}
