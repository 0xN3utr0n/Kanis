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
	"github.com/0xN3utr0n/Kanis/rulengine/event"
	"github.com/0xN3utr0n/Kanis/rulengine/threat"
)

// Custom rules designed exclusively for ftrace events.
var ftraceRules = event.Rules{
	"EXECVE": {
		Category:       event.Exec,
		RequiresYara:   true,
		ProcessEvent:   (*event.Context).ProcessExecve,
		ThreatAnalysis: threat.ExecveAnalysis,
	},
	"sched_process_exec": {
		Category:       event.Exec,
		RequiresYara:   true,
		ProcessEvent:   (*event.Context).ProcessSchedExecve,
		ThreatAnalysis: threat.ExecveAnalysis,
	},
	"FORK": {
		Category:     event.Task,
		ProcessEvent: (*event.Context).ProcessFork,
	},
	"task_newtask": {
		Category:     event.Task,
		ProcessEvent: (*event.Context).ProcessNewTask,
	},
	"EXIT": {
		Category:     event.Task,
		ProcessEvent: (*event.Context).ProcessExit,
	},
	"UNSHARE": {
		Category:     event.Ns,
		ProcessEvent: (*event.Context).ProcessUnshare,
	},
	"MOUNT": {
		Category:     event.Mount,
		ProcessEvent: (*event.Context).ProcessMount,
	},
	"COMMIT_CREDS": {
		Category:     event.Task,
		ProcessEvent: (*event.Context).ProcessCommitCreds,
	},
	"SETHOSTNAME": {
		Category:     event.Ns,
		ProcessEvent: (*event.Context).ProcessSetHostname,
	},
	"SETNS": {
		Category:     event.Ns,
		ProcessEvent: (*event.Context).ProcessSetNs,
	},
	"PTRACE": {
		Category:       event.Ptrace,
		ProcessEvent:   (*event.Context).ProcessPtrace,
		ThreatAnalysis: threat.PtraceAnalysis,
	},
	"PROC_VM_WRITERV": {
		Category:       event.Ptrace,
		ProcessEvent:   (*event.Context).ProcessPtrace,
		ThreatAnalysis: threat.PtraceAnalysis,
	},
	"SIGACTION": {
		Category:       event.Signal,
		ProcessEvent:   (*event.Context).ProcessSigaction,
		ThreatAnalysis: threat.SignalAnalysis,
	},
	"CHDIR": {
		Category:     event.File,
		ProcessEvent: (*event.Context).ProcessChdir,
	},
	"OPEN": {
		Category:     event.File,
		ProcessEvent: (*event.Context).ProcessOpen,
	},
	"CLOSE": {
		Category:       event.File,
		ProcessEvent:   (*event.Context).ProcessClose,
		ThreatAnalysis: threat.BinaryAnalysis,
	},
	"UNLINK": {
		Category:       event.File,
		ProcessEvent:   (*event.Context).ProcessUnlink,
		ThreatAnalysis: threat.UnlinkAnalysis,
	},
	"RENAME": {
		Category:       event.File,
		ProcessEvent:   (*event.Context).ProcessRename,
		ThreatAnalysis: threat.BinaryAnalysis,
	},
}
