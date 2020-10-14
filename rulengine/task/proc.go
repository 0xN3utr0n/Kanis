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

package task

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"
)

func (current *Task) IsDead(pid int) bool {
	var status bool

	p, err := procfs.NewProc(pid)
	if err != nil {
		return true
	}

	// Check that the process is really dead
	for i := 0; i < 3; i++ {
		ps, err := p.NewStat()
		if err != nil {
			return true
		}

		if ps.State == "X" || ps.State == "Z" {
			status = true
		} else {
			status = false
		}

		time.Sleep(100 * time.Millisecond)
	}

	return status
}

// fetchExecutable returns the path of the task's executable
// along with the commandline arguments.
func FetchExecutable(p *procfs.Proc, pid int, name string) ([]string, bool) {
	if p == nil {
		if d, err := procfs.NewProc(pid); err != nil {
			return nil, false
		} else {
			p = &d
		}
	}

	args, err := p.CmdLine()
	if err != nil || len(args) == 0 {
		args = []string{name}
	}

	if comm, err := p.Executable(); err == nil {
		if strings.HasSuffix(comm, " (deleted)") {
			comm = strings.Split(comm, " (deleted)")[0]
		}
		args[0] = comm
	}

	return args, filepath.IsAbs(args[0])
}

// createTask Creates a new task object using the corresponding /proc/ information.
func createTask(name string, pid int) (*Task, error) {
	p, err := procfs.NewProc(pid)
	if err != nil {
		return nil, nil
	}
	ps, err := p.NewStatus()
	if err != nil {
		return nil, err
	}
	s, err := p.Stat()
	if err != nil {
		return nil, err
	}
	cwd, err := p.Cwd()
	if err != nil {
		return nil, err
	}

	//  TODO: Get PidNS

	// Check if it's a thread
	var flags uint64
	if ps.TGID != pid {
		flags |= unix.CLONE_VM
	}

	args, _ := FetchExecutable(&p, pid, name)

	ntask := new(Task)
	ntask.SetPPid(s.PPID)
	ntask.SetComm(args[0])
	ntask.SetArgv(args)
	ntask.SetCwd(cwd)
	ntask.SetFlags(flags)

	return ntask, nil
}
