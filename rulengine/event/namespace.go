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
	"strconv"

	"github.com/0xN3utr0n/Kanis/rulengine/task"
	"golang.org/x/sys/unix"
)

// ProcessSetHostname Processes incoming SETHOSTNAME events for a given task.
// Only useful if the task is in a UTS namespace.
func (ctx *Context) ProcessSetHostname(evt *Event) error {
	r, err := strconv.Atoi(evt.RetValue[0])
	if err != nil {
		return err
	} else if r < 0 {
		ctx.Debug(evt.Function, "Failed function call")
		return nil
	}

	args := evt.Args.([]string)

	if ctx.Current.NamespaceID(task.UtsNs) == 0 { // Not inside a namespace
		return nil
	}

	if err := ctx.Current.UpdateNamespace(task.UtsNs, args[0]); err != nil {
		return err
	}

	return nil
}

// ProcessUnshare Processes incoming UNSHARE events for a given task.
// Used to detect the creation of new Namespaces.
func (ctx *Context) ProcessUnshare(evt *Event) error {
	r, err := strconv.Atoi(evt.RetValue[0])
	if err != nil {
		return err
	} else if r != 0 {
		ctx.Debug(evt.Function, "Failed function call")
		return nil
	}

	args := evt.Args.([]string)
	flags, err := strconv.ParseUint(args[0][2:], 16, 64)
	if err != nil {
		return err
	}

	if (flags & unix.CLONE_NEWPID) != 0 {
		ctx.Current.SetVPid(newPidNS)
	}

	ctx.Current.SwitchNamespace(flags)
	ctx.Current.SetFlags(flags | ctx.Current.GetFlags())

	return nil
}

// ProcessSetNs Processes incoming SetNS events for a given task.
// Useless event right now.
func (ctx *Context) ProcessSetNs(evt *Event) error {
	r, err := strconv.Atoi(evt.RetValue[0])
	if err != nil {
		return err
	} else if r != 0 {
		ctx.Debug(evt.Function, "Failed function call")
		return nil
	}

	args := evt.Args.([]string)
	flags, err := strconv.ParseUint(args[0][1:], 16, 64)
	if err != nil {
		return err
	}

	// TODO: Throught the task's FDs (database)
	// get the corresponding namespace path (/proc/<pid>/ns) and retrieve the
	// target process PID (which has a valid namespace id).

	ctx.Current.SetFlags(ctx.Current.GetFlags() | flags)
	return nil
}
