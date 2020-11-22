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
	"strconv"

	"github.com/0xN3utr0n/Kanis/rulengine/task"
	"golang.org/x/sys/unix"
)

// ProcessMount Processes incoming Mount events for a given task.
func (ctx *Context) ProcessMount(evt *Event) error {
	r, err := strconv.Atoi(evt.RetValue[0])
	if err != nil {
		return err
	} else if r != 0 {
		ctx.Debug(evt.Function, "Failed function call")
		return nil
	}

	args := evt.Args.([]string)
	if len(args) != 2 {
		return nil
	}

	// CLONE_ flags
	flags, err := strconv.ParseInt(args[1][2:], 16, 64)
	if err != nil {
		return err
	}

	if (flags & unix.MS_BIND) == 0 {
		return nil
	}

	path := args[0]

	// Only interested in directories.
	if fi, err := os.Lstat(path); err != nil || fi.IsDir() == false {
		return err
	}

	var mount string

	if ctx.Current.NamespaceID(task.MountNs) > 0 {
		mount, err = mountNamespace(ctx.Current, path)
		if err != nil || mount == "" {
			return err
		}
	} else {
		// TODO: Add support for common mountpoints
		return nil
	}

	logMount(path, mount, ctx)
	return nil
}

func mountNamespace(current *task.Task, path string) (string, error) {
	data, err := current.NamespaceData(task.MountNs)
	if data != "" || err != nil {
		return "", err
	}

	mount := "NEW_MOUNT_NS"

	if current.IsInContainer() == true {
		mount = "NEW_CONTAINER"
	}

	if err := current.UpdateNamespace(task.MountNs, path); err != nil {
		return "", err
	}

	current.SetCwd(path)

	return mount, nil
}
