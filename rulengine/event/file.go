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

	"github.com/0xN3utr0n/Kanis/rulengine/database"
	"github.com/0xN3utr0n/Kanis/rulengine/elf"
	"golang.org/x/sys/unix"
)

// ProcessOpen Processes incoming OPEN events for a given task.
// It currently only supports write attempts to monitored files.
func (ctx *Context) ProcessOpen(evt *Event) error {
	fd, err := strconv.Atoi(evt.RetValue[0])
	if err != nil {
		return err
	} else if fd < 0 {
		ctx.Debug(evt.Function, "Failed function call")
		return nil
	}

	args := evt.Args.([]string)
	if len(args) != 2 {
		return nil
	}

	flags, err := strconv.Atoi(args[1])
	if err != nil || ((flags & unix.O_WRONLY) == 0) {
		return err
	}

	file, err := elf.GetAbsFilePath(ctx.Current.GetCwd(), args[0])
	if err != nil {
		return err
	}

	ok, err := database.ExistsExecutable(file)
	if err != nil || ok == false {
		return err
	}

	if err := database.InsertFileDescriptor(fd, ctx.PID, file); err != nil {
		return err
	}

	logOpen(file, ctx)

	return nil
}

// ProcessClose Processes incoming CLOSE events for a given task.
// Returns an Elf object for further analysis.
func (ctx *Context) ProcessClose(evt *Event) (*elf.Elf, error) {
	ret, err := strconv.Atoi(evt.RetValue[0])
	if err != nil {
		return nil, err
	} else if ret < 0 {
		ctx.Debug(evt.Function, "Failed function call")
		return nil, nil
	}

	fd, err := strconv.Atoi(evt.Args.([]string)[0])
	if err != nil {
		return nil, err
	}

	ok, err := database.ExistsFileDescriptor(fd, ctx.PID)
	if err != nil || ok == false {
		return nil, err
	}

	path, err := database.GetFileDescriptorPath(fd, ctx.PID)
	if err != nil {
		return nil, err
	}

	if err := database.DeleteFileDescriptor(fd, ctx.PID); err != nil {
		return nil, err
	}

	// Only returns the elf if the hash has change since the last modification.
	e, err := elf.New(path)
	if err != nil {
		return nil, err
	}

	logClose(path, ctx)

	return e, nil
}

// ProcessUnlink Processes incoming UNLINK events for a given task.
// Returns the monitored file's path.
func (ctx *Context) ProcessUnlink(evt *Event) (string, error) {
	ret, err := strconv.Atoi(evt.RetValue[0])
	if err != nil {
		return "", err
	} else if ret < 0 {
		ctx.Debug(evt.Function, "Failed function call")
		return "", nil
	}

	file, err := elf.GetAbsFilePath(ctx.Current.GetCwd(), evt.Args.([]string)[0])
	if err != nil {
		return "", err
	}

	ok, err := database.ExistsExecutable(file)
	if err != nil || ok == false {
		return "", err
	}

	// Not needed, but it makes debugging easier.
	if err := database.DeleteExecutable(file); err != nil {
		return "", err
	}

	logUnlink(file, ctx)

	return file, nil
}

// ProcessRename Processes incoming RENAME events for a given task.
// At least one of the paths (old or new) must be currently monitored.
// Returns the corresponding ELF object to new path.
func (ctx *Context) ProcessRename(evt *Event) (*elf.Elf, error) {
	ret, err := strconv.Atoi(evt.RetValue[0])
	if err != nil {
		return nil, err
	} else if ret < 0 {
		ctx.Debug(evt.Function, "Failed function call")
		return nil, nil
	}

	args := evt.Args.([]string)
	if len(args) != 2 {
		return nil, nil
	}

	old, err := elf.GetAbsFilePath(ctx.Current.GetCwd(), args[0])
	if err != nil {
		return nil, err
	}

	ok1, err := database.ExistsExecutable(old)
	if err != nil {
		return nil, err
	} else if ok1 == true {
		if err := database.DeleteExecutable(old); err != nil {
			return nil, err
		}
	}

	new, err := elf.GetAbsFilePath(ctx.Current.GetCwd(), args[1])
	if err != nil {
		return nil, err
	}

	ok2, err := database.ExistsExecutable(new)
	if err != nil || (ok1 == false && ok2 == false) {
		return nil, err
	}

	e, err := elf.New(new)
	if err != nil {
		return nil, err
	}

	logRename(new, old, ctx)

	return e, nil
}

// ProcessChdir Processes incoming CHDIR events for a given task.
// Used to retrieve the task's Current Working Directory (CWD).
func (ctx *Context) ProcessChdir(evt *Event) error {
	r, err := strconv.Atoi(evt.RetValue[0])
	if err != nil {
		return err
	} else if r < 0 {
		ctx.Debug(evt.Function, "Failed function call")
		return nil
	}

	cwd, err := elf.GetAbsDirPath(ctx.Current.GetCwd(), evt.Args.([]string)[0])
	if err != nil {
		return err
	}

	ctx.Current.SetCwd(cwd)
	return nil
}
