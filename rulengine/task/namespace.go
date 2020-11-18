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
	"errors"

	"github.com/0xN3utr0n/Kanis/rulengine/database"
	"golang.org/x/sys/unix"
)

const (
	MountNs = iota
	PidNs   = iota
	UtsNs   = iota
	maxNS   = iota
)

var nsDict = map[uint64]uint64{
	unix.CLONE_NEWNS:  MountNs,
	unix.CLONE_NEWPID: PidNs,
	unix.CLONE_NEWUTS: UtsNs,
}

type Namespaces [maxNS]int64

func (current *Task) IsInContainer() bool {
	ns := current.GetNamespaces()

	if ns[MountNs] != 0 && ns[PidNs] != 0 && ns[UtsNs] != 0 {
		return true
	}

	return false
}

func (current *Task) GetNamespaces() Namespaces {
	current.mutex.RLock()
	ns := current.ns
	current.mutex.RUnlock()

	return ns
}

func (current *Task) SetNamespaces(ns Namespaces) {
	current.mutex.RLock()
	current.ns = ns
	current.mutex.RUnlock()
}

func (current *Task) SwitchNamespace(flags uint64) (err error) {
	for unixns, localns := range nsDict {
		if (flags & unixns) != 0 {
			current.ns[localns], err = database.NewNamespace(localns, "")
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (current *Task) NamespaceId(ns uint64) int64 {
	return current.GetNamespaces()[ns]
}

func (current *Task) NamespaceData(ns uint64) (string, error) {
	nsID := current.NamespaceId(ns)
	if nsID == 0 {
		return "", errors.New("Task not inside a valid namespace")
	}

	_, data, err := database.GetNamespace(nsID)
	if err != nil {
		return "", err
	}

	return data, nil
}

func (current *Task) UpdateNamespace(ns uint64, data string) error {
	nsID := current.NamespaceId(ns)
	if nsID == 0 {
		return errors.New("Task not inside a valid namespace")
	}

	err := database.UpdateNamespace(nsID, data)
	if err != nil {
		return err
	}

	return nil
}
