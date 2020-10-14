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

import "sync"

type List struct {
	tasks map[int]*Task
	mutex sync.RWMutex
}

// NewList Returns a hashmap for safe concurrent access.
func NewList(size int) *List {
	return &List{tasks: make(map[int]*Task, size)}
}

func (list *List) Insert(pid int, current *Task) {
	list.mutex.Lock()
	list.tasks[pid] = current
	list.mutex.Unlock()
}

func (list *List) Delete(pid int) {
	list.mutex.Lock()
	delete(list.tasks, pid)
	list.mutex.Unlock()
}

func (list *List) Get(pid int) *Task {
	list.mutex.RLock()
	t := list.tasks[pid]
	list.mutex.RUnlock()

	return t
}
