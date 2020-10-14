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

package database

import (
	"os"
	"strconv"
	"testing"
)

func BenchmarkInsert(b *testing.B) {
	for i := 0; i < b.N; i++ {
		err := InsertExecutable(0, 1123, "/usr/bin/grep"+strconv.Itoa(i), "939483rjj2we2")
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkUpdate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		err := UpdateExecutable(0, 1123, "/usr/bin/grep"+strconv.Itoa(i), "939483rjj2sdswe2")
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkRead(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := ExistsExecutable("/usr/bin/grep" + strconv.Itoa(i))
		if err != nil {
			panic(err)
		}
	}
}

func init() {
	os.Remove(dbpath)

	if err := NewDb(); err != nil {
		panic(err)
	}

	if err := CreateExecutableTable(); err != nil {
		panic(err)
	}
}
