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

package elf

import (
	"path/filepath"
	"strings"
)

// CleanPath returns the base of the given path.
func CleanPath(path string) string {
	var file string

	if path[0] == '/' || path[0] == '.' {
		file = filepath.Base(path)
	} else {
		file = path
	}

	return strings.TrimLeft(file, " ")
}

// ValidExtension Reports whether the given filepath includes a valid executable extension.
func ValidExtension(file string) (string, bool) {
	extRaw := filepath.Ext(file)

	if size := len(extRaw); size > 0 {
		ext := strings.ToLower(extRaw)
		for _, e := range []string{".bin", ".out", ".elf", ".exe", ".run"} {
			if strings.HasPrefix(ext, e) {
				return ext, true
			}
		}

		return ext, false
	}

	return "", true
}
