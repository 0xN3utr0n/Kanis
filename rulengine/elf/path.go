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
	"errors"
	"path/filepath"
	"strings"
)

// GetAbsFilePath returns a valid and absolute path for the given file.
// Note: it follows symbolic links.
func GetAbsFilePath(cwd, file string) (string, error) {
	if filepath.IsAbs(file) == true { // Just in case the file has already been deleted
		dir, err := filepath.EvalSymlinks(filepath.Dir(file))
		if err == nil {
			cwd = dir
			file = filepath.Base(file)
		}
	}

	file = filepath.Join(cwd, file)
	if filepath.IsAbs(file) == false {
		return "", errors.New("Invalid path: " + file)
	}

	path, err := filepath.EvalSymlinks(file)
	if err != nil { // Don't care if the file doesn't exist anymore
		return file, nil
	}

	return path, nil
}

// GetAbsDirPath returns a valid and absolute path for the given directory.
// Note: it follows symbolic links.
func GetAbsDirPath(cwd, dir string) (string, error) {
	if filepath.IsAbs(dir) == true {
		return dir, nil
	}

	dir = filepath.Join(cwd, dir)
	if filepath.IsAbs(dir) == false {
		return "", errors.New("Invalid path: " + dir)
	}

	abs, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", err
	}

	return abs, nil
}

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
