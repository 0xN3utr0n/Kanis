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
	"debug/elf"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/0xN3utr0n/Kanis/rulengine/database"
)

type Elf struct {
	Fd    *elf.File
	Tpath string // temporal path for the copy
	Rpath string // real path
	Score int    // danger score
	mutex sync.RWMutex
}

const (
	// Danger levels
	Unknown   = -1
	Benign    = 0
	Dangerous = 1
	filesDir  = "/var/kanis/files/"
)

// New returns the corresponding ELF object to the given file.
func New(path string) (*Elf, error) {
	if filepath.IsAbs(path) == false {
		return nil, errors.New("Invalid ELF Path: " + path)
	}

	bin := new(Elf)
	bin.Rpath = path
	file := fstat{path: path}

	var err error

	if file.scanElf() == false {
		return nil, errors.New("Invalid ELF file: " + path)
	}

	if err = storeExecInformation(file); err != nil {
		return nil, err
	}

	// Bening executables are whitelisted.
	bin.Score, err = database.GetExecutableDanger(path)
	if err != nil || bin.Score == Benign {
		return nil, err
	}

	// The RuleEngine must explicitly mark them as dangerous.
	if bin.Score == Unknown {
		bin.UpdateScore(Benign)
	}

	if err = bin.Open(path); err != nil {
		return nil, err
	}

	return bin, nil
}

// Open makes a copy, for later analysis, of the ELF executable pointed by the given path.
func (bin *Elf) Open(path string) error {
	bin.Tpath = filesDir + filepath.Base(path)

	// Check if the copy already exists.
	if _, err := os.Stat(bin.Tpath); err != nil {
		src, err := os.Open(path)
		if err != nil {
			return err
		}

		defer src.Close()

		dst, err := os.OpenFile(bin.Tpath, os.O_RDWR|os.O_CREATE, 0700)
		if err != nil {
			return err
		}

		defer dst.Close()

		if _, err = io.Copy(dst, src); err != nil {
			return err
		}
	}

	var err error

	bin.Fd, err = elf.Open(bin.Tpath)
	if err != nil {
		return err
	}

	return nil
}

// Close deletes the Elf copy created with Open().
func (bin *Elf) Close() {
	bin.Fd.Close()
	os.Remove(bin.Tpath)
}

// UpdateScore updates the file's danger score.
func (bin *Elf) UpdateScore(score int) {
	bin.mutex.Lock()
	if bin.Score < score || score == Benign {
		bin.Score = score
		database.UpdateExecutableDanger(bin.Rpath, score)
	}
	bin.mutex.Unlock()
}

// CheckElfMagic Reads the file's magic bytes in order to find out if it's an ELF.
func CheckElfMagic(Fd *os.File) bool {
	var header [4]byte

	_, err := io.ReadFull(Fd, header[:])
	if err != nil {
		return false
	}

	if header != [4]byte{0x7f, 0x45, 0x4c, 0x46} {
		return false
	}

	return true
}
