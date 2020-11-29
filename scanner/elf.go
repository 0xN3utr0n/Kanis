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

package scanner

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/0xN3utr0n/Kanis/rulengine/database"
)

var update bool

type Fstat struct {
	Path  string
	info  os.FileInfo
	inode uint64
	dev   uint64
	hash  string
}

func scanExecutables() error {
	log.InfoS("Scanning ELF binaries", "Sys-Scan")

	if err := database.CreateExecutableTable(); err != nil {
		return err
	}

	scan([]string{"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local"})

	return nil
}

// scanElf Checks whether the given filepath points to a valid ELF file.
// In addition, it retrieves some basic information about it.
func (file *Fstat) ScanElf() bool {
	var err error

	// Follow symbolic-links
	file.Path, err = filepath.EvalSymlinks(file.Path)
	if err != nil {
		log.ErrorS(err, "Sys-Scan")
		return false
	}

	fd, err := os.Open(file.Path)
	if err != nil {
		log.ErrorS(err, "Sys-Scan")
		return false
	}

	defer fd.Close()

	if checkElfMagic(fd) == false {
		return false
	}

	// Get file's hash
	h := sha256.New()
	if _, err := io.Copy(h, fd); err != nil {
		log.ErrorS(err, "Sys-Scan")
		return false
	}

	file.hash = fmt.Sprintf("%x", h.Sum(nil))

	if file.setInodeDev() == false {
		log.ErrorS(err, "Sys-Scan")
		return false
	}

	return true
}

// setInodeDev Get a file's inode and device id
func (file *Fstat) setInodeDev() bool {
	var err error

	file.info, err = os.Lstat(file.Path)
	if err != nil {
		log.ErrorS(err, "Sys-Scan")
		return false
	}

	s, ok := file.info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}

	file.inode = uint64(s.Ino)
	file.dev = uint64(s.Dev)

	return true
}

// CheckElfMagic Reads the file's magic bytes in order to find out if it's an ELF.
func checkElfMagic(Fd *os.File) bool {
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

func StoreExecInformation(file Fstat) error {
	exists, err := database.ExistsExecutable(file.Path)
	if err != nil {
		return err
	}

	if exists == true {
		if err := database.UpdateExecutable(file.dev, file.inode, file.Path, file.hash); err != nil {
			return err
		}
	} else {
		if err := database.InsertExecutable(file.dev, file.inode, file.Path, file.hash); err != nil {
			return err
		}
	}

	return nil
}
