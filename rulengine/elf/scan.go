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
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"

	"github.com/0xN3utr0n/Kanis/logger"
	"github.com/0xN3utr0n/Kanis/rulengine/database"
)

type fstat struct {
	path  string
	info  os.FileInfo
	inode uint64
	dev   uint64
	hash  string
}

var (
	wg     sync.WaitGroup
	wg2    sync.WaitGroup
	update bool
	log    *logger.Logger
)

// ScanSystem scans for critical files within the specified directories.
func ScanSystem(main *logger.Logger) {
	log = main

	log.InfoS("Taking system snapshot", "Sys-Scan")

	// Currently Sys-Scan only searches for ELF Executables.
	if err := database.CreateExecutableTable(); err != nil {
		log.FatalS(err, "Sys-Scan")
	}

	paths := []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local"}
	files := make(chan fstat, 200)

	for _, p := range paths {
		log.DebugS("Scanning directory: "+p, "Sys-Scan")
		wg.Add(1)
		go scanDir(p, files)
	}

	for i := 0; i < (runtime.NumCPU() * 2); i++ {
		wg2.Add(1)
		go scanFile(files)
	}

	wg.Wait()
	close(files)
	wg2.Wait()

	log.InfoS("Snapshot completed", "Sys-Scan")
}

// scanDir Scans a directory recursively for files.
func scanDir(p string, files chan fstat) {
	defer wg.Done()

	err := filepath.Walk(p,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.Mode().IsRegular() == true {
				files <- fstat{path: path}
			}
			return nil
		})
	if err != nil {
		log.ErrorS(err, "Sys-Scan")
	}
}

// scanFile (worker)
func scanFile(files chan fstat) {
	defer wg2.Done()

	for f := range files {
		var err error
		if ok := f.scanElf(); ok == true {
			err = storeExecInformation(f)
		}
		if err != nil {
			log.ErrorS(err, "Sys-Scan")
		}
	}
}

func storeExecInformation(file fstat) error {
	exists, err := database.ExistsExecutable(file.path)
	if err != nil {
		return err
	}

	if exists == true {
		if err := database.UpdateExecutable(file.dev, file.inode, file.path, file.hash); err != nil {
			return err
		}
	} else {
		if err := database.InsertExecutable(file.dev, file.inode, file.path, file.hash); err != nil {
			return err
		}
	}

	return nil
}

// scanElf Checks whether the given filepath points to a valid ELF file.
// In addition, it retrieves some basic information about it.
func (file *fstat) scanElf() bool {
	var err error

	// Follow symbolic-links
	file.path, err = filepath.EvalSymlinks(file.path)
	if err != nil {
		log.ErrorS(err, "Sys-Scan")
		return false
	}

	fd, err := os.Open(file.path)
	if err != nil {
		log.ErrorS(err, "Sys-Scan")
		return false
	}

	defer fd.Close()

	if CheckElfMagic(fd) == false {
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
func (file *fstat) setInodeDev() bool {
	var err error

	file.info, err = os.Lstat(file.path)
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
