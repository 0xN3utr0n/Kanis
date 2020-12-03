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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/0xN3utr0n/Kanis/logger"
)

var (
	wg  sync.WaitGroup
	wg2 sync.WaitGroup
	log *logger.Logger
)

type fileScanner func(file *Fstat) error

// NewSnapshot takes a file system snapshot.
// It scans for executables, binaries, and even Yara Rules.
func NewSnapshot(main *logger.Logger) {
	log = main

	log.InfoS("Taking system snapshot", "Scanner")

	// TODO: Implement a proper interface. This is a bit lame.
	if err := scanExecutables(); err != nil {
		log.ErrorS(err, "Scanner")
	}
	if err := scanYara(); err != nil {
		log.ErrorS(err, "Scanner")
	}

	log.InfoS("Snapshot completed", "Scanner")
}

// scan is a generic multithreaded FS scanner.
func scan(paths []string, callback fileScanner) {
	files := make(chan Fstat, 200)

	for _, p := range paths {
		log.DebugS("Scanning directory: "+p, "Scanner")
		wg.Add(1)
		go scanDir(p, files)
	}

	for i := 0; i < (runtime.NumCPU() * 2); i++ {
		wg2.Add(1)
		go scanFile(files, callback)
	}

	wg.Wait()
	close(files)
	wg2.Wait()
}

// scanDir Scans a directory recursively for files.
func scanDir(p string, files chan Fstat) {
	defer wg.Done()

	err := filepath.Walk(p,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.Mode().IsRegular() == true {
				files <- Fstat{Path: path}
			}
			return nil
		})
	if err != nil {
		log.ErrorS(err, "Scanner")
	}
}

// scanFile (worker)
func scanFile(files chan Fstat, callback fileScanner) {
	defer wg2.Done()

	for f := range files {
		if err := callback(&f); err != nil {
			log.ErrorS(fmt.Errorf("%s - %s", f.Path, err), "Scanner")
		}
	}
}
