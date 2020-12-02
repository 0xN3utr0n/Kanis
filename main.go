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

package main

import (
	"flag"
	l "log"

	"github.com/0xN3utr0n/Kanis/ftrace"
	"github.com/0xN3utr0n/Kanis/logger"
	"github.com/0xN3utr0n/Kanis/rulengine"
	"github.com/0xN3utr0n/Kanis/rulengine/database"
	"github.com/0xN3utr0n/Kanis/scanner"
)

func main() {
	showEvents := flag.Bool("e", false, "Enable kernel events monitoring (very verbose).")
	debug := flag.Bool("d", false, "Show debug messages (very verbose).")
	stdout := flag.Bool("s", false, "Redirect all output to stdout.")
	flag.Parse()

	logger.SetDebug(*debug)

	log, err := logger.New("/var/kanis/kanis.log", *stdout)
	if err != nil {
		l.Fatal(err)
	}

	if err := database.NewDb(); err != nil {
		log.FatalS(err, "None")
	}

	scanner.NewSnapshot(log)

	ruleChan := ftrace.New(log).Init()

	rulengine.Run(ruleChan, log, *showEvents, *stdout)
}
