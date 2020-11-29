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
	"os"
	"strings"
	"sync"

	"github.com/Velocidex/go-yara"
)

var (
	rules    *yara.Rules
	compiler *yara.Compiler
	mutex    sync.RWMutex
	filesIn  chan string
	rulesOut chan []YaraRule
	noRules  = true
)

type YaraRule struct {
	Rule        string
	Description string
}

func scanYara() error {
	log.InfoS("Scanning Yara Rules", "Sys-Scan")

	if err := newYaraCompiler(); err != nil {
		return err
	}

	scan([]string{"/var/kanis/rules"})

	return nil
}

func (file *Fstat) scanYaraRule() (bool, error) {
	if !strings.HasSuffix(file.Path, ".yara") &&
		!strings.HasSuffix(file.Path, ".yar") {
		return false, nil
	}

	fd, err := os.Open(file.Path)
	if err != nil {
		return false, err
	}

	defer fd.Close()

	mutex.Lock()
	defer mutex.Unlock()

	if err := compiler.AddFile(fd, file.Path); err != nil {
		// The compiler becomes unusable if AddFile() fails.
		// The only workaround is to create a new one.
		newYaraCompiler()
		return false, err
	}

	if noRules == true {
		noRules = false
	}

	return true, nil
}

func newYaraCompiler() error {
	if compiler != nil {
		compiler.Destroy()
	}

	var err error

	compiler, err = yara.NewCompiler()
	if err != nil {
		return err
	}

	return nil
}

func StartYara() error {
	var err error

	if noRules == true {
		log.InfoS("Yara Disabled - No Rules Loaded", "Sys-Scan")
		return nil
	}

	rules, err = compiler.GetRules()
	if err != nil {
		return err
	}

	filesIn = make(chan string, 1)
	rulesOut = make(chan []YaraRule, 1)

	go func() {
		defer close(filesIn)
		defer close(rulesOut)

		for f := range filesIn {
			r, err := rules.ScanFile(f, 0, 0)
			if err != nil {
				log.ErrorS(err, "Sys-Scan")
			}
			rulesOut <- parseRule(r)
		}
	}()

	return nil
}

func parseRule(rules []yara.MatchRule) []YaraRule {
	matches := make([]YaraRule, len(rules))

	for i, rule := range rules {
		description := "Unknown"
		for d, m := range rule.Meta {
			if d == "description" {
				description = m.(string)
			}
		}
		matches[i] = YaraRule{rule.Rule, description}
	}

	return matches
}

func ConnectToYara() (chan string, chan []YaraRule, bool) {
	return filesIn, rulesOut, noRules
}
