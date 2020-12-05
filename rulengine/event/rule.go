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

package event

import (
	"fmt"
	"strings"
)

// Rules is a list of rules used by the engine.
type Rules map[string]*Rule

const (
	// All supported categories
	Exec   = 'x'
	Task   = 't'
	Signal = 's'
	File   = 'f'
	Mount  = 'm'
	Ptrace = 'p'
	Ns     = 'n'
)

// Rule is a generic structure that contains the needed information
// required to parse/process an specific event.
type Rule struct {
	// Type of event
	Category     rune
	RequiresYara bool
	log          bool
	// ProcessEvent Event handler
	ProcessEvent func(ctx *Context, evt *Event) (interface{}, error)
	// ThreatAnalysis Threat handler
	ThreatAnalysis func(i interface{}, ctx *Context)
}

func checkRuleMonitoring(rules Rules, categories string) error {
	// categories are indicated by the -e option
	// using the following format: -e=t:x:m
	parsed := strings.Split(categories, ":")

	for _, s := range parsed {
		if len(s) != 1 {
			return fmt.Errorf("Invalid option -e='%s'", s)
		}

		for _, r := range rules {
			if s == "a" || rune(s[0]) == r.Category {
				r.log = true
			}
		}
	}

	return nil
}
