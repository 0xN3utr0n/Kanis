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
	"github.com/0xN3utr0n/Kanis/logger"
)

var log *logger.Logger

func EnableLogging(main *logger.Logger) {
	log = main
}

func (event *Event) Warn(msg string) {
	log.Warn("EventDecoder").
		Int("Current.PID", event.PID).
		Str("Current.Comm", event.Comm).
		Msg(msg)
}

func (event *Event) Debug(msg string) {
	log.Debug("EventDecoder").
		Int("Current.PID", event.PID).
		Str("Current.Comm", event.Comm).
		Msg(msg)
}

func (event *Event) Error(err error) {
	log.Error(err, "EventDecoder").
		Int("Current.PID", event.PID).
		Str("Current.Comm", event.Comm).
		Send()
}
