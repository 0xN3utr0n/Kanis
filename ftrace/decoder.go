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

package ftrace

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/0xN3utr0n/Kanis/rulengine/event"
)

const (
	sQueueSize  = 100  // Small queue size
	xlQueueSize = 1000 // Big queue size
)

// EventDecoder parses any kind of ftrace-related event received from the
// eventChannel pipe.
func (myftrace *Ftracer) EventDecoder(eventChan <-chan string) <-chan *event.Event {
	argChan := make(chan *event.Event, sQueueSize)
	retChan := make(chan *event.Event, sQueueSize)
	ruleChan := make(chan *event.Event, xlQueueSize)

	go decodeFields(eventChan, argChan)
	go decodeArgs(myftrace.cookie, argChan, retChan)
	go addReturnValue(retChan, ruleChan)

	return ruleChan
}

// decodeFields decodes simple and static values that follow a pattern in all events.
func decodeFields(input <-chan string, output chan *event.Event) {
	lineRegex := regexp.MustCompile(`(.{16})-(\d+) +\[(\d{3})\] (.{4}) +(\d+\.\d+)\: (.*?)\:( \(.*?\))? (.*)`)
	for {
		data := <-input
		fields := lineRegex.FindStringSubmatch(data)
		if len(fields) == 0 {
			msg := fmt.Errorf("Failed to decode event fields(%d) -> '%s'", len(fields), data)
			log.ErrorS(msg, "EventDecoder")
			continue
		}

		task := strings.Trim(fields[1], " ")
		pid, _ := strconv.Atoi(fields[2])

		output <- &event.Event{
			Comm:     task,
			PID:      pid,
			Function: fields[6],
			Args:     fields[len(fields)-1], // Save the raw arguments for later decoding.
		}
	}
}

const (
	evt_Kprobe     = 1
	evt_Tracepoint = 2
)

// decodeArgs decodes the function's arguments from the raw event.
// Raw args -> 'arg2A_str1="Hello" arg2A_str2="World"'
// Decoded args -> Hello World
func decodeArgs(cookie string, input <-chan *event.Event, output chan *event.Event) {
	event.EnableLogging(log)

	for {
		evt := <-input

		eventArgs := evt.Args.(string)
		if len(eventArgs) == 0 {
			evt.Warn("Empty event arguments")
			continue
		}

		var argsList []string

		if eventType(evt.Function) == evt_Kprobe {
			argsList = decodeKProbe(evt, cookie, eventArgs)
		} else {
			argsList = decodeTracepoint(evt, eventArgs)
		}

		if len(argsList) == 0 {
			evt.Debug("Empty arguments after parsing")
			continue
		}

		evt.Args = argsList
		output <- evt
	}
}

// addReturnValue Correlates ret_ (return) type events with their corresponding main event.
func addReturnValue(eventInput <-chan *event.Event, eventOutput chan *event.Event) {
	stack := make(map[string]*event.Event)

	// TODO: Fine-tune the correlation, there's an important memory leak.
	// Some return type events don't always match.
	for {
		evt := <-eventInput

		key := strconv.Itoa(evt.PID)
		if strings.HasPrefix(evt.Function, "ret") {
			key += strings.SplitAfter(evt.Function, "ret_")[1]
			if stack[key] == nil {
				evt.Debug("Invalid return event " + evt.Function)
				continue
			}
			if len(evt.Args.([]string)) == 0 {
				evt.Warn("Invalid return event arguments")
				continue
			}

			stack[key].RetValue = evt.Args.([]string)
			evt = stack[key]
			delete(stack, key)

		} else if eventType(evt.Function) == evt_Kprobe {
			if evt.Function != "EXIT" {
				key += evt.Function
				stack[key] = evt
				continue
			}
		}

		eventOutput <- evt
	}
}

// decodeKProbe decodes the arguments for the given kprobe event.
func decodeKProbe(evt *event.Event, cookie, eventArgs string) []string {
	argsList := make([]string, 0)

	asplit := strings.Split(eventArgs, "arg"+cookie+"_")
	if len(asplit) < 2 {
		evt.Debug(fmt.Sprintf("Failed to decode kprobe event cookie -> '%s'", eventArgs))
		return nil
	}

	for _, arg := range asplit[1:] { // [0] is always empty.
		a := strings.TrimSpace(arg)
		content := strings.SplitN(a, "=", 2)
		if len(content) < 2 {
			evt.Debug(fmt.Sprintf("Failed to decode kprobe event arguments -> '%s'", eventArgs))
			continue
		}
		if strings.HasPrefix(arg, "str") && len(content[1]) > 1 { // Remove first and last double quotes.
			content[1] = content[1][1 : len(content[1])-1]
		}
		if content[1] != "fault" { // Not a NULL arg
			argsList = append(argsList, content[1])
		} else if evt.Function == "EXECVE" {
			break // Argv is null terminated
		}
	}

	return argsList
}

// decodeTracepoint decodes the arguments for the given tracepoint event.
func decodeTracepoint(evt *event.Event, eventArgs string) []string {
	argsList := make([]string, 0)

	asplit := strings.Split(eventArgs, " ")
	if len(asplit) == 0 {
		evt.Debug(fmt.Sprintf("Failed to decode tracepoint event arguments -> '%s'", eventArgs))
		return nil
	}

	for _, arg := range asplit {
		clean := strings.SplitN(arg, "=", 2)
		if len(clean) < 2 {
			evt.Debug(fmt.Sprintf("Failed to decode tracepoint event arguments -> '%s'", eventArgs))
			continue
		}
		argsList = append(argsList, clean[1])
	}

	return argsList
}

// eventType Returns which kind of event we are analysing (kprobe or tracepoint).
func eventType(function string) int {
	if unicode.IsUpper([]rune(function)[0]) {
		return evt_Kprobe
	}

	return evt_Tracepoint
}
