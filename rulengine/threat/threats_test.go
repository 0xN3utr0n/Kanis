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

// +build integration

package threat

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type Task struct {
	Comm   string
	Danger int
	Task   string
	VPid   int
}

type Alert struct {
	Level     int
	Category  string
	Technique string
}

type Indicator struct {
	Value string
}

type threatEvent struct {
	Current Task
	IOC     Indicator
	Threat  Alert
}

var r *bufio.Reader
var cwd string

func TestMain(m *testing.M) {
	cwd, _ = os.Getwd()

	go func() {
		if err := exec.Command("Kanis", "-e=a").Run(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}()

	time.Sleep(5 * time.Second)

	fd, err := os.OpenFile("/var/kanis/threats.log", os.O_RDONLY, 0644)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	defer fd.Close()

	r = bufio.NewReader(fd)

	m.Run()
	exec.Command("pkill", "Kanis").Run()
	os.Exit(0)
}

func TestMasquerading(t *testing.T) {
	err := exec.Command("/usr/bin/bash", "Tests/sample1/sample1.sh").Run()
	if err != nil {
		t.Error(err)
	}

	msg := []threatEvent{
		{Task{"/tmp/[kworkerd]", 0, "Process", 0}, Indicator{},
			Alert{1, "Defense Evasion", "Kernel Thread Masquerading"}},
		{Task{"/tmp/[kworkerd]", 0, "Process", 0}, Indicator{},
			Alert{1, "Defense Evasion", "Kernel Thread Masquerading"}},
		{Task{"/tmp/[kworkerd]", 0, "Process", 0}, Indicator{},
			Alert{1, "Defense Evasion", "Kernel Thread Masquerading"}},
		{Task{"/tmp/  [kworkerd]", 0, "Process", 0}, Indicator{},
			Alert{1, "Defense Evasion", "Kernel Thread Masquerading"}},
		{Task{"/tmp/file.txt ", 0, "Process", 0}, Indicator{},
			Alert{1, "Defense Evasion", "Space After Filename Masquerading"}},
	}

	for _, m := range msg {
		validateOutput(m, t)
	}
}

func TestSoftwarePacking(t *testing.T) {
	err := exec.Command("Tests/sample2/sample2.bin", "0.5").Run()
	if err != nil {
		t.Error(err)
	}

	msg := []threatEvent{
		{Task{cwd + "/Tests/sample2/sample2.bin", 0, "Thread", 0}, Indicator{},
			Alert{3, "Defense Evasion", "Software Packing"}},
	}

	for _, m := range msg {
		validateOutput(m, t)
	}
}

func TestTracingProtection(t *testing.T) {
	err := exec.Command("Tests/sample3/sample3.bin").Run()
	if err != nil && !strings.Contains(err.Error(), "stop signal") {
		t.Error(err)
	}

	msg := []threatEvent{
		{Task{cwd + "/Tests/sample3/sample3.bin", 0, "Process", 0}, Indicator{},
			Alert{1, "Defense Evasion", "Two-Way-Tracing Protection"}},
		{Task{cwd + "/Tests/sample3/sample3.bin", 0, "Thread", 0}, Indicator{},
			Alert{1, "Defense Evasion", "Traceme Protection"}},
	}

	for _, m := range msg {
		validateOutput(m, t)
	}
}

func TestExecutableDeletion(t *testing.T) {
	os.Chdir("Tests/sample4")
	err := exec.Command("./sample4.bin").Run()
	if err != nil {
		t.Error(err)
	}

	msg := []threatEvent{
		{Task{"/usr/bin/rm", 0, "Process", 0}, Indicator{cwd + "/Tests/sample4/sample4.bin"},
			Alert{1, "Persistence", "Executable Deletion"}},
	}

	for _, m := range msg {
		validateOutput(m, t)
	}
	os.Chdir("../..")
}

func TestSigTrapHandler(t *testing.T) {
	err := exec.Command("Tests/sample5/sample5.bin").Run()
	if err != nil {
		t.Error(err)
	}

	msg := []threatEvent{
		{Task{cwd + "/Tests/sample5/sample5.bin", 0, "Thread", 0}, Indicator{cwd + "/Tests/sample5/sample5.bin"},
			Alert{3, "Defense Evasion", "Software Packing"}},
		{Task{cwd + "/Tests/sample5/sample5.bin", 3, "Thread", 0}, Indicator{},
			Alert{1, "Defense Evasion", "SIGTRAP-Handler Protection"}},
	}

	for _, m := range msg {
		validateOutput(m, t)
	}
}

func validateOutput(validMsg threatEvent, t *testing.T) {
	assert := assert.New(t)
	event := threatEvent{}

	js := readEvent(t)
	if len(js) == 0 {
		return
	}

	if err := json.Unmarshal(js, &event); err != nil {
		t.Error(err)
	}

	if assert.NotEmpty(event) == false {
		return
	}

	assert.Equal(validMsg.Current, event.Current)
	assert.Equal(validMsg.Threat, event.Threat)

	if validMsg.IOC != (Indicator{}) {
		assert.Equal(validMsg.IOC, event.IOC)
	}
}

func readEvent(t *testing.T) []byte {
	ch := make(chan string, 1)
	timeout := make(chan bool, 1)

	defer close(ch)
	defer close(timeout)

	go func() {
		for {
			select {
			case <-timeout:
				return
			default:
				if line, _ := r.ReadString(byte('\n')); line != "" {
					ch <- line
					return
				}
				time.Sleep(1 * time.Second)
			}
		}
	}()

	select {
	case line := <-ch:
		return []byte(line)

	case <-time.After(5 * time.Second):
		t.Error(errors.New("Timeout error"))
		timeout <- true
	}

	return []byte{}
}
