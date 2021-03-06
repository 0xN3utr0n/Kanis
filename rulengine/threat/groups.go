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

package threat

import (
	"sync"

	"github.com/0xN3utr0n/Kanis/rulengine/event"
	"github.com/0xN3utr0n/Kanis/scanner"

	"github.com/0xN3utr0n/Kanis/rulengine/elf"
	"github.com/0xN3utr0n/Kanis/rulengine/task"
	"golang.org/x/sys/unix"
)

type Group struct {
	category string
	ctx      *event.Context
	wg       *sync.WaitGroup
}

func ExecveAnalysis(ioc interface{}, ctx *event.Context) {
	var wg sync.WaitGroup
	grp := Group{"Defense Evasion", ctx, &wg}
	bin := ioc.(*elf.Elf)

	defer func() {
		bin.Close()
		ctx.Current.SetElf(nil)
	}()

	grp.wg.Add(3)
	go grp.detectMasquerading(bin)
	go grp.detectBinaryPacking(bin)
	go grp.detectBinaryParasite(bin)
	grp.wg.Wait()
}

func SignalAnalysis(ioc interface{}, ctx *event.Context) {
	var wg sync.WaitGroup
	grp := Group{"Defense Evasion", ctx, &wg}
	signal := ioc.(unix.Signal)

	grp.wg.Add(1)
	grp.detectSigTrapHandler(signal)
	grp.wg.Wait()
}

func PtraceAnalysis(ioc interface{}, ctx *event.Context) {
	var wg sync.WaitGroup
	grp := Group{"Defense Evasion", ctx, &wg}
	tracee := ioc.(*task.Tracee)

	grp.wg.Add(3)
	go grp.detectTwoWayTracing()
	go grp.detectProcessInjection(tracee)
	go grp.detectUnexpectedTracer(tracee)
	grp.wg.Wait()
}

func BinaryAnalysis(ioc interface{}, ctx *event.Context) {
	var wg sync.WaitGroup
	grp := Group{"Persistence", ctx, &wg}
	bin := ioc.(*elf.Elf)

	defer bin.Close()

	grp.wg.Add(2)
	go grp.detectBinaryPacking(bin)
	go grp.detectBinaryParasite(bin)
	grp.wg.Wait()
}

func UnlinkAnalysis(ioc interface{}, ctx *event.Context) {
	var wg sync.WaitGroup
	grp := Group{"Persistence", ctx, &wg}
	path := ioc.(string)

	grp.wg.Add(1)
	grp.detectExecutableDeletion(path)
	grp.wg.Wait()
}

func YaraAnalysis(ctx *event.Context) {
	in, out, noRules := scanner.ConnectToYara()
	if noRules == true {
		return
	}

	grp := Group{"Execution", ctx, nil}
	bin := ctx.Current.GetElf()

	in <- bin.Tpath
	matches := <-out

	if len(matches) == 0 {
		return
	}

	// Create an alert for each found rule.
	for _, m := range matches {
		logThreat("Malware", high, bin.Rpath, &m, &grp)
	}

	grp.ctx.Current.UpdateScore(high)
	bin.UpdateScore(elf.Dangerous)
}
