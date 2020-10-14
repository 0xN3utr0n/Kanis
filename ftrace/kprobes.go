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
	"io/ioutil"
	"os"
	"strings"
)

const (
	start = "1" // start function probe.
	stop  = "0" // stop function probe.
)

// Kprobe contains information about a kernel function probe.
type kProbe struct {
	name      string
	functions []string
	param     string
	retVal    string
	// Some kprobes aren't required to be enabled, although it's highly recommended.
	optional bool
}

var kprobes = []kProbe{
	kProbe{
		"EXECVE",
		[]string{"sys_execve ", "__x64_sys_execve"},
		"arg??_str1=+0(%di):string arg??_str2=+0(+8(%si)):string " +
			"arg??_str3=+0(+16(%si)):string arg??_str4=+0(+24(%si)):string " +
			"arg??_str5=+0(+32(%si)):string arg??_str6=+0(+40(%si)):string " +
			"arg??_str7=+0(+48(%si)):string arg??_str8=+0(+56(%si)):string ",
		"arg??_int1=$retval:s32",
		false,
	},
	kProbe{
		"EXIT",
		[]string{"do_exit"},
		"arg??_int1=%di:s32",
		"arg??_int1=$retval:s32",
		false,
	},
	kProbe{
		"FORK",
		[]string{"do_fork", "_do_fork"},
		"arg??_int1=%di:s32", // TODO: delete this kprobe
		"arg??_int1=$retval:s32",
		false,
	},
	kProbe{
		"UNSHARE",
		[]string{"sys_unshare", "__x64_sys_unshare"},
		"arg??_int1=%di:s32",
		"arg??_int1=$retval:s32",
		true,
	},
	kProbe{
		"PTRACE",
		[]string{"sys_ptrace", "__x64_sys_ptrace"},
		"arg??_int1=%di:s32 arg??_int2=%si:s32",
		"arg??_int1=$retval:s32",
		true,
	},
	kProbe{
		"PROC_VM_WRITERV",
		[]string{"SyS_process_vm_writev", "__x64_sys_process_vm_writev"},
		"arg??_int1=%di:s32",
		"arg??_int1=$retval:s32",
		true,
	},
	kProbe{
		"CHDIR",
		[]string{"sys_chdir", "ksys_chdir"},
		"arg??_str1=+0(%di):string",
		"arg??_int1=$retval:s32",
		false,
	},
	kProbe{
		"SIGACTION",
		[]string{"do_sigaction"},
		"arg??_int1=%di:s32 arg??_int2=+0(%si):s32",
		"arg??_int1=$retval:s32",
		true,
	},
	kProbe{
		"OPEN",
		[]string{"do_sys_open"},
		"arg??_str1=+0(%si):string arg??_int1=%dx:s32",
		"arg??_int1=$retval:s32",
		false,
	},
	kProbe{
		"CLOSE",
		[]string{"sys_close", "__x64_sys_close"},
		"arg??_int1=%di:s32",
		"arg??_int1=$retval:s32",
		false,
	},
	kProbe{
		"UNLINK",
		[]string{"do_unlinkat"},
		"arg??_str1=+0(+0(%si)):string",
		"arg??_int1=$retval:s32",
		true,
	},
	kProbe{
		"RENAME",
		[]string{"do_renameat2", "sys_renameat2"},
		"arg??_str1=+0(%si):string arg??_str2=+0(%cx):string",
		"arg??_int1=$retval:s32",
		true,
	},
}

func (kfunc *kProbe) enable(kevents *os.File, cookie string) error {
	var err error

	pinit := "p:" + kfunc.name
	pret := "r:ret_" + kfunc.name

	// Only one function among the available ones will be enabled.
	for _, f := range kfunc.functions {
		p := fixSyscallParams(f, kfunc.param)
		command := pinit + " " + f + " " + strings.ReplaceAll(p, "??", cookie)
		if _, err = kevents.WriteString(command); err != nil {
			continue
		}

		// Set a return kprobe to get the function's return value.
		command = pret + " " + f + " " + strings.ReplaceAll(kfunc.retVal, "??", cookie)
		if _, err = kevents.WriteString(command); err != nil {
			continue
		}

		break
	}

	return err
}

// action starts and stops the specified kprobe.
func (kfunc *kProbe) action(msg string) error {
	file := "/sys/kernel/debug/tracing/events/kprobes/" + kfunc.name + "/enable"
	if err := ioutil.WriteFile(file, []byte(msg), 0644); err != nil {
		return err
	}
	// Do the same action to the return kprobe
	file = "/sys/kernel/debug/tracing/events/kprobes/ret_" + kfunc.name + "/enable"
	if err := ioutil.WriteFile(file, []byte(msg), 0644); err != nil {
		return err
	}

	return nil
}

func (myftrace *Ftracer) initKProbes() {
	eventfd, err := os.OpenFile(keventPath, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.FatalS(err, "EventReader")
	}

	defer eventfd.Close()

	myftrace.tracedFuncs = make(map[string]*kProbe)

	for i := 0; i < len(kprobes); i++ {
		if err := kprobes[i].enable(eventfd, myftrace.cookie); err != nil {
			if kprobes[i].optional == true {
				log.ErrorS(err, "EventReader")
				continue
			}
			log.FatalS(err, "EventReader")
		}
		if err := kprobes[i].action(start); err != nil {
			if kprobes[i].optional == true {
				log.ErrorS(err, "EventReader")
				continue
			}
			log.FatalS(err, "EventReader")
		}

		log.DebugS("Ftrace: Added - "+kprobes[i].name, "EventReader")
		myftrace.tracedFuncs[kprobes[i].name] = &kprobes[i]
	}
}
