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

type information struct {
	description string
	ioc         string
}

var threats = map[string]information{
	"Execution Flow Hijacking": information{
		description: "Malicious payloads can be executed by hijacking/infecting the control flow of a benign binary. Common technique among parasites, viruses and troyans.",
		ioc:         "Executable File",
	},
	"Software Packing": information{
		description: "It's a method of compressing or encrypting an executable in order to conceal its code.",
		ioc:         "Packed Executable File",
	},
	"Executable Deletion": information{
		description: "Malicious process may delete its own executable file in order to minimize its footprint.",
		ioc:         "Executable File",
	},
	"Kernel Thread Masquerading": information{
		description: "Occurs when a malicious executable masquerades its name as a kernel thread in order to make it appear legitimate.",
		ioc:         "Executable File",
	},
	"Space After Filename Masquerading": information{
		description: "An executable's true filetype can be hidden by changing its extension and appending a space at the end of the filename.",
		ioc:         "Executable File",
	},
	"Process Injection": information{
		description: "It's a method of executing arbitrary code in the address space of a separate live process.",
		ioc:         "Target's PID",
	},
	"Traceme Protection": information{
		description: "Commonly used as an anti-debugging technique in which a malicious process forces its parent to trace him.",
		ioc:         "Tracer's PID",
	},
	"Self-Tracing Protection": information{
		description: "Anti-debugging technique in which the malicious process traces itself.",
		ioc:         "Tracer's PID",
	},
	"Two-Way-Tracing Protection": information{
		description: "Anti-debugging technique in which two related processes trace each other. Usual indicator of Nanomites technique.",
		ioc:         "Tracer's PID",
	},
	"SIGTRAP-Handler Protection": information{
		description: "Anti-debugging technique in which the malicious process sets up a signal handler to catch SIGTRAP signals issued by breakpoint instructions.",
		ioc:         "None",
	},
}
