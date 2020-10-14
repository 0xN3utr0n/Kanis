# Kanis
Kanis is an advanced threat detection solution exclusively designed for Linux with performance and simplicity in mind. Runs locally "out-of-the-box" (even on ancient systems) along with a powerful engine, mainly based on heuristic and behavioral analysis, for event and anomaly correlation.

### Features
- Real-time binary monitoring.
- Container monitoring (_In progress_).
- Kernel event monitoring.
- ELF Viruses/Trojans detection.
- ELF anti-debugging techniques detection.
- Process injection detection.
- Rootkits detection (_In progress_).
- And much more... :)

### How it works
As an event-driven software, Kanis requires real-time interaction with the kernel; this is achieved throught [ftrace](https://www.kernel.org/doc/Documentation/trace/ftrace.txt) and the use of [Kprobes](https://www.kernel.org/doc/Documentation/kprobes.txt), as well as [Tracepoints](https://www.kernel.org/doc/Documentation/trace/tracepoints.txt). That is, it can not only monitor syscalls, but any kernel function too. The rule engine is in charge of processing all this stream of information and make sense out of it. 

Additionally, Kanis includes some modules for static heuristic analysis (such as for binaries) which further enhance the product's detection capabilities.

### Requirements
```
- Linux >=3.10 x86_64
- Kernel compiled with CONFIG_FUNCTION_TRACER flag
- go >=1.14
```
### Install
```
git clone https://github.com/0xN3utr0n/Kanis && cd Kanis
make
sudo make install
```

### Usage
Kanis requires root privileges in order to properly work.
```
  -h	This help.
  -d	Show debug messages (very verbose).
  -e	Enable kernel events monitoring (very verbose).
  -s	Redirect all output to stdout.
```
Once executed, the following log files will be created (within `/var/kanis/`):
- **events.log** : Real-time kernel events.
- **kanis.log**  : Errors and Kanis related messages.
- **threats.log** : Detected threats.

### Disclaimer
The project is currently in pre-alpha state, meaning that there might be some instability issues along with low detection rates or even a high number of false-positives. 

