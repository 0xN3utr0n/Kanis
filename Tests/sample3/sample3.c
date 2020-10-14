#include <stdio.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <stdlib.h>

void 
two_way_tracing() 
{
	if (fork() == 0) {
		pid_t pid = fork();
		if (!pid) {
			pid = getppid();
		} 
		ptrace(PTRACE_SEIZE, pid, 0 ,0);
		sleep(3);
		exit(1);	
	}
}


void 
traceme() 
{
	ptrace(PTRACE_TRACEME, 0, 0, 0);
	sleep(3);
}

int 
main() 
{
	two_way_tracing();
	sleep(1);
	traceme();
}
