#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

// gcc -static -o tests-samples/test5/test5 tests-samples/test5/test5.c

static int tracer = 0;

void 
sighandler(int sig)
{
    tracer++;
}

int 
detect_debugger()
{   
    struct sigaction new_action = {0};

    new_action.sa_handler = sighandler;
    sigaction(SIGTRAP, &new_action, NULL);

    __asm__ volatile("int3");

    if (tracer == 0) {
        printf("There is a debugger attached!\n");
        exit(1);
    }
}

int 
main() 
{
    detect_debugger();
    sleep(1);
}