#include <stdio.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <stdlib.h>

int 
main() 
{
    system("cp ./sample4.bin ./temp");
    // unlink("sample4");  Easier to detect...
    system("rm ./sample4.bin");
    system("mv ./temp ./sample4.bin");
    sleep(1);
}