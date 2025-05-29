#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int main() {
    int cpid = fork();
    
    if (cpid == 0) {
        printf("Child process (PID: %d) forked, PPID: %d\n", getpid(), getppid());
        printf("Child process finished\n");
        exit(5);
    } else if (cpid > 0) {
        printf("Parent process (PID: %d) fork child process (PID: %d)\n", getpid(), cpid);
        
        printf("Parent process sleeps for 60 seconds...\n");
        printf("Check for child process state:\n");
        printf("  cat /proc/%d/status\n", cpid);

        sleep(20);

	int wpid;
	wait(&wpid);
	printf("Check for child status again\n");
        sleep(20);
        printf("Parent process finihed\n");
    } else {
	perror("Error while fork()");
        exit(1);
    }
    
    return 0;
}
