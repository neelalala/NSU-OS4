#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int global_var = 100;

int main() {
    int local_var = 50;
   
    printf("Parent process:\n");
    
    printf("Global var address: %p, value: %d\n", &global_var, global_var);
    printf("Local var address: %p, value: %d\n", &local_var, local_var);
    
    printf("Parent process PID: %d\n", getpid());
    
    int cpid = fork();
    
    if (cpid == 0) {
        printf("\nChild process:\n");
        printf("Child process PID: %d\n", getpid());
        printf("Child process PPID: %d\n", getppid());
        
        printf("Global var address: %p, value: %d\n", &global_var, global_var);
        printf("Local var address: %p, value: %d\n", &local_var, local_var);
        
        global_var = 200;
        local_var = 100;
        printf("New global var address: %p, value: %d\n", &global_var, global_var);
        printf("New local var address: %p, value: %d\n", &local_var, local_var);
        
        printf("Check for child process maps:\n");
        printf("  cat /proc/%d/maps\n", getpid());

	sleep(15);

        printf("Child process ended with code 5\n");
        exit(5);
    } else if (cpid > 0) {
        printf("\nParent process after fork():\n");
        printf("Global var address: %p, value: %d\n", &global_var, global_var);
        printf("Local var address: %p, value: %d\n", &local_var, local_var);
        

	printf("Check for parent process state:\n");
        printf("  cat /proc/%d/status\n", getpid());

        printf("Parent process sleeps for 10 sec...\n");
        sleep(10);
	
	printf("Global var address: %p, value: %d\n", &global_var, global_var);
        printf("Local var address: %p, value: %d\n", &local_var, local_var);

	int status;
        int wpid = wait(&status);

	if (WIFEXITED(status)) {
            printf("Child process finished normally: %d\n", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("Child process finished with signal: %d\n", WTERMSIG(status));
        }

        if (wpid == -1) {
            perror("Error waiting for child process to end");
            exit(1);
        }
        
        printf("\nChild process (PID: %d) finished\n", wpid);
        
        printf("Parent process finishing...\n");
    } else {
        perror("Couldn't fork() process");
        exit(1);
    }
    
    return 0;
}
