#include <stdio.h>
#include <unistd.h>

int main(void) {
	printf("Hello world from pid %d!\n", getpid());
	sleep(20);
	return 0;
}
