#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <fcntl.h>

#define STACK_SIZE (1 * 1024)

void func(int counter) {
    char array[12] = "hello world";
    if (counter < 10) {
        func(counter + 1);
    }
}

int child(void *arg) {
    func(0);
    return 0;
}

int main() {
    int fd;
    void *stack_base;
    void *stack_top;

    fd = open("stack_file", O_RDWR | O_CREAT | O_TRUNC, 0666);
    if (fd == -1) {
        perror("open");
        exit(1);
    }

    if (ftruncate(fd, STACK_SIZE) == -1) {
        perror("ftruncate");
        close(fd);
        exit(2);
    }

    stack_base = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (stack_base == MAP_FAILED) {
        perror("mmap");
        close(fd);
        exit(3);
    }

    stack_top = stack_base + STACK_SIZE;

    int flags = SIGCHLD;
    int cpid = clone(child, stack_top, flags, NULL);
    if (cpid == -1) {
        perror("clone");
        munmap(stack_base, STACK_SIZE);
        close(fd);
        exit(4);
    }

    if (waitpid(cpid, NULL, 0) == -1) {
        perror("waitpid");
    }

    munmap(stack_base, STACK_SIZE);
    close(fd);

    return 0;
}
