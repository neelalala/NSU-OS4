#include <unistd.h>
#include <syscall.h>

int print(const void* buffer, int count) {
	return syscall(SYS_write, 1, buffer, count);
}

int main(void) {
	print("Hello world!\n", 13);
	return 0;
}
