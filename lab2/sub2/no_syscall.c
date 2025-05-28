const char *msg = "Hello world!\n";
const int len = 13;

void _start(void) {
    	asm volatile (
        	"mov w8, #64\n"
       		"mov x0, #1\n"
        	"mov x1, %0\n"
        	"mov x2, %1\n"
        	"svc #0\n"

        	:
        	: "r"(msg), "r"(len)
        	: "x0", "x1", "x2", "w8"
    	);
}
