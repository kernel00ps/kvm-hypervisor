#include <stddef.h>
#include <stdint.h>

#define ESC 27

static void outb(uint16_t port, uint8_t value) {
	asm("outb %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
}
static uint8_t inb(uint16_t port) {
	uint8_t ret;
	asm("inb %1,%0" : "=a" (ret) : "Nd" (port) : "memory");
	return ret;
}

void
__attribute__((noreturn))
__attribute__((section(".start")))
_start(void) {

	const char *p;
	uint16_t port = 0x0278;
	uint8_t value;

    do {
		value = inb(0xE9);
		if(value != ESC) outb(0xE9, value);
	} while(value != ESC);

	for (;;)
		asm("hlt");
}
