#include <stddef.h>
#include <stdint.h>

#define PORT_KBD 0xE9
#define PORT_FILE 0x0278
#define ESC 27

static void outb(uint16_t port, uint8_t value) {
    asm volatile ("outb %0, %1" : : "a"(value), "Nd"(port) : "memory");
}
static uint8_t inb(uint16_t port) {
    uint8_t ret;
    asm volatile ("inb %1, %0" : "=a"(ret) : "Nd"(port) : "memory");
    return ret;
}

// send a zero‐terminated C string to PORT_FILE, then send ‘|’ delimiter
static void send_filename(const char *name) {
    for (const char *p = name; *p != '\0'; ++p)
        outb(PORT_FILE, (uint8_t)*p);
    outb(PORT_FILE, (uint8_t)'|');
}

// high‐level open call
static void hv_open(const char *filename) {
    outb(PORT_FILE, (uint8_t)'o');
    send_filename(filename);
    // hypervisor does not return anything on open
}

// high‐level close call
static void hv_close(const char *filename) {
    outb(PORT_FILE, (uint8_t)'c');
    send_filename(filename);
    // no IN expected on close
}

// high‐level WR call (1 byte)
// returns 0 on success (ignoring the IN result in practice)
static void hv_write(const char *filename, uint8_t data) {
    outb(PORT_FILE, (uint8_t)'w');
    send_filename(filename);
    // send the data byte
    outb(PORT_FILE, data);
    // hypervisor will respond via IN (read and discard)
    (void)inb(PORT_FILE);
}

// high‐level RD call (1 byte)
// returns the file byte (or 0 if EOF)
static uint8_t hv_read(const char *filename) {
    outb(PORT_FILE, (uint8_t)'r');
    send_filename(filename);
    // hypervisor immediately returns one byte via IN
    return inb(PORT_FILE);
}

void __attribute__((noreturn))
__attribute__((section(".start")))
_start(void)
{
    const char *fname = "foo.txt";

    // open “foo.txt” (creates if missing)
    hv_open(fname);

    // write ASCII “Hello\n” to foo.txt
    const char *msg = "Hello\n";
    for (const char *c = msg; *c != '\0'; ++c)
        hv_write(fname, (uint8_t)*c);

    // reset file offset to beginning—close and re‐open
    hv_close(fname);
    hv_open(fname);

    // read back and echo to port 0xE9
    uint8_t ch;
    do {
        ch = hv_read(fname);
        if (ch != 0) {
            outb(PORT_KBD, ch);
        }
    } while (ch != 0);

    // close the file and halt
    hv_close(fname);

    for (;;) {
        asm ("hlt");
    }
}
