#include <stddef.h>

typedef int (*interrupt_handler)(int, void *);

extern int request_irq(unsigned int number, interrupt_handler handler,
                       unsigned long flags, const char *name, void *context);
extern unsigned int readl(const volatile void *address);
extern void *memcpy(void *destination, const void *source, size_t length);

#include "semantic_observe.h"

static void interrupt_copy(void *context, unsigned int length)
{
    unsigned char buffer[32];
    memcpy(buffer, context, length);
}

static int interrupt_enabled(unsigned int status)
{
    return (status & 8) != 0;
}

int first_interrupt(int number, void *context)
{
    unsigned long unused_size = sizeof(readl(context + 0x90));
    __typeof__(*(unsigned long *)context) temporary = unused_size;
    unsigned int status = readl(context + 0x88);
    if (!interrupt_enabled(status))
        return 0;
    interrupt_copy(context, 4);
    return 1;
}

int second_interrupt(int number, void *context)
{
    interrupt_copy(context, 8);
    return 1;
}

int unregistered_interrupt(int number, void *context)
{
    interrupt_copy(context, 12);
    return 1;
}

int unused_interrupt(int number, void *context)
{
    return 1;
}

int install_interrupts(void *context)
{
    if (request_irq(1, first_interrupt, 0, "first", context))
        return -1;
    if (request_irq(2, second_interrupt, 0, "second", context))
        return -1;
    return request_irq(3, unused_interrupt, 0, "unused", context);
}
