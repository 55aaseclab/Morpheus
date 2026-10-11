#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

size_t observed_length;
size_t observed_first_length;
unsigned int observed_calls;
unsigned int observed_index;
unsigned int observed_index_mask;
size_t observed_destination_remaining;
size_t observed_source_remaining;
unsigned char read_values[256];
unsigned int read_count;
unsigned int read_cursor;

unsigned int observe_index(unsigned int index)
{
    observed_index = index;
    if (index < 32)
        observed_index_mask |= 1u << index;
    return index;
}
typedef int (*interrupt_handler)(int, void *);
static interrupt_handler handlers[4];
static void *handler_contexts[4];
unsigned char device_bytes[256];
static unsigned char *coherent_region;
static size_t coherent_size;

struct page {
    unsigned char *address;
    unsigned long metadata;
};

void *page_address(struct page *page)
{
    return page->address;
}

unsigned long dma_map_page(void *device, struct page *page, size_t offset,
                           size_t size, int direction)
{
    return (unsigned long)(page->address + offset);
}

void *dma_alloc_coherent(void *device, size_t size, unsigned long *handle, unsigned int flags)
{
    coherent_region = calloc(1, size);
    coherent_size = size;
    *handle = (unsigned long)coherent_region;
    return coherent_region;
}

void dma_free_coherent(void *device, size_t size, void *buffer, unsigned long handle)
{
    free(buffer);
    coherent_region = 0;
    coherent_size = 0;
}

void dma_rmb(void)
{
    for (size_t index = 1; index < coherent_size && index < sizeof(device_bytes); index++)
        coherent_region[index] = device_bytes[index];
}

unsigned long dma_map_single(void *device, void *buffer, size_t size, int direction)
{
    return (unsigned long)buffer;
}

void dma_sync_single_for_cpu(void *device, unsigned long address, size_t size, int direction)
{
    unsigned char *buffer = (unsigned char *)address;
    if (direction == 0 || direction == 2) {
        for (size_t index = 0; index < size && index < sizeof(device_bytes); index++)
            buffer[index] = device_bytes[index];
    }
}

void dma_unmap_single(void *device, unsigned long address, size_t size, int direction)
{
    dma_sync_single_for_cpu(device, address, size, direction);
}

void dma_sync_single_range_for_cpu(void *device, unsigned long address, size_t offset,
                                   size_t size, int direction)
{
    dma_sync_single_for_cpu(device, address + offset, size, direction);
}

int request_irq(unsigned int number, interrupt_handler handler,
                unsigned long flags, const char *name, void *context)
{
    if (number >= 4)
        return -1;
    handlers[number] = handler;
    handler_contexts[number] = context;
    return 0;
}

int dispatch_irq(unsigned int number)
{
    if (number >= 4 || !handlers[number])
        return -1;
    return handlers[number](number, handler_contexts[number]);
}

unsigned char readb(const volatile void *address)
{
    if (read_cursor < read_count)
        return read_values[read_cursor++];
    return *(const volatile unsigned char *)address;
}

void writel(unsigned int value, volatile void *address)
{
    *(volatile unsigned int *)address = value;
}

unsigned short readw(const volatile void *address)
{
    const volatile unsigned char *bytes = address;
    return bytes[0] | ((unsigned short)bytes[1] << 8);
}

unsigned short ioread16be(const volatile void *address)
{
    const volatile unsigned char *bytes = address;
    return ((unsigned short)bytes[0] << 8) | bytes[1];
}

unsigned int readl(const volatile void *address)
{
    const volatile unsigned char *bytes = address;
    return bytes[0] | ((unsigned int)bytes[1] << 8) |
           ((unsigned int)bytes[2] << 16) | ((unsigned int)bytes[3] << 24);
}

void *memcpy(void *destination, const void *source, size_t length)
{
    unsigned char *output = destination;
    const unsigned char *input = source;
    if (observed_calls == 0)
        observed_first_length = length;
    observed_length = length;
    observed_calls++;
    for (size_t index = 0; index < length; index++)
        output[index] = input[index];
    return destination;
}

void *observe_memcpy(void *destination, const void *source, size_t length,
                     size_t destination_remaining, size_t source_remaining)
{
    if (observed_calls == 0) {
        observed_destination_remaining = destination_remaining;
        observed_source_remaining = source_remaining;
    }
    return memcpy(destination, source, length);
}

void *kmalloc(size_t length)
{
    if (observed_calls == 0)
        observed_first_length = length;
    observed_length = length;
    observed_calls++;
    return (void *)0;
}

void *ioremap(unsigned long address, size_t size)
{
    return (void *)address;
}

void *allocate_region(size_t size)
{
    return calloc(1, size);
}

void release_region(void *pointer)
{
    free(pointer);
}
