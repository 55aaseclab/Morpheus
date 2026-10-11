#include <stddef.h>

typedef unsigned long dma_addr_t;
enum dma_data_direction { DMA_BIDIRECTIONAL, DMA_TO_DEVICE, DMA_FROM_DEVICE, DMA_NONE };

extern dma_addr_t dma_map_single(void *device, void *buffer, size_t size, enum dma_data_direction direction);
extern void dma_sync_single_for_cpu(void *device, dma_addr_t address, size_t size, enum dma_data_direction direction);
extern void dma_unmap_single(void *device, dma_addr_t address, size_t size, enum dma_data_direction direction);
extern void *memcpy(void *destination, const void *source, size_t length);
extern void *dma_alloc_coherent(void *device, size_t size, dma_addr_t *handle, unsigned int flags);
extern void dma_free_coherent(void *device, size_t size, void *buffer, dma_addr_t handle);
extern void dma_rmb(void);

#include "semantic_observe.h"

struct page {
    unsigned char *address;
    unsigned long metadata;
};

extern void *page_address(struct page *page);
extern dma_addr_t dma_map_page(void *device, struct page *page, size_t offset,
                               size_t size, enum dma_data_direction direction);
extern void dma_sync_single_range_for_cpu(void *device, dma_addr_t address, size_t offset,
                                          size_t size, enum dma_data_direction direction);

struct page_pool {
    void *device;
    enum dma_data_direction direction;
    unsigned int offset;
};

static dma_addr_t page_pool_get_dma_addr(struct page *page)
{
    return (dma_addr_t)page->address;
}

static void page_pool_dma_sync_for_cpu(struct page_pool *pool, struct page *page,
                                      unsigned int offset, unsigned int size)
{
    dma_sync_single_range_for_cpu(pool->device, page_pool_get_dma_addr(page),
                                  offset + pool->offset, size, pool->direction);
}

void dma_receive(void)
{
    unsigned char buffer[64] = {0};
    unsigned char destination[32];
    dma_addr_t handle = dma_map_single(0, buffer, sizeof(buffer), DMA_FROM_DEVICE);
    dma_sync_single_for_cpu(0, handle, sizeof(buffer), DMA_FROM_DEVICE);
    unsigned int length = buffer[0];
    if (length <= 16)
        memcpy(destination, buffer + 8, length);
}

void dma_offset(void)
{
    unsigned char buffer[64] = {0};
    unsigned char destination[32];
    dma_addr_t handle = dma_map_single(0, buffer, sizeof(buffer), DMA_BIDIRECTIONAL);
    dma_sync_single_for_cpu(0, handle, sizeof(buffer), DMA_BIDIRECTIONAL);
    unsigned int length = buffer[5];
    if (length <= 16)
        memcpy(destination, buffer + 8, length);
}

struct dma_entry {
    unsigned short tag;
    unsigned char length;
};

struct dma_packet {
    unsigned int header;
    struct dma_entry entries[3];
};

void dma_nested_field(void)
{
    struct dma_packet buffer = {0};
    struct dma_packet *packet = &buffer;
    unsigned char destination[32];
    dma_addr_t handle = dma_map_single(0, &buffer, sizeof(buffer), DMA_FROM_DEVICE);
    dma_sync_single_for_cpu(0, handle, sizeof(buffer), DMA_FROM_DEVICE);
    unsigned int length = packet->entries[1].length;
    if (length <= 16)
        memcpy(destination, packet, length);
}

void dma_transmit_only(void)
{
    unsigned char buffer[64] = {7};
    unsigned char destination[32];
    dma_addr_t handle = dma_map_single(0, buffer, sizeof(buffer), DMA_TO_DEVICE);
    dma_sync_single_for_cpu(0, handle, sizeof(buffer), DMA_TO_DEVICE);
    memcpy(destination, buffer + 8, buffer[0]);
}

void dma_cpu_overwrite(void)
{
    unsigned char buffer[64] = {0};
    unsigned char destination[32];
    dma_addr_t handle = dma_map_single(0, buffer, sizeof(buffer), DMA_FROM_DEVICE);
    dma_sync_single_for_cpu(0, handle, sizeof(buffer), DMA_FROM_DEVICE);
    buffer[0] = 7;
    memcpy(destination, buffer + 8, buffer[0]);
}

void dma_unrelated_completion(void)
{
    unsigned char first[64] = {7};
    unsigned char second[64] = {0};
    unsigned char destination[32];
    dma_map_single(0, first, sizeof(first), DMA_FROM_DEVICE);
    dma_addr_t handle = dma_map_single(0, second, sizeof(second), DMA_FROM_DEVICE);
    dma_sync_single_for_cpu(0, handle, sizeof(second), DMA_FROM_DEVICE);
    memcpy(destination, first + 8, first[0]);
}

void dma_before_completion(void)
{
    unsigned char buffer[64] = {7};
    unsigned char destination[32];
    dma_addr_t handle = dma_map_single(0, buffer, sizeof(buffer), DMA_FROM_DEVICE);
    unsigned int length = buffer[0];
    dma_sync_single_for_cpu(0, handle, sizeof(buffer), DMA_FROM_DEVICE);
    memcpy(destination, buffer + 8, length);
}

void coherent_receive(void)
{
    dma_addr_t handle;
    unsigned char destination[32];
    unsigned char *buffer = dma_alloc_coherent(0, 64, &handle, 0);
    if (!buffer)
        return;
    dma_rmb();
    unsigned int length = buffer[1];
    if (length <= 16)
        memcpy(destination, buffer + 8, length);
    dma_free_coherent(0, 64, buffer, handle);
}

void coherent_cpu_field(void)
{
    dma_addr_t handle;
    unsigned char destination[32];
    unsigned char *buffer = dma_alloc_coherent(0, 64, &handle, 0);
    if (!buffer)
        return;
    buffer[0] = 7;
    dma_rmb();
    memcpy(destination, buffer + 8, buffer[0]);
    dma_free_coherent(0, 64, buffer, handle);
}

void coherent_private_memory(void)
{
    unsigned char buffer[64] = {7};
    unsigned char destination[32];
    dma_rmb();
    memcpy(destination, buffer + 8, buffer[0]);
}

void dma_page_receive(void)
{
    unsigned char buffer[64] = {0};
    unsigned char destination[32];
    struct page page = {buffer, 7};
    unsigned char *data = page_address(&page);
    dma_addr_t handle = dma_map_page(0, &page, 8, 24, DMA_FROM_DEVICE);
    dma_sync_single_for_cpu(0, handle, 24, DMA_FROM_DEVICE);
    unsigned int length = data[11];
    if (length <= 16)
        memcpy(destination, data + 16, length);
}

void dma_other_page(void)
{
    unsigned char first[64] = {7};
    unsigned char second[64] = {0};
    unsigned char destination[32];
    struct page first_page = {first, 7};
    struct page second_page = {second, 9};
    unsigned char *data = page_address(&first_page);
    dma_addr_t handle = dma_map_page(0, &second_page, 0, 64, DMA_FROM_DEVICE);
    dma_sync_single_for_cpu(0, handle, 64, DMA_FROM_DEVICE);
    memcpy(destination, data + 8, data[0]);
}

unsigned long dma_page_metadata(unsigned long metadata)
{
    unsigned char buffer[64] = {0};
    struct page page = {buffer, metadata};
    dma_addr_t handle = dma_map_page(0, &page, 0, 64, DMA_FROM_DEVICE);
    dma_sync_single_for_cpu(0, handle, 64, DMA_FROM_DEVICE);
    return page.metadata;
}

void dma_conditional_completion(unsigned int enabled)
{
    unsigned char buffer[64] = {7};
    unsigned char destination[32];
    dma_addr_t handle = dma_map_single(0, buffer, sizeof(buffer), DMA_FROM_DEVICE);
    if (enabled)
        dma_sync_single_for_cpu(0, handle, sizeof(buffer), DMA_FROM_DEVICE);
    unsigned int length = buffer[0];
    if (length <= 16)
        memcpy(destination, buffer + 8, length);
}

void dma_alternative_completion(unsigned int enabled)
{
    unsigned char buffer[64] = {7};
    unsigned char destination[32];
    dma_addr_t handle = dma_map_single(0, buffer, sizeof(buffer), DMA_FROM_DEVICE);
    if (enabled)
        dma_sync_single_for_cpu(0, handle, sizeof(buffer), DMA_FROM_DEVICE);
    else
        dma_unmap_single(0, handle, sizeof(buffer), DMA_FROM_DEVICE);
    unsigned int length = buffer[0];
    if (length <= 16)
        memcpy(destination, buffer + 8, length);
}

void dma_conditional_overwrite(unsigned int enabled)
{
    unsigned char buffer[64] = {0};
    unsigned char destination[32];
    dma_addr_t handle = dma_map_single(0, buffer, sizeof(buffer), DMA_FROM_DEVICE);
    if (enabled)
        dma_sync_single_for_cpu(0, handle, sizeof(buffer), DMA_FROM_DEVICE);
    buffer[0] = 7;
    memcpy(destination, buffer + 8, buffer[0]);
}

void page_pool_observation(struct page_pool *pool, struct page *page, unsigned int enabled)
{
    unsigned char *data = page_address(page);
    unsigned char destination[32];
    if (enabled)
        page_pool_dma_sync_for_cpu(pool, page, 8, 24);
    unsigned int length = data[11];
    if (length <= 16)
        memcpy(destination, data + 16, length);
}

void page_pool_unrelated(struct page_pool *pool, struct page *first, struct page *second)
{
    unsigned char *data = page_address(first);
    unsigned char destination[32];
    page_pool_dma_sync_for_cpu(pool, second, 0, 64);
    unsigned int length = data[0];
    if (length <= 16)
        memcpy(destination, data + 8, length);
}
