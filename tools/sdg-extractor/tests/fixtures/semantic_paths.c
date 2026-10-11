#include <stddef.h>
#include <stdint.h>

extern unsigned char readb(const volatile void *address);
extern unsigned short readw(const volatile void *address);
extern unsigned short ioread16be(const volatile void *address);
extern unsigned int readl(const volatile void *address);
extern void *memcpy(void *destination, const void *source, size_t length);
extern void *kmalloc(size_t length);
extern unsigned int observe_index(unsigned int index);
extern void *ioremap(unsigned long address, size_t size);
extern void writel(unsigned int value, volatile void *address);
extern void *allocate_region(size_t size) __attribute__((alloc_size(1)));
extern void release_region(void *pointer);

#include "semantic_observe.h"

#ifndef SDG_OBSERVE_INDEX
#define SDG_OBSERVE_INDEX(index) (index)
#endif

#define SMALLER(first, second) ({ \
    unsigned int first_value = (first); \
    unsigned int second_value = (second); \
    first_value < second_value ? first_value : second_value; \
})

#define READ_PAIR(address) \
    (({ unsigned int value = readb((address) + 0x60); value; }) + \
     ({ unsigned int value = readb((address) + 0x64); value; }))

struct buffer_state {
    unsigned int length;
    unsigned char bytes[32];
};

extern void consume_length(struct buffer_state *state, const void *payload);

void guarded_copy(void *registers, const void *payload)
{
    unsigned int flags = readl(registers + 0x10);
    unsigned int length = readb(registers + 0x40);
    unsigned char buffer[32];
    if (!(flags & 4) || length > sizeof(buffer))
        return;
    memcpy(buffer, payload, length);
}

void false_branch(void *registers, const void *payload)
{
    unsigned int length = readb(registers + 0x41);
    unsigned char buffer[32];
    if (length > sizeof(buffer))
        return;
    memcpy(buffer, payload, length);
}

void transformed_copy(void *registers, const void *payload)
{
    unsigned int length = readb(registers + 0x42);
    unsigned char buffer[32];
    if (length < 2 || length > sizeof(buffer) + 2)
        return;
    memcpy(buffer, payload, length - 2);
}

void clamped_copy(void *registers, const void *payload)
{
    unsigned int length = readb(registers + 0x43);
    unsigned char buffer[32];
    length = SMALLER(length, sizeof(buffer));
    memcpy(buffer, payload, length);
}

void separate_instances(void *registers, const void *payload)
{
    struct buffer_state first = {0};
    struct buffer_state second = {0};
    first.length = readb(registers + 0x44);
    second.length = 7;
    consume_length(&first, payload);
    consume_length(&second, payload);
}

void unrelated_comparison(void *registers, const void *payload, unsigned int other)
{
    unsigned int length = readb(registers + 0x45);
    unsigned char buffer[32];
    if (other > 73)
        other = 0;
    if (length > sizeof(buffer))
        return;
    memcpy(buffer, payload, length);
}

void impossible_target(void *registers, const void *payload)
{
    unsigned char length = readb(registers + 0x46);
    unsigned char buffer[256];
    if (length > 256)
        memcpy(buffer, payload, length);
}

void reversed_comparison(void *registers, const void *payload)
{
    unsigned int length = readb(registers + 0x47);
    unsigned char buffer[32];
    if (32 < length)
        return;
    memcpy(buffer, payload, length);
}

void alternatives(void *registers, const void *payload)
{
    unsigned int flags = readl(registers + 0x14);
    unsigned int length = readb(registers + 0x48);
    unsigned char buffer[32];
    if ((flags & 2) || (flags & 8)) {
        if (length <= sizeof(buffer))
            memcpy(buffer, payload, length);
    }
}

void zero_exit(void *registers)
{
    unsigned int count = readb(registers + 0x49);
    if (count == 0)
        return;
    kmalloc(count);
}

void overwrite_same_instance(void *registers, const void *payload)
{
    struct buffer_state state = {0};
    state.length = readb(registers + 0x4a);
    state.length = 7;
    consume_length(&state, payload);
}

void short_circuit(void *registers, const void *payload)
{
    unsigned int length = readb(registers + 0x4b);
    unsigned char buffer[32];
    if ((length == 0 || 16 / length > 0) && length <= sizeof(buffer))
        memcpy(buffer, payload, length);
}

void conditional_transform(void *registers, const void *payload)
{
    unsigned int length = readb(registers + 0x4c);
    unsigned char buffer[32];
    memcpy(buffer, payload, length ? 16 / length : 0);
}

void narrowing(void *registers, const void *payload)
{
    unsigned int length = readl(registers + 0x50);
    unsigned char narrowed = length;
    unsigned char buffer[32];
    if (narrowed <= sizeof(buffer))
        memcpy(buffer, payload, narrowed);
}

void signed_comparison(void *registers, const void *payload)
{
    signed char length = readb(registers + 0x54);
    unsigned char buffer[32];
    if (length >= 0 && length <= sizeof(buffer))
        memcpy(buffer, payload, length);
}

void macro_scopes(void *registers, const void *payload)
{
    unsigned int length = READ_PAIR(registers);
    unsigned char buffer[32];
    if (length <= sizeof(buffer))
        memcpy(buffer, payload, length);
}

void optional_exit(void *registers, const void *payload)
{
    unsigned int flags = readl(registers + 0x68);
    unsigned int length = readb(registers + 0x6c);
    unsigned char buffer[32];
    if (flags & 1) {
        if (length > 16)
            goto failure;
    }
    if (__builtin_expect(length > sizeof(buffer), 0))
        return;
    memcpy(buffer, payload, length);
failure:
    return;
}

int successful_return(void *registers, const void *payload)
{
    unsigned int flags = readl(registers + 0x70);
    unsigned char buffer[32];
    if (!flags)
        return -1;
    if (flags & 1) {
        unsigned int length = readb(registers + 0x74);
        if (length <= sizeof(buffer))
            memcpy(buffer, payload, length);
    }
    return 0;
}

void optional_loop(void *registers, const void *payload)
{
    unsigned int flags = readl(registers + 0x78);
    unsigned int length = readb(registers + 0x7c);
    unsigned int index;
    volatile unsigned int progress = 0;
    unsigned char buffer[32];
    if (!(flags & 1))
        return;
    if (flags & 1) {
        for (index = 0; index < length; index++)
            progress++;
        if (length > 16)
            return;
    }
    memcpy(buffer, payload, length);
}

void constant_field_guard(void *registers, const void *payload)
{
    struct buffer_state first;
    struct buffer_state second;
    unsigned int length = readb(registers + 0x80);
    first.length = 16;
    second.length = 32;
    if (!second.length || length > first.length)
        return;
    memcpy(first.bytes, payload, length);
}

void conditional_store(void *registers, const void *payload, unsigned int replacement)
{
    unsigned int length = readb(registers + 0x84);
    unsigned char buffer[32];
    if (replacement)
        length = 4;
    if (length <= sizeof(buffer))
        memcpy(buffer, payload, length);
}

void loop_update(void *registers, const void *payload, unsigned int repeat)
{
    unsigned int length = readb(registers + 0x8c);
    unsigned char buffer[32];
    while (repeat) {
        length += 2;
        repeat--;
    }
    if (length <= sizeof(buffer))
        memcpy(buffer, payload, length);
}

void checked_replacement(void *registers, const void *payload)
{
    unsigned int length = readb(registers + 0x94);
    unsigned char buffer[32];
    if (length > 16)
        length = 16;
    memcpy(buffer, payload, length);
}

void swapped_length(void *registers, const void *payload)
{
    unsigned int length = __builtin_bswap16(readw(registers + 0x98));
    unsigned char buffer[32];
    if (length <= sizeof(buffer))
        memcpy(buffer, payload, length);
}

void big_endian_length(void *registers, const void *payload)
{
    unsigned int length = ioread16be(registers + 0x9c);
    unsigned char buffer[32];
    if (length <= sizeof(buffer))
        memcpy(buffer, payload, length);
}

void control_only_copy(void *registers, const void *payload)
{
    unsigned int flags = readl(registers + 0xa0);
    unsigned char buffer[32];
    if ((flags & 8) && !(flags & 16))
        memcpy(buffer, payload, 16);
}

static unsigned int bounded_result(unsigned int value)
{
    if (value > 16)
        return 16;
    return value;
}

void multiple_returns(void *registers, const void *payload)
{
    unsigned int length = bounded_result(readb(registers + 0xa4));
    unsigned char buffer[32];
    memcpy(buffer, payload, length);
}

void separate_array_cells(void *registers, const void *payload)
{
    unsigned int values[2];
    unsigned char buffer[32];
    values[0] = readb(registers + 0xa8);
    values[1] = 7;
    if (values[SDG_OBSERVE_INDEX(0)] > sizeof(buffer) || values[SDG_OBSERVE_INDEX(1)] != 7)
        return;
    memcpy(buffer, payload, values[SDG_OBSERVE_INDEX(0)]);
}

void overwritten_array_cell(void *registers, const void *payload)
{
    unsigned int values[2];
    unsigned char buffer[32];
    values[0] = readb(registers + 0xac);
    values[0] = 7;
    memcpy(buffer, payload, values[0]);
}

void indirect_value_store(void *registers, const void *payload)
{
    unsigned int value;
    unsigned int *stored = &value;
    unsigned char buffer[32];
    *stored = readb(registers + 0xb0);
    if (*stored <= sizeof(buffer))
        memcpy(buffer, payload, *stored);
}

static unsigned int add_checked(unsigned int value, unsigned int addition)
{
    return value + addition;
}

void repeated_invocation(void *registers, const void *payload)
{
    unsigned int length = readb(registers + 0xb4);
    unsigned char buffer[32];
    unsigned int first = add_checked(length, 1);
    unsigned int second = add_checked(length, 3);
    if (first + second - length <= sizeof(buffer))
        memcpy(buffer, payload, first + second - length);
}

void nested_invocation(void *registers, const void *payload)
{
    unsigned int length = readb(registers + 0xb8);
    unsigned char buffer[32];
    unsigned int result = add_checked(add_checked(length, 1), 2);
    if (result <= sizeof(buffer))
        memcpy(buffer, payload, result);
}

static int matching_position(const unsigned char *first, const unsigned char *second)
{
    return first + 4 == second;
}

void pointer_condition(void *registers, const void *payload)
{
    unsigned int length = readb(registers + 0xbc);
    unsigned char buffer[32];
    if (matching_position(buffer, buffer + 4) && length <= sizeof(buffer))
        memcpy(buffer, payload, length);
}

static int absolute_length(int value)
{
    if (value < 0)
        return -value;
    return value;
}

void signed_negation(void *registers, const void *payload)
{
    int length = absolute_length((signed char)readb(registers + 0xc0));
    unsigned char buffer[32];
    if (length <= (int)sizeof(buffer))
        memcpy(buffer, payload, length);
}

static unsigned int read_slot(void *address)
{
    return readb(address);
}

void separate_observations(void *registers, const void *payload)
{
    unsigned int first = read_slot(registers + 0xc4);
    unsigned int second = read_slot(registers + 0xc8);
    unsigned char buffer[32];
    if (first + second <= sizeof(buffer))
        memcpy(buffer, payload, first + second);
}

void infeasible_taint_branch(void *registers, const void *payload)
{
    unsigned int length = readb(registers + 0xcc);
    unsigned char buffer[256];
    unsigned int bounded = length < 256 ? length : 256;
    memcpy(buffer, payload, bounded);
}

static unsigned int optional_result(unsigned int value, unsigned int enabled)
{
    if (enabled) {
        if (value > 16)
            return 16;
    }
    return value;
}

void inactive_return_branch(void *registers, const void *payload)
{
    unsigned int length = optional_result(readb(registers + 0xd0), 0);
    unsigned char buffer[32];
    if (length <= sizeof(buffer))
        memcpy(buffer, payload, length);
}

struct anonymous_state {
    union {
        struct {
            unsigned int length;
        };
        unsigned int word;
    };
};

void anonymous_member(void *registers, const void *payload)
{
    struct anonymous_state state;
    unsigned char buffer[32];
    state.length = readb(registers + 0xd4);
    if (state.length <= sizeof(buffer))
        memcpy(buffer, payload, state.length);
}

void omitted_conditional_operand(void *registers, const void *payload)
{
    struct buffer_state first = {0};
    struct buffer_state *selected = &first;
    unsigned char buffer[32];
    first.length = readb(registers + 0xd8);
    selected = selected ?: &first;
    if (selected->length <= sizeof(buffer))
        memcpy(buffer, payload, selected->length);
}

void mapped_window(void *registers, const void *payload)
{
    unsigned char *window = ioremap((unsigned long)registers, 512);
    unsigned char *subregion = window + 8;
    unsigned int length = readb(subregion + 0xdc);
    unsigned char buffer[32];
    if (length <= sizeof(buffer))
        memcpy(buffer, payload, length);
}

static unsigned int unchanged_length(unsigned int length)
{
    return length;
}

static unsigned int optional_call(unsigned int length, unsigned int enabled)
{
    if (enabled)
        return unchanged_length(length);
    return length;
}

void inactive_call_branch(void *registers, const void *payload)
{
    unsigned int length = optional_call(readb(registers + 0xe8), 0);
    unsigned char buffer[32];
    if (length <= sizeof(buffer))
        memcpy(buffer, payload, length);
}

static unsigned int saved_length(unsigned int length)
{
    struct buffer_state state;
    state.length = length;
    return state.length + 1;
}

void repeated_store_invocation(void *registers, const void *payload)
{
    unsigned int first = saved_length(readb(registers + 0xec));
    unsigned int second = saved_length(4);
    unsigned char buffer[32];
    if (first + second <= sizeof(buffer))
        memcpy(buffer, payload, first + second);
}

void selected_window(void *registers, const void *payload)
{
    unsigned char *window = ioremap((unsigned long)registers, 512);
    unsigned char buffer[32];
    writel(1, window + 0x20);
    unsigned int first = readb(window + 0x24);
    writel(0, window + 0x20);
    unsigned int second = readb(window + 0x24);
    if (first + second <= sizeof(buffer))
        memcpy(buffer, payload, first + second);
}

void signed_wrap_addition(void *registers, const void *payload)
{
    int value = (int)readl(registers + 0xf0);
    unsigned char buffer[32];
    if (value + 1 < value)
        memcpy(buffer, payload, 16);
}

void signed_wrap_subtraction(void *registers, const void *payload)
{
    int value = (int)readl(registers + 0xf4);
    unsigned char buffer[32];
    if (value - 1 > value)
        memcpy(buffer, payload, 16);
}

void signed_wrap_product(void *registers, const void *payload)
{
    int value = (int)readl(registers + 0xf8);
    unsigned char buffer[32];
    if (value > 0 && value * 2 < 0)
        memcpy(buffer, payload, 16);
}

void signed_wrap_negation(void *registers, const void *payload)
{
    int value = (int)readl(registers + 0xfc);
    unsigned char buffer[32];
    if (value < 0 && -value == value)
        memcpy(buffer, payload, 16);
}

struct register_window {
    unsigned char *base;
};

void selected_field_window(void *registers, const void *payload)
{
    struct register_window storage = {registers};
    struct register_window other_storage = {registers + 0x100};
    struct register_window *device = &storage;
    struct register_window *other = &other_storage;
    unsigned char buffer[32];
    writel(3, other->base + 0x20);
    writel(1, device->base + 0x20);
    unsigned int first = readb(device->base + 0x24);
    writel(0, device->base + 0x20);
    unsigned int second = readb(device->base + 0x24);
    if (first + second <= sizeof(buffer))
        memcpy(buffer, payload, first + second);
}

void replaced_window(void *registers, const void *payload)
{
    struct register_window storage = {registers + 0x100};
    struct register_window *device = &storage;
    unsigned char buffer[32];
    writel(3, device->base + 0x20);
    device->base = registers;
    unsigned int length = readb(device->base + 0x28);
    if (length <= sizeof(buffer))
        memcpy(buffer, payload, length);
}

void copied_window(void *registers, const void *payload)
{
    struct register_window storage = {registers + 0x100};
    struct register_window *device = &storage;
    unsigned char buffer[32];
    writel(3, device->base + 0x20);
    *device = (struct register_window){registers};
    unsigned int length = readb(device->base + 0x28);
    if (length <= sizeof(buffer))
        memcpy(buffer, payload, length);
}

void pointer_destination(void *registers, const void *payload)
{
    unsigned char buffer[32];
    unsigned int offset = readb(registers + 0x100);
    if (offset + 4 <= sizeof(buffer))
        memcpy(buffer + offset, payload, 4);
}

void pointer_source(void *registers, const void *payload)
{
    unsigned char buffer[32] = {0};
    unsigned char destination[32];
    unsigned int offset = readb(registers + 0x104);
    if (offset + 4 <= sizeof(buffer))
        memcpy(destination, buffer + offset, 4);
}

void pointer_stride(void *registers, const void *payload)
{
    unsigned int buffer[16];
    unsigned int offset = readb(registers + 0x108);
    if (offset < 15)
        memcpy(buffer + offset, payload, 2 * sizeof(*buffer));
}

struct pointer_record {
    unsigned int prefix;
    unsigned char bytes[28];
};

void pointer_field(void *registers, const void *payload)
{
    struct pointer_record buffer;
    unsigned int offset = readb(registers + 0x10c);
    if (offset + 4 <= sizeof(buffer.bytes))
        memcpy(buffer.bytes + offset, payload, 4);
}

static unsigned char *advance_pointer(unsigned char *buffer, unsigned int offset)
{
    return buffer + offset;
}

void pointer_helper(void *registers, const void *payload)
{
    unsigned char buffer[32];
    unsigned int offset = readb(registers + 0x110);
    if (offset + 4 <= sizeof(buffer))
        memcpy(advance_pointer(buffer, offset), payload, 4);
}

void pointer_allocated(void *registers, const void *payload)
{
    unsigned int size = readb(registers + 0x114);
    unsigned int offset = readb(registers + 0x118);
    if (size < 8 || size > 64)
        return;
    unsigned char *buffer = allocate_region(size);
    if (!buffer)
        return;
    if (offset + 4 <= size)
        memcpy(buffer + offset, payload, 4);
    release_region(buffer);
}

static unsigned int replace_parameter(unsigned int length)
{
    length = length + 3;
    return length;
}

static unsigned int conditionally_replace_parameter(unsigned int length, unsigned int enabled)
{
    if (enabled)
        length = 8;
    return length;
}

void parameter_overwrite(void *registers, const void *payload)
{
    unsigned int length = replace_parameter(readb(registers + 0x11c));
    unsigned char buffer[32];
    if (length <= sizeof(buffer))
        memcpy(buffer, payload, length);
}

void parameter_alternative(void *registers, const void *payload)
{
    unsigned int length = conditionally_replace_parameter(readb(registers + 0x120), 0);
    unsigned char buffer[32];
    if (length <= sizeof(buffer))
        memcpy(buffer, payload, length);
}

void inconsistent_parameter(void *registers, const void *payload, unsigned int limit)
{
    unsigned int length = readb(registers + 0x124);
    unsigned char buffer[32];
    if (limit > 4 && limit < 2 && length <= sizeof(buffer))
        memcpy(buffer, payload, length);
}

void pointer_sparse_offset(void *registers, const void *payload)
{
    unsigned char buffer[32];
    unsigned int offset = 4 * readb(registers + 0x128) + 2;
    if (offset + 4 <= sizeof(buffer))
        memcpy(buffer + offset, payload, 4);
}

static void assign_pointer(unsigned char **output, unsigned char *buffer, unsigned int offset)
{
    *output = buffer + offset;
}

void pointer_out_parameter(void *registers, const void *payload)
{
    unsigned char buffer[32];
    unsigned char *pointer = 0;
    unsigned int offset = readb(registers + 0x12c);
    if (offset + 4 > sizeof(buffer))
        return;
    assign_pointer(&pointer, buffer, offset);
    memcpy(pointer, payload, 4);
}

static unsigned char *choose_region(unsigned char *first, unsigned char *second, unsigned int selector)
{
    if (selector)
        return first + 1;
    return second + 5;
}

void guarded_pointer_return(void *registers, const void *payload)
{
    unsigned char first[32], second[32];
    unsigned int selector = readb(registers + 0x130);
    memcpy(choose_region(first, second, selector), payload, 1);
}

void guarded_pointer_select(void *registers, const void *payload)
{
    unsigned char first[32], second[32];
    unsigned int selector = readb(registers + 0x134);
    unsigned char *target = selector ? first + 1 : second + 5;
    memcpy(target, payload, 1);
}

static void choose_length(unsigned int *output, unsigned int value)
{
    if (value < 8)
        *output = value + 1;
    else
        *output = 8;
}

void guarded_output_parameter(void *registers, const void *payload)
{
    unsigned char buffer[32];
    unsigned int value = readb(registers + 0x138);
    unsigned int length;
    choose_length(&length, value);
    memcpy(buffer, payload, length);
}

void guarded_pointer_null(void *registers, const void *payload)
{
    unsigned char buffer[32];
    unsigned int selector = readb(registers + 0x13c);
    unsigned char *target = selector ? buffer + 1 : 0;
    if (target)
        memcpy(target, payload, 1);
}
