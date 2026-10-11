#include <stddef.h>

extern void *memcpy(void *destination, const void *source, size_t length);

#include "semantic_observe.h"

struct buffer_state {
    unsigned int length;
    unsigned char bytes[32];
};

void consume_length(struct buffer_state *state, const void *payload)
{
    if (state->length > sizeof(state->bytes))
        return;
    memcpy(state->bytes, payload, state->length);
}
