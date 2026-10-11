#ifdef SDG_OBSERVE_ACCESS
extern void *observe_memcpy(void *destination, const void *source, size_t length,
                            size_t destination_remaining, size_t source_remaining);
#define memcpy(destination, source, length) ({ \
    __auto_type observed_destination = (destination); \
    __auto_type observed_source = (source); \
    size_t observed_count = (length); \
    observe_memcpy(observed_destination, observed_source, observed_count, \
        __builtin_dynamic_object_size(observed_destination, 1), \
        __builtin_dynamic_object_size(observed_source, 1)); \
})
#endif
