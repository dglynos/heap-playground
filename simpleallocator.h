#ifndef SIMPLE_ALLOCATOR_H
#define SIMPLE_ALLOCATOR_H 1

void *sa_alloc(size_t region);
void sa_free(void *ptr);
void sa_print_freelist(void);

#endif
