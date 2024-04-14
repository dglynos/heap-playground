#ifndef UTIL_H
#define UTIL_H 1

#ifdef DEBUG

#define DPRINTF(...) do { \
	fprintf(stderr, ##__VA_ARGS__); \
} while(0)

#else

#define DPRINTF(...)

#endif /* DEBUG */


#endif
