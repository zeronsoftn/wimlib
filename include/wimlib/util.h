/*
 * util.h - utility functions and macros
 */
#ifndef _WIMLIB_UTIL_H
#define _WIMLIB_UTIL_H

#include "common_defs.h"

/****************
 * General macros
 *****************/

/* Maximum number of bytes that can be allocated on the stack.
 *
 * Note: this isn't a hard bound on the stack space used, since this is just for
 * individual arrays.  The full call stack could use more than this.  */
#define STACK_MAX 32768

/* Default size of file I/O buffer.  Currently assumed to be <= STACK_MAX.  */
#define BUFFER_SIZE 32768

/*******************
 * Memory allocation
 *******************/

void *
wimlib_malloc(size_t size);

void
wimlib_free_memory(void *p);

void *
wimlib_realloc(void *ptr, size_t size);

void *
wimlib_calloc(size_t nmemb, size_t size);

char *
wimlib_strdup(const char *str);

#ifdef _WIN32
wchar_t *
wimlib_wcsdup(const wchar_t *str);
#endif

void *
wimlib_aligned_malloc(size_t size, size_t alignment);

void
wimlib_aligned_free(void *ptr);

void *
memdup(const void *mem, size_t size);

#define MALLOC		wimlib_malloc
#define FREE		wimlib_free_memory
#define REALLOC		wimlib_realloc
#define CALLOC		wimlib_calloc
#define STRDUP		wimlib_strdup
#define WCSDUP		wimlib_wcsdup
#define ALIGNED_MALLOC	wimlib_aligned_malloc
#define ALIGNED_FREE	wimlib_aligned_free

/*******************
 * String utilities
 *******************/

#ifndef HAVE_MEMPCPY
void *
mempcpy(void *dst, const void *src, size_t n);
#endif

/**************************
 * Random number generation
 **************************/

void
get_random_bytes(void *p, size_t n);

void
get_random_alnum_chars(tchar *p, size_t n);

/************************
 * Hashing and comparison
 ************************/

static inline bool
is_power_of_2(unsigned long n)
{
	return (n != 0 && (n & (n - 1)) == 0);

}

static inline u64
hash_u64(u64 n)
{
	return n * 0x9e37fffffffc0001ULL;
}

static inline int
cmp_u32(u32 n1, u32 n2)
{
	if (n1 < n2)
		return -1;
	if (n1 > n2)
		return 1;
	return 0;
}

static inline int
cmp_u64(u64 n1, u64 n2)
{
	if (n1 < n2)
		return -1;
	if (n1 > n2)
		return 1;
	return 0;
}

/************************
 * System information
 ************************/

unsigned
get_available_cpus(void);

u64
get_available_memory(void);

#endif /* _WIMLIB_UTIL_H */
