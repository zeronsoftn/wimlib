/*
 * common_defs.h
 *
 * Copyright 2022 Eric Biggers
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef _WIMLIB_COMMON_DEFS_H
#define _WIMLIB_COMMON_DEFS_H

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "wimlib.h"

/* Optional definitions for checking with 'sparse'.  */
#ifdef __CHECKER__
#  define _bitwise_attr	__attribute__((bitwise))
#  define _force_attr	__attribute__((force))
#else
#  define _bitwise_attr
#  define _force_attr
#endif

#ifndef _NTFS_TYPES_H
/* Unsigned integer types of exact size in bits */
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/* Signed integer types of exact size in bits */
typedef int8_t  s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

/* Unsigned little endian types of exact size */
typedef uint16_t _bitwise_attr le16;
typedef uint32_t _bitwise_attr le32;
typedef uint64_t _bitwise_attr le64;

/* Unsigned big endian types of exact size */
typedef uint16_t _bitwise_attr be16;
typedef uint32_t _bitwise_attr be32;
typedef uint64_t _bitwise_attr be64;
#endif /* _NTFS_TYPES_H */

/* A pointer to 'utf16lechar' indicates a UTF-16LE encoded string */
typedef le16 utf16lechar;

/*
 * Type of a machine word.  'unsigned long' would be logical, but that is only
 * 32 bits on x86_64 Windows.  The same applies to 'uint_fast32_t'.  So the best
 * we can do without a bunch of #ifdefs appears to be 'size_t'.
 */
typedef size_t machine_word_t;

#define WORDBYTES	sizeof(machine_word_t)
#define WORDBITS	(8 * WORDBYTES)

/* Is the compiler GCC of the specified version or later?  This always returns
 * false for clang, since clang is "frozen" at GNUC 4.2.  The __has_*
 * feature-test macros should be used to detect clang functionality instead.  */
#define GCC_PREREQ(major, minor)					\
	(!defined(__clang__) && !defined(__INTEL_COMPILER) &&		\
	 (__GNUC__ > major ||						\
	  (__GNUC__ == major && __GNUC_MINOR__ >= minor)))

/* Feature-test macros defined by recent versions of clang.  */
#ifndef __has_attribute
#  define __has_attribute(attribute)	0
#endif
#ifndef __has_feature
#  define __has_feature(feature)	0
#endif
#ifndef __has_builtin
#  define __has_builtin(builtin)	0
#endif

/* Declare that the annotated function should always be inlined.  This might be
 * desirable in highly tuned code, e.g. compression codecs.  */
#define forceinline		inline __attribute__((always_inline))

/* Declare that the annotated function should *not* be inlined.  */
#define noinline		__attribute__((noinline))

/* Functionally the same as 'noinline', but documents that the reason for not
 * inlining is to prevent the annotated function from being inlined into a
 * recursive function, thereby increasing its stack usage.  */
#define noinline_for_stack	noinline

/* Hint that the expression is usually true.  */
#define likely(expr)		__builtin_expect(!!(expr), 1)

/* Hint that the expression is usually false.  */
#define unlikely(expr)		__builtin_expect(!!(expr), 0)

/* Prefetch into L1 cache for read.  */
#define prefetchr(addr)		__builtin_prefetch((addr), 0)

/* Prefetch into L1 cache for write.  */
#define prefetchw(addr)		__builtin_prefetch((addr), 1)

/* Hint that the annotated function takes a printf()-like format string and
 * arguments.  This is currently disabled on Windows because MinGW does not
 * support this attribute on functions taking wide-character strings.  */
#ifdef _WIN32
#  define _format_attribute(type, format_str, format_start)
#else
#  define _format_attribute(type, format_str, format_start)	\
			__attribute__((format(type, format_str, format_start)))
#endif

/* Endianness definitions.  Either CPU_IS_BIG_ENDIAN() or CPU_IS_LITTLE_ENDIAN()
 * evaluates to 1.  The other evaluates to 0.  Note that newer gcc supports
 * __BYTE_ORDER__ for easily determining the endianness; older gcc doesn't.  In
 * the latter case we fall back to a configure-time check.  */
#ifdef __BYTE_ORDER__
#  define CPU_IS_BIG_ENDIAN()	(__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#elif defined(HAVE_CONFIG_H)
#  include "config.h"
#  ifdef WORDS_BIGENDIAN
#    define CPU_IS_BIG_ENDIAN()	1
#  else
#    define CPU_IS_BIG_ENDIAN()	0
#  endif
#endif
#define CPU_IS_LITTLE_ENDIAN() (!CPU_IS_BIG_ENDIAN())

/* UNALIGNED_ACCESS_IS_FAST should be defined to 1 if unaligned memory accesses
 * can be performed efficiently on the target platform.  */
#if defined(__x86_64__) || defined(__i386__) || \
	defined(__ARM_FEATURE_UNALIGNED) || defined(__powerpc64__)
#  define UNALIGNED_ACCESS_IS_FAST 1
#else
#  define UNALIGNED_ACCESS_IS_FAST 0
#endif

/* Get the minimum of two variables, without multiple evaluation.  */
#undef min
#define min(a, b)  ({ typeof(a) _a = (a); typeof(b) _b = (b); \
		    (_a < _b) ? _a : _b; })
#undef MIN
#define MIN(a, b)	min((a), (b))

/* Get the maximum of two variables, without multiple evaluation.  */
#undef max
#define max(a, b)  ({ typeof(a) _a = (a); typeof(b) _b = (b); \
		    (_a > _b) ? _a : _b; })
#undef MAX
#define MAX(a, b)	max((a), (b))

/* Swap the values of two variables, without multiple evaluation.  */
#ifndef swap
#  define swap(a, b) ({ typeof(a) _a = (a); (a) = (b); (b) = _a; })
#endif
#define SWAP(a, b)	swap((a), (b))

/* Cast a pointer to a struct member to a pointer to the containing struct.  */
#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))

/* Calculate 'n / d', but round up instead of down.  */
#define DIV_ROUND_UP(n, d)	(((n) + (d) - 1) / (d))

/* Calculate 'n % d', but return 'd' if the result would be 0.  */
#define MODULO_NONZERO(n, d)	(((n) % (d)) ? ((n) % (d)) : (d))

/* Get the number of elements of an array type.  */
#define ARRAY_LEN(array)	(sizeof(array) / sizeof((array)[0]))

/* Round 'v' up to the next 'alignment'-byte aligned boundary.  'alignment' must
 * be a power of 2.  */
#undef ALIGN	/* NetBSD <sys/param.h> defines this already */
#define ALIGN(v, alignment)	(((v) + ((alignment) - 1)) & ~((alignment) - 1))


/* STATIC_ASSERT() - verify the truth of an expression at compilation time.  */
#ifdef __CHECKER__
#  define STATIC_ASSERT(expr)
#elif __STDC_VERSION__ >= 201112L
#  define STATIC_ASSERT(expr)	_Static_assert((expr), "")
#else
#  define STATIC_ASSERT(expr)	((void)sizeof(char[1 - 2 * !(expr)]))
#endif

/* STATIC_ASSERT_ZERO() - verify the truth of an expression at compilation time
 * and also produce a result of value '0' to be used in constant expressions */
#define STATIC_ASSERT_ZERO(expr) ((int)sizeof(char[-!(expr)]))

#define CONCAT_IMPL(s1, s2)	s1##s2

/* CONCAT() - concatenate two tokens at preprocessing time.  */
#define CONCAT(s1, s2)		CONCAT_IMPL(s1, s2)


/* Functions to act on "tchar" strings, which have a platform-dependent encoding
 * and character size. */

#ifdef _WIN32
#include <wchar.h>
/*
 * For Windows builds, the "tchar" type will be 2 bytes and will be equivalent
 * to "wchar_t" and "utf16lechar".  All indicate one coding unit of a string
 * encoded in UTF-16LE with the additional possibility of unpaired surrogates.
 */
typedef wchar_t tchar;
#  define TCHAR_IS_UTF16LE 1
#  define _T(text) L##text
#  define T(text) _T(text) /* Make a string literal into a wide string */
#  define TS "ls" /* Format a string of "tchar" */
#  define TC "lc" /* Format a "tchar" */

/* For Windows builds, the following definitions replace the "tchar" functions
 * with the "wide-character" functions. */
#  define tmemchr	wmemchr
#  define tmemcpy	wmemcpy
#  define tmemmove	wmemmove
#  define tmempcpy	wmempcpy
#  define tstrcat	wcscat
#  define tstrcpy	wcscpy
#  define tprintf	wprintf
#  define tsprintf	swprintf
#  define tfprintf	fwprintf
#  define tvfprintf	vfwprintf
#  define tscanf	swscanf
#  define istalpha(c)	iswalpha((wchar_t)(c))
#  define istspace(c)	iswspace((wchar_t)(c))
#  define totlower(c)	towlower((wchar_t)(c))
#  define tstrcmp	wcscmp
#  define tstrncmp	wcsncmp
#  define tstrchr	wcschr
#  define tstrpbrk	wcspbrk
#  define tstrrchr	wcsrchr
#  define tstrstr	wcsstr
#  define tstrlen	wcslen
#  define tmemcmp	wmemcmp
#  define tstrcasecmp   _wcsicmp
#  define tstrftime	wcsftime
#  define tputchar	putwchar
#  define tputc		putwc
#  define tputs		_putws
#  define tfputs	fputws
#  define tfopen	_wfopen
#  define topen		_wopen
#  define tstat		_wstati64
#  define tstrtol	wcstol
#  define tstrtod	wcstod
#  define tstrtoul	wcstoul
#  define tstrtoull	wcstoull
#  define tunlink	_wunlink
#  define tstrerror	_wcserror
#  define taccess	_waccess
#  define tstrdup	wcsdup
#  define tgetenv	_wgetenv
/* The following "tchar" functions do not have exact wide-character equivalents
 * on Windows so require parameter rearrangement or redirection to a replacement
 * function defined ourselves. */
#  define TSTRDUP	WCSDUP
#  define tmkdir(path, mode) _wmkdir(path)
#  define tstrerror_r(errnum, buf, bufsize) \
			_wcserror_s((buf), (bufsize), (errnum))
#  define trename	win32_rename_replacement
#  define tglob		win32_wglob
#else /* _WIN32 */
/*
 * For non-Windows builds, the "tchar" type will be one byte and will specify a
 * string encoded in UTF-8 with the additional possibility of surrogate
 * codepoints.
 */
typedef char tchar;
#  define TCHAR_IS_UTF16LE 0
#  define T(text) text /* In this case, strings of "tchar" are simply strings of
			  char */
#  define TS "s"       /* Similarly, a string of "tchar" is printed just as a
			  normal string. */
#  define TC "c"       /* Print a single character */
/* For non-Windows builds, replace the "tchar" functions with the regular old
 * string functions. */
#  define tmemchr	memchr
#  define tmemcpy	memcpy
#  define tmemmove	memmove
#  define tmempcpy	mempcpy
#  define tstrcat	strcat
#  define tstrcpy	strcpy
#  define tprintf	printf
#  define tsprintf	sprintf
#  define tfprintf	fprintf
#  define tvfprintf	vfprintf
#  define tscanf	sscanf
#  define istalpha(c)	isalpha((unsigned char)(c))
#  define istspace(c)	isspace((unsigned char)(c))
#  define totlower(c)	tolower((unsigned char)(c))
#  define tstrcmp	strcmp
#  define tstrncmp	strncmp
#  define tstrchr	strchr
#  define tstrpbrk	strpbrk
#  define tstrrchr	strrchr
#  define tstrstr	strstr
#  define tstrlen	strlen
#  define tmemcmp	memcmp
#  define tstrcasecmp   strcasecmp
#  define tstrftime	strftime
#  define tputchar	putchar
#  define tputc		putc
#  define tputs		puts
#  define tfputs	fputs
#  define tfopen	fopen
#  define topen		open
#  define tstat		stat
#  define tunlink	unlink
#  define tstrerror	strerror
#  define tstrtol	strtol
#  define tstrtod	strtod
#  define tstrtoul	strtoul
#  define tstrtoull	strtoull
#  define tmkdir	mkdir
#  define tstrdup	strdup
#  define tgetenv	getenv
#  define TSTRDUP	STRDUP
#  define tstrerror_r	strerror_r
#  define trename	rename
#  define taccess	access
#  define tglob		glob
#endif /* !_WIN32 */

#ifdef HAVE_SYS_ENDIAN_H
   /* Needed on NetBSD to stop system bswap macros from messing things up */
#  include <sys/endian.h>
#  undef bswap16
#  undef bswap32
#  undef bswap64
#endif

/* Watch out for conflict with ntfs-3g/endians.h ... */
#ifndef _NTFS_ENDIANS_H

#define bswap16_const(n)			\
	((((u16)(n) & 0x00FF) << 8)	|	\
	 (((u16)(n) & 0xFF00) >> 8))

#define bswap32_const(n)				\
	((((u32)(n) & 0x000000FF) << 24)	|	\
	 (((u32)(n) & 0x0000FF00) << 8)		|	\
	 (((u32)(n) & 0x00FF0000) >> 8)		|	\
	 (((u32)(n) & 0xFF000000) >> 24))

#define bswap64_const(n)					\
	((((u64)(n) & 0x00000000000000FF) << 56)	|	\
	 (((u64)(n) & 0x000000000000FF00) << 40)	|	\
	 (((u64)(n) & 0x0000000000FF0000) << 24)	|	\
	 (((u64)(n) & 0x00000000FF000000) << 8)		|	\
	 (((u64)(n) & 0x000000FF00000000) >> 8)		|	\
	 (((u64)(n) & 0x0000FF0000000000) >> 24)	|	\
	 (((u64)(n) & 0x00FF000000000000) >> 40)	|	\
	 (((u64)(n) & 0xFF00000000000000) >> 56))

static forceinline u16 do_bswap16(u16 n)
{
#if GCC_PREREQ(4, 8) || __has_builtin(__builtin_bswap16)
	return __builtin_bswap16(n);
#else
	return bswap16_const(n);
#endif
}

static forceinline u32 do_bswap32(u32 n)
{
#if GCC_PREREQ(4, 3) || __has_builtin(__builtin_bswap32)
	return __builtin_bswap32(n);
#else
	return bswap32_const(n);
#endif
}

static forceinline u64 do_bswap64(u64 n)
{
#if GCC_PREREQ(4, 3) || __has_builtin(__builtin_bswap64)
	return __builtin_bswap64(n);
#else
	return bswap64_const(n);
#endif
}

#define bswap16(n) (__builtin_constant_p(n) ? bswap16_const(n) : do_bswap16(n))
#define bswap32(n) (__builtin_constant_p(n) ? bswap32_const(n) : do_bswap32(n))
#define bswap64(n) (__builtin_constant_p(n) ? bswap64_const(n) : do_bswap64(n))

#if CPU_IS_BIG_ENDIAN()
#  define cpu_to_le16(n) ((_force_attr le16)bswap16(n))
#  define cpu_to_le32(n) ((_force_attr le32)bswap32(n))
#  define cpu_to_le64(n) ((_force_attr le64)bswap64(n))
#  define le16_to_cpu(n) bswap16((_force_attr u16)(le16)(n))
#  define le32_to_cpu(n) bswap32((_force_attr u32)(le32)(n))
#  define le64_to_cpu(n) bswap64((_force_attr u64)(le64)(n))
#  define cpu_to_be16(n) ((_force_attr be16)(u16)(n))
#  define cpu_to_be32(n) ((_force_attr be32)(u32)(n))
#  define cpu_to_be64(n) ((_force_attr be64)(u64)(n))
#  define be16_to_cpu(n) ((_force_attr u16)(be16)(n))
#  define be32_to_cpu(n) ((_force_attr u32)(be32)(n))
#  define be64_to_cpu(n) ((_force_attr u64)(be64)(n))
#else
#  define cpu_to_le16(n) ((_force_attr le16)(u16)(n))
#  define cpu_to_le32(n) ((_force_attr le32)(u32)(n))
#  define cpu_to_le64(n) ((_force_attr le64)(u64)(n))
#  define le16_to_cpu(n) ((_force_attr u16)(le16)(n))
#  define le32_to_cpu(n) ((_force_attr u32)(le32)(n))
#  define le64_to_cpu(n) ((_force_attr u64)(le64)(n))
#  define cpu_to_be16(n) ((_force_attr be16)bswap16(n))
#  define cpu_to_be32(n) ((_force_attr be32)bswap32(n))
#  define cpu_to_be64(n) ((_force_attr be64)bswap64(n))
#  define be16_to_cpu(n) bswap16((_force_attr u16)(be16)(n))
#  define be32_to_cpu(n) bswap32((_force_attr u32)(be32)(n))
#  define be64_to_cpu(n) bswap64((_force_attr u64)(be64)(n))
#endif

#endif /* _NTFS_ENDIANS_H */

#define DEFINE_UNALIGNED_TYPE(type)				\
static forceinline type						\
load_##type##_unaligned(const void *p)				\
{								\
	type v;							\
	memcpy(&v, p, sizeof(v));				\
	return v;						\
}								\
								\
static forceinline void						\
store_##type##_unaligned(type v, void *p)			\
{								\
	memcpy(p, &v, sizeof(v));				\
}

DEFINE_UNALIGNED_TYPE(u16);
DEFINE_UNALIGNED_TYPE(u32);
DEFINE_UNALIGNED_TYPE(u64);
DEFINE_UNALIGNED_TYPE(le16);
DEFINE_UNALIGNED_TYPE(le32);
DEFINE_UNALIGNED_TYPE(le64);
DEFINE_UNALIGNED_TYPE(be16);
DEFINE_UNALIGNED_TYPE(be32);
DEFINE_UNALIGNED_TYPE(be64);
DEFINE_UNALIGNED_TYPE(size_t);
DEFINE_UNALIGNED_TYPE(machine_word_t);

#define load_word_unaligned	load_machine_word_t_unaligned
#define store_word_unaligned	store_machine_word_t_unaligned

static forceinline u16
get_unaligned_le16(const u8 *p)
{
	if (UNALIGNED_ACCESS_IS_FAST)
		return le16_to_cpu(load_le16_unaligned(p));
	else
		return ((u16)p[1] << 8) | p[0];
}

static forceinline u32
get_unaligned_le32(const u8 *p)
{
	if (UNALIGNED_ACCESS_IS_FAST)
		return le32_to_cpu(load_le32_unaligned(p));
	else
		return ((u32)p[3] << 24) | ((u32)p[2] << 16) |
			((u32)p[1] << 8) | p[0];
}

static forceinline u32
get_unaligned_be32(const u8 *p)
{
	if (UNALIGNED_ACCESS_IS_FAST)
		return be32_to_cpu(load_be32_unaligned(p));
	else
		return ((u32)p[0] << 24) | ((u32)p[1] << 16) |
			((u32)p[2] << 8) | p[3];
}

static forceinline void
put_unaligned_le16(u16 v, u8 *p)
{
	if (UNALIGNED_ACCESS_IS_FAST) {
		store_le16_unaligned(cpu_to_le16(v), p);
	} else {
		p[0] = (u8)(v >> 0);
		p[1] = (u8)(v >> 8);
	}
}

static forceinline void
put_unaligned_le32(u32 v, u8 *p)
{
	if (UNALIGNED_ACCESS_IS_FAST) {
		store_le32_unaligned(cpu_to_le32(v), p);
	} else {
		p[0] = (u8)(v >> 0);
		p[1] = (u8)(v >> 8);
		p[2] = (u8)(v >> 16);
		p[3] = (u8)(v >> 24);
	}
}

static forceinline void
put_unaligned_be32(u32 v, u8 *p)
{
	if (UNALIGNED_ACCESS_IS_FAST) {
		store_be32_unaligned(cpu_to_be32(v), p);
	} else {
		p[0] = (u8)(v >> 24);
		p[1] = (u8)(v >> 16);
		p[2] = (u8)(v >> 8);
		p[3] = (u8)(v >> 0);
	}
}

/*
 * Bit Scan Reverse (BSR) - find the 0-based index (relative to the least
 * significant bit) of the *most* significant 1 bit in the input value.  The
 * input value must be nonzero!
 */

static forceinline unsigned
bsr32(u32 v)
{
#if defined(__GNUC__) || __has_builtin(__builtin_clz)
	return 31 - __builtin_clz(v);
#else
	unsigned bit = 0;
	while ((v >>= 1) != 0)
		bit++;
	return bit;
#endif
}

static forceinline unsigned
bsr64(u64 v)
{
#if defined(__GNUC__) || __has_builtin(__builtin_clzll)
	return 63 - __builtin_clzll(v);
#else
	unsigned bit = 0;
	while ((v >>= 1) != 0)
		bit++;
	return bit;
#endif
}

static forceinline unsigned
bsrw(machine_word_t v)
{
	STATIC_ASSERT(WORDBITS == 32 || WORDBITS == 64);
	if (WORDBITS == 32)
		return bsr32(v);
	else
		return bsr64(v);
}

/*
 * Bit Scan Forward (BSF) - find the 0-based index (relative to the least
 * significant bit) of the *least* significant 1 bit in the input value.  The
 * input value must be nonzero!
 */

static forceinline unsigned
bsf32(u32 v)
{
#if defined(__GNUC__) || __has_builtin(__builtin_ctz)
	return __builtin_ctz(v);
#else
	unsigned bit;
	for (bit = 0; !(v & 1); bit++, v >>= 1)
		;
	return bit;
#endif
}

static forceinline unsigned
bsf64(u64 v)
{
#if defined(__GNUC__) || __has_builtin(__builtin_ctzll)
	return __builtin_ctzll(v);
#else
	unsigned bit;
	for (bit = 0; !(v & 1); bit++, v >>= 1)
		;
	return bit;
#endif
}

static forceinline unsigned
bsfw(machine_word_t v)
{
	STATIC_ASSERT(WORDBITS == 32 || WORDBITS == 64);
	if (WORDBITS == 32)
		return bsf32(v);
	else
		return bsf64(v);
}

/* Return the log base 2 of 'n', rounded up to the nearest integer. */
static forceinline unsigned
ilog2_ceil(size_t n)
{
        if (n <= 1)
                return 0;
        return 1 + bsrw(n - 1);
}

/* Round 'n' up to the nearest power of 2 */
static forceinline size_t
roundup_pow_of_2(size_t n)
{
	return (size_t)1 << ilog2_ceil(n);
}

#endif /* _WIMLIB_COMMON_DEFS_H */
