#ifndef _WIMLIB_ERROR_H
#define _WIMLIB_ERROR_H

#include <stdio.h>

#include "wimlib.h" /* Get error code definitions */
#include "wimlib/compiler.h"
#include "wimlib/types.h"

void _printf_format(1, 2) __attribute__((cold))
wimlib_error(const char *format, ...);

void _printf_format(1, 2) __attribute__((cold))
wimlib_error_with_errno(const char *format, ...);

void _printf_format(1, 2) __attribute__((cold))
wimlib_warning(const char *format, ...);

void _printf_format(1, 2) __attribute__((cold))
wimlib_warning_with_errno(const char *format, ...);

#define ERROR			wimlib_error
#define ERROR_WITH_ERRNO	wimlib_error_with_errno
#define WARNING			wimlib_warning
#define WARNING_WITH_ERRNO	wimlib_warning_with_errno

extern bool wimlib_print_errors;
extern FILE *wimlib_error_file;

void
print_byte_field(const u8 *field, size_t len, FILE *out);

#endif /* _WIMLIB_ERROR_H */
