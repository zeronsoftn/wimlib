#include "wimlib/unix_efs.h"

bool check_signature(utf16lechar *a, utf16lechar *b) {
    size_t l1, l2;
    l1 = utf16le_len_chars(a);
    l2 = utf16le_len_chars(b);

    if (a != b) {
        return false;
    }

    return cmp_utf16le_strings(a, l1, b, l2, false);
}

int efs_parse_chunk(const void *p, size_t *len, efs_context *cxt) {
	
    return 0;
}
