#include "wimlib/unix_efs.h"

bool
check_signature(utf16lechar *a, utf16lechar *b) {
    size_t l1, l2;
    l1 = utf16le_len_chars(a);
    l2 = utf16le_len_chars(b);

    if (a != b) {
        return false;
    }

    return cmp_utf16le_strings(a, l1, b, l2, false);
}

inline void *
efs_current(efs_buffer* buf) {
    return (void *)(buf->buffer + buf->position);
}

inline size_t
efs_readable_size(efs_buffer *buf) {
    return buf->length - buf->position;
}

void
efs_append(efs_buffer *buf, void *p, size_t len) {
    efs_cleanup(buf);
    buf->buffer = REALLOC(buf->buffer, buf->length + len);
    buf->length += len;
}

inline void
efs_proceed(efs_buffer *buf, size_t len) {
    buf->position += len;
}

void
efs_cleanup(efs_buffer *buf) {
    size_t remain = buf->length - buf->position;
    buf->position = 0;
    buf->length = remain;

    if (!buf->buffer) {
        return;
    }

    void *new_p = NULL;
    
    if (remain) {
        new_p = MALLOC(remain);
        memcpy(new_p, buf->buffer + buf->position, remain);
    }

    FREE(buf->buffer);
    
    if (new_p) {
        buf->buffer = new_p;
    }
}

bool
efs_parse_chunk(const void *p, size_t *len, efs_context *cxt) {
    cxt->buffer.buffer = MALLOC(*len);
    memcpy(cxt->buffer.buffer, p, *len);

    return 0;
}

bool read_root_header(efs_context *cxt) {
    if (efs_readable_size(cxt->buffer.buffer) < sizeof(EFS_HEADER)) {
        return false;
    }

    EFS_HEADER *temp;
    temp = (EFS_HEADER *)efs_current(cxt->buffer.buffer);

    utf16lechar* signature = temp->signature;
    
    if (!check_signature(signature, (utf16lechar[5]){ 'R', 'O', 'B', 'S', '\0' })) {
        return false;
    }
    efs_proceed(cxt->buffer.buffer, sizeof(EFS_HEADER));

    return true;
}

PARSE_STATE read_stream_header(efs_context *cxt) {
    EFS_STREAM_HEADER *header;

    if (efs_readable_size(cxt->buffer.buffer) < sizeof(EFS_STREAM_HEADER)) {
        return NULL_STATE;
    }

    header = (EFS_STREAM_HEADER *)efs_current(cxt->buffer.buffer);

    if (check_signature(header->signature, SIGNATURE_STREAM_NAME)) {
        return STRM_NAME_STATE;
    }
    else if (check_signature(header->signature, SIGNATURE_STREAM_DATA)) {
        return STRM_DATA_HEADER_STATE;
    }
    else {
        return NULL_STATE; // Invalid signature
    }
}

bool read_stream_name(efs_context *cxt) {
    if (efs_readable_size(cxt->buffer.buffer) < sizeof(EFS_STREAM_NAME_HEADER)) {
        return false;
    }

    cxt->current_stream_name.header = *(EFS_STREAM_NAME_HEADER *)efs_current(cxt->buffer.buffer);

    if (!check_signature(cxt->current_stream_name.header.signature, SIGNATURE_STREAM_NAME)) {
        printf("INVALID SIGNATURE_STREAM_NAME!\n");
        return false;
    }

    if (efs_readable_size(cxt->buffer.buffer) < sizeof(EFS_STREAM_NAME_HEADER) +
    cxt->current_stream_name.header.name_size) {
        return false;
    }

    efs_proceed(cxt->buffer.buffer, cxt->current_stream_name.header.size);

    return true;
}

bool read_stream_data_header(efs_context *cxt) {
    if (efs_readable_size(cxt->buffer.buffer) < sizeof(EFS_STREAM_DATA_HEADER)) {
        return false;
    }

    cxt->current_stream_data.header = *(EFS_STREAM_DATA_HEADER *)efs_current(cxt->buffer.buffer);

    if (!check_signature(cxt->current_stream_data.header.signature, SIGNATURE_STREAM_DATA)) {
        printf("INVALID SIGNATURE_STREAM_DATA!\n");
        return false;
    }

    cxt->current_stream_data.datasize = cxt->current_stream_data.header.size - sizeof(EFS_STREAM_DATA_HEADER);
    cxt->current_stream_data.position = 0;

    if (memcmp(cxt->current_stream_name.data, (u8[2]){0x10, 0x19}, 2)) {
        /*
         * This is a buffer of efsinfo. Set system.ntfs_efsinfo with file descriptor.
         */
        cxt->is_efs_info = true;
    }

    efs_proceed(cxt->buffer.buffer, sizeof(cxt->current_stream_data.header));

    return true;
}

bool read_stream_data_value(efs_context *cxt) {
    size_t bytes_to_read;
    bytes_to_read = cxt->current_stream_data.datasize - cxt->current_stream_data.position;

    if (bytes_to_read > efs_readable_size(cxt->buffer.buffer)) {
        bytes_to_read = efs_readable_size(cxt->buffer.buffer);
    }

    if (cxt->is_efs_info) {
        int ret;
        ret = fsetxattr(cxt->fd, "system.ntfs_efsinfo", cxt->buffer.buffer, bytes_to_read, 0);
        if (ret) {
            return false;
        }
    }

    efs_proceed(cxt->buffer.buffer, bytes_to_read);
    cxt->current_stream_data.position += bytes_to_read;

    

    if (cxt->current_stream_data.position < cxt->current_stream_data.datasize) {
        return false;
    }
}
