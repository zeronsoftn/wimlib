#include "wimlib/unix_efs.h"

static bool
check_signature(utf16lechar *a, utf16lechar *b) {
    size_t l1, l2;
    l1 = utf16le_len_chars(a);
    l2 = utf16le_len_chars(b);

    if (a != b) {
        return false;
    }

    return cmp_utf16le_strings(a, l1, b, l2, false);
}

static inline void *
efs_current(efs_buffer *buf) {
    return (void *)(buf->buffer + buf->position);
}

static inline size_t
efs_readable_size(efs_buffer *buf) {
    return buf->length - buf->position;
}

static void
efs_append(efs_buffer *buf, void *p, size_t len) {
    efs_cleanup(buf);
    buf->buffer = REALLOC(buf->buffer, buf->length + len);
    memcpy(buf->buffer + buf->length, p, len);
    buf->length += len;
}

static inline void
efs_proceed(efs_buffer *buf, size_t len) {
    buf->position += len;
}

static void
efs_cleanup(efs_buffer *buf) {
    size_t remain = buf->length - buf->position;

    if (!buf->buffer) {
        return;
    }

    if (remain) {
        void *new_p = MALLOC(remain);
        memcpy(new_p, buf->buffer + buf->position, remain);
        FREE(buf->buffer);
        buf->buffer = new_p;
    }

    buf->position = 0;
    buf->length = remain;
}


static bool
read_root_header(efs_context *ctx) {
    if (efs_readable_size(ctx->buffer.buffer) < sizeof(EFS_HEADER)) {
        return false;
    }

    EFS_HEADER *temp = (EFS_HEADER *)efs_current(ctx->buffer.buffer);

    utf16lechar* signature = temp->signature;
    
    if (!check_signature(signature, (utf16lechar[5]){ 'R', 'O', 'B', 'S', '\0' })) {
		ctx->err_flag = true;
        return false;
    }
    efs_proceed(ctx->buffer.buffer, sizeof(EFS_HEADER));

    return true;
}

static PARSE_STATE
read_stream_header(efs_context *ctx) {
    if (efs_readable_size(ctx->buffer.buffer) < sizeof(EFS_STREAM_HEADER)) {
        return NULL_STATE;
    }

    EFS_STREAM_HEADER *header = (EFS_STREAM_HEADER *)efs_current(ctx->buffer.buffer);

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

static bool
read_stream_name(efs_context *ctx) {
    if (efs_readable_size(ctx->buffer.buffer) < sizeof(EFS_STREAM_NAME_HEADER)) {
        return false;
    }

    ctx->current_stream_name.header = *(EFS_STREAM_NAME_HEADER *)efs_current(ctx->buffer.buffer);

    if (!check_signature(ctx->current_stream_name.header.signature, SIGNATURE_STREAM_NAME)) {
        printf("INVALID SIGNATURE_STREAM_NAME!\n");
		ctx->err_flag = true;
        return false;
    }

    if (efs_readable_size(ctx->buffer.buffer) < sizeof(EFS_STREAM_NAME_HEADER) +
    ctx->current_stream_name.header.name_size) {
        return false;
    }

    efs_proceed(ctx->buffer.buffer, ctx->current_stream_name.header.size);

    return true;
}

static bool
read_stream_data_header(efs_context *ctx) {
    if (efs_readable_size(ctx->buffer.buffer) < sizeof(EFS_STREAM_DATA_HEADER)) {
        return false;
    }

    ctx->current_stream_data.header = *(EFS_STREAM_DATA_HEADER *)efs_current(ctx->buffer.buffer);

    if (!check_signature(ctx->current_stream_data.header.signature, SIGNATURE_STREAM_DATA)) {
        printf("INVALID SIGNATURE_STREAM_DATA!\n");
		ctx->err_flag = true;
        return false;
    }

    ctx->current_stream_data.position = 0;


    if (memcmp(ctx->current_stream_name.data, (u8[2]){0x10, 0x19}, 2)) {
		ctx->current_stream_data.datasize = ctx->current_stream_data.header.size - sizeof(EFS_STREAM_DATA_HEADER);
        /*
         * This is a buffer of efsinfo. Set system.ntfs_efsinfo with file descriptor.
         */
        ctx->is_efs_info = true;
        efs_proceed(ctx->buffer.buffer, sizeof(ctx->current_stream_data.header));
    }
	else if (memcmp(ctx->current_stream_name.data, (u16[7]){ ':', ':', '$', 'D', 'A', 'T', 'A' }, 14)) {
        EFS_DATA_ENT *temp = (EFS_DATA_ENT *)efs_current(ctx->buffer.buffer);
		ctx->current_stream_data.datasize = ctx->current_stream_data.header.size - sizeof(EFS_DATA_ENT);
        /*
         * This is a part of a raw encrypted data.
         * If a size of a data is less then 66048 bytes(64KB + sizeof(EFS_DATA_ENT)),
         * we can get efs_padding_size required for writing raw encrypted file with ntfs-3g.
         */
        if (ctx->current_stream_data.header.size < 0x10200) {
            ctx->padding_size = temp->padded_size - temp->actual_size.s1;
        }
	}
    else {
        printf("INVALID STREAM NAME!");
        return false;
    }

    return true;
}

static
bool read_stream_data_value(efs_context *ctx, void *p, size_t *st) {
    size_t bytes_to_write = min(efs_readable_size(ctx->buffer.buffer), 
        ctx->current_stream_data.datasize - ctx->current_stream_data.position);

    if (ctx->is_efs_info) {
        int ret;
        ret = fsetxattr(ctx->fd, "system.ntfs_efsinfo", efs_current(ctx->buffer.buffer), bytes_to_write, 0);
        if (ret) {
			ctx->err_flag = true;
            return false;
        }
		ctx->is_efs_info = false;
    }
	else {
		efs_proceed(ctx->buffer.buffer, sizeof(EFS_DATA_ENT) - sizeof(ctx->current_stream_data.header));
		bytes_to_write = min(efs_readable_size(ctx->buffer.buffer), 
            ctx->current_stream_data.datasize - ctx->current_stream_data.position);
		p = mempcpy(p, efs_current(ctx->buffer.buffer), bytes_to_write);
		*st += bytes_to_write;
	}

    efs_proceed(ctx->buffer.buffer, bytes_to_write);
    ctx->current_stream_data.position += bytes_to_write;

    if (ctx->current_stream_data.position < ctx->current_stream_data.datasize) {
        return false;
    }

	return true;
}

bool
efs_parse_chunk(const void *p, const void *efs_p, size_t *len, efs_context *ctx) {
    ctx->buffer.buffer = MALLOC(*len);
    memcpy(ctx->buffer.buffer, p, *len);
	size_t write_byte = 0;

	void *write_p = efs_p; //* ptr to write data to
	PARSE_STATE next;
	bool finish;

	while (efs_readable_size(ctx->buffer.buffer) > 0) {
		switch (ctx->parse_state) {
		case ROOT_HEADER_STATE:
			finish = read_root_header(ctx);
			if (finish) {
				ctx->parse_state = STRM_HEADER_STATE;
			}
			else if (ctx->err_flag) {
				return false;
			}
			else {
				return true;
				// read more
			}
		case STRM_HEADER_STATE:
			next = read_stream_header(ctx);
			if (next == NULL_STATE) {
				return true;
				// read more
			}
			else if (ctx->err_flag) {
				return false;
			}
			else {
				ctx->parse_state = next;
			}
		case STRM_NAME_STATE:
			finish = read_stream_name(ctx);
			if (finish) {
				ctx->parse_state = STRM_HEADER_STATE;
			}
			else if (ctx->err_flag) {
				return false;
			}
			else {
				return true;
				// read more
			}
		case STRM_DATA_HEADER_STATE:
			finish = read_stream_data_header;
			if (finish) {
				ctx->parse_state = STRM_DATA_VALUE_STATE;
			}
			else if (ctx->err_flag) {
				return false;
			}
			else {
				return true;
				// read more
			}
		case STRM_DATA_VALUE_STATE:
			finish = read_stream_data_value(ctx, write_p, &write_byte);
			if (finish) {
				ctx->parse_state = STRM_HEADER_STATE;
			}
			else if (ctx->err_flag) {
				return false;
			}
			else {
				return true;
				// read more
			}
		}
	}
	FREE(ctx->buffer.buffer);

	if (write_byte < *len) {
		*len = write_byte;
	}

    return 0;
}
