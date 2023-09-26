#include "wimlib/unix_ntfs-3g_xattr_efs.h"

static bool
check_signature(utf16lechar *a, utf16lechar *b) {
	size_t l1, l2;
	l1 = utf16le_len_chars(a);
	l2 = utf16le_len_chars(b);

	if (l1 != l2) {
		return false;
	}

	return cmp_utf16le_strings(a, l1, b, l2, false) ? false : true;
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
efs_cleanup(efs_buffer *buf) {
	if (!buf->buffer) {
		return;
	}

	size_t remain = buf->length - buf->position;

	if (remain) {
		void *new_p = MALLOC(remain);
		memcpy(new_p, buf->buffer + buf->position, remain);
		FREE(buf->buffer);
		buf->buffer = new_p;
	}

	buf->position = 0;
	buf->length = remain;
}

static void
efs_append(efs_buffer *buf, const void *p, size_t len) {
	efs_cleanup(buf);
	buf->buffer = REALLOC(buf->buffer, buf->length + len);
	memcpy(buf->buffer + buf->length, p, len);
	buf->length += len;
}

static inline void
efs_proceed(efs_buffer *buf, size_t len) {
	buf->position += len;
}

static bool
read_root_header(efs_context *ctx) {
	if (efs_readable_size(&ctx->buffer) < sizeof(EFS_HEADER)) {
		return false;
	}

	EFS_HEADER *temp = (EFS_HEADER *)efs_current(&ctx->buffer);

	utf16lechar* signature = temp->signature;
	
	if (!check_signature(signature, (utf16lechar[]){ 'R', 'O', 'B', 'S', '\0' })) {
		ctx->err_flag = true;
		return false;
	}
	efs_proceed(&ctx->buffer, sizeof(EFS_HEADER));

	return true;
}

static PARSE_STATE
read_stream_header(efs_context *ctx) {
	if (efs_readable_size(&ctx->buffer) < sizeof(EFS_STREAM_HEADER)) {
		return NULL_STATE;
	}

	EFS_STREAM_HEADER *header = (EFS_STREAM_HEADER *)efs_current(&ctx->buffer);

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
	if (efs_readable_size(&ctx->buffer) < sizeof(EFS_STREAM_NAME_HEADER)) {
		return false;
	}

	ctx->current_stream_name.header = *(EFS_STREAM_NAME_HEADER *)efs_current(&ctx->buffer);

	if (!check_signature(ctx->current_stream_name.header.signature, SIGNATURE_STREAM_NAME)) {
		ERROR("INVALID SIGNATURE_STREAM_NAME!\n");
		ctx->err_flag = true;
		return false;
	}

	if (efs_readable_size(&ctx->buffer) < sizeof(EFS_STREAM_NAME_HEADER) +
	ctx->current_stream_name.header.name_size) {
		return false;
	}

	ctx->current_stream_name.data = efs_current(&ctx->buffer) + sizeof(EFS_STREAM_NAME_HEADER);
	efs_proceed(&ctx->buffer, ctx->current_stream_name.header.size);

	return true;
}

static bool
read_stream_data_header(efs_context *ctx) {
	if (efs_readable_size(&ctx->buffer) < sizeof(EFS_STREAM_DATA_HEADER)) {
		return false;
	}

	ctx->current_stream_data.header = *(EFS_STREAM_DATA_HEADER *)efs_current(&ctx->buffer);

	if (!check_signature(ctx->current_stream_data.header.signature, SIGNATURE_STREAM_DATA)) {
		ERROR("INVALID SIGNATURE_STREAM_DATA!\n");
		ctx->err_flag = true;
		return false;
	}

	ctx->current_stream_data.position = 0;


	if (!memcmp(ctx->current_stream_name.data, NAME_STREAM_NAME, 2)) {
		ctx->current_stream_data.datasize = ctx->current_stream_data.header.size - sizeof(EFS_STREAM_DATA_HEADER);
		/*
		 * This is a buffer of efsinfo. Set system.ntfs_efsinfo with file descriptor.
		 */
		ctx->is_efs_info = true;
		efs_proceed(&ctx->buffer, sizeof(ctx->current_stream_data.header));
	}
	else if (ctx->is_writing || !memcmp(ctx->current_stream_name.data, DATA_STREAM_NAME, 14)) {
		if (efs_readable_size(&ctx->buffer) < sizeof(EFS_DATA_ENT)) {
			return false;
		}

		if (!ctx->is_writing)
			ctx->is_writing = true; // begin writing encrypted data

		EFS_DATA_ENT *temp = (EFS_DATA_ENT *)efs_current(&ctx->buffer);
		ctx->current_stream_data.datasize = ctx->current_stream_data.header.size - sizeof(*temp);
		/*
		 * This is a part of a raw encrypted data.
		 * If a size of a data is less then 66048 bytes(64KB + sizeof(EFS_DATA_ENT)),
		 * we can get efs_padding_size required for writing raw encrypted file with ntfs-3g.
		 */
		if (ctx->current_stream_data.header.size < 0x10200) {
			ctx->padding_size = temp->padded_size - temp->actual_size.s1;
		}
		efs_proceed(&ctx->buffer, sizeof(*temp));
	}
	else {
		ERROR("INVALID STREAM NAME!");
		return false;
	}

	return true;
}

static
bool read_stream_data_value(efs_context *ctx, void *write_p, size_t *write_byte) {
	size_t bytes_to_write = min(efs_readable_size(&ctx->buffer), 
		ctx->current_stream_data.datasize - ctx->current_stream_data.position);

	if (!ctx->is_efs_info) {
		write_p = write_p ? mempcpy(write_p, efs_current(&ctx->buffer), bytes_to_write) : NULL;
		*write_byte += bytes_to_write;
		efs_proceed(&ctx->buffer, bytes_to_write);
		ctx->current_stream_data.position += bytes_to_write;

		if (ctx->current_stream_data.position < ctx->current_stream_data.datasize) {
			return false;
			// read more
		}
	}

	if (ctx->is_efs_info) {
		if (bytes_to_write < ctx->current_stream_data.datasize) {
			return false;
			// read more
		}
		/*
		 * efsinfo should be set after the file is fully written with padding size(otherwise file is broken)
		 */
		ctx->efsinfo_buf = MALLOC(ctx->current_stream_data.datasize);
		memcpy(ctx->efsinfo_buf, efs_current(&ctx->buffer), bytes_to_write);
		ctx->efsinfo_buf_size = bytes_to_write;

		ctx->is_efs_info = false;

		efs_proceed(&ctx->buffer, bytes_to_write);
		ctx->current_stream_data.position += bytes_to_write;
	}

	return true;
}

bool
efs_parse_chunk(const void *p, const void *efs_p, size_t *len, efs_context *ctx) {
	if (!ctx->buffer.buffer) {
		ctx->buffer.buffer = MALLOC(*len);
		memcpy(ctx->buffer.buffer, p, *len);
		ctx->buffer.length = *len;
		ctx->buffer.position = 0;
	}
	else {
		efs_append(&ctx->buffer, p, *len);
	}

	size_t write_byte = 0;
	void *write_p = (void *)efs_p; //* ptr to write data to
	PARSE_STATE next;
	bool finish;

	while (efs_readable_size(&ctx->buffer) > 0) {
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
			break;
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
			break;
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
			break;
		case STRM_DATA_HEADER_STATE:
			finish = read_stream_data_header(ctx);
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
			break;
		case STRM_DATA_VALUE_STATE:
			finish = read_stream_data_value(ctx, write_p, &write_byte);
			if (finish) {
				ctx->parse_state = STRM_HEADER_STATE;
			}
			else if (ctx->err_flag) {
				return false;
			}
			else {
				break;
			}
		}
	}

	*len = write_byte; // set length of currently written data

	return true;
}
