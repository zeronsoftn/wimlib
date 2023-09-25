/*
 * unix_ntfs-3g_xattr_efs.h: Declaration for processing efs raw data from wim in linux
 * using ntfs-3g xattr.
*/

#include "wimlib/encoding.h"
#include "wimlib/types.h"
#include "wimlib/util.h"
#include <sys/xattr.h>

#define SIGNATURE_STREAM_NAME (utf16lechar[]){ 'N', 'T', 'F', 'S', '\0' }
#define SIGNATURE_STREAM_DATA (utf16lechar[]){ 'G', 'U', 'R', 'E', '\0' }

#define NAME_STREAM_NAME (u8[]){ 0x10, 0x19 }
#define DATA_STREAM_NAME (u16[]){ ':', ':', '$', 'D', 'A', 'T', 'A' }


/* ENCRYPTION HEADER in encrypted file. */
typedef struct _EFS_HEADER {
    u32 version; //* 0x00000100
    utf16lechar signature[4]; //* unicode "ROBS"
    u32 unknown_0xc;
	u32 unknown_0x10;
} __attribute__((packed)) EFS_HEADER;


/* STREAM HEADER on each stream included. */
typedef struct _EFS_STREAM_HEADER {
	u32 size;
	utf16lechar signature[4];
	/*
	 * STREAM_NAME: NTFS
	 * STREAM_DATA: GURE
	 */
} __attribute__((packed)) EFS_STREAM_HEADER;

typedef struct _EFS_STREAM_NAME_HEADER {
	u32 size;
	utf16lechar signature[4]; //* signature "NTFS"
	u32 unknown_0x0c;
	u32 unknown_0x10;
	u32 unknown_0x14;
	u32 name_size;
	// void *name;
} __attribute__((packed)) EFS_STREAM_NAME_HEADER;

typedef struct _EFS_STREAM_DATA_HEADER {
	u32 size; //* max 66048 bytes for efs data
	utf16lechar signature[4]; //*signature "GURE"
	u32 unknown_0x0c;
} __attribute__((packed)) EFS_STREAM_DATA_HEADER;

/* Can have more than one if file is bigger than 64KB */
typedef struct _DATA_ENTRY_HEADER {
	EFS_STREAM_DATA_HEADER STREAM_HEADER;
	u32 unknown_0x10[3]; //* "........ð..."
	struct __attribute__((packed)) {
		u32 s1;
		u32 s2;
		/* s1 = s2(?) */
	} actual_size; //* size of actual data, limited to 65536 bytes(64KB)
	u16 unknown_0x24;
	u8 unknown_0x26[2]; //* 0x09-0x10 when size is each 0-512,513-1024,...,32769-65536(64KB) bytes..?
	u32 unknown_0x28;
	u32 padded_size; //* size padded with 512 bytes
	u8 unknown_0x32[8]; //* "EXTD...."
	u8 unknown_zeros[456]; //* 456 zeros..?
	// void* data;
} __attribute__((packed)) EFS_DATA_ENT;

/* EFS_INFO part in encrypted file. */
typedef struct _EFS_INFO {
	EFS_STREAM_NAME_HEADER stream_name;
	EFS_STREAM_DATA_HEADER stream_data;
	// void *data;
} __attribute__((packed)) EFS_INFO;

enum PARSE_STATE {
	NULL_STATE = -1,

	ROOT_HEADER_STATE,
	STRM_HEADER_STATE,
	STRM_NAME_STATE,
	STRM_DATA_HEADER_STATE,
	STRM_DATA_VALUE_STATE
};

typedef int PARSE_STATE;

typedef struct _EFS_STREAM_NAME {
	EFS_STREAM_NAME_HEADER header;
	void *data;
} EFS_STREAM_NAME;

typedef struct _EFS_STREAM_DATA {
	EFS_STREAM_DATA_HEADER header;
	u32 datasize;
	u32 position;

	void *buffer;
} EFS_STREAM_DATA;

typedef struct _efs_buffer {
	void* buffer;
	size_t length;
	u32 position;
} efs_buffer;

typedef struct _efs_context {
	PARSE_STATE parse_state;
	efs_buffer buffer;

	EFS_HEADER efs_header;

	EFS_STREAM_NAME current_stream_name;
	EFS_STREAM_DATA current_stream_data;

	bool is_efs_info;
	bool err_flag;

	int fd;
	const char *path; // for writing efsinfo in encrypted directory
	void *efsinfo_buf; // buffer for efsinfo xattr
	size_t efsinfo_buf_size; // size for efsinfo buffer

	u16 padding_size;

	u32 write_offset; // writing offset for raw encrypted data

	bool is_writing; // is data writing in progress?
} efs_context;

bool
efs_parse_chunk(const void *p, const void *efs_p, size_t *len, efs_context *cxt);
