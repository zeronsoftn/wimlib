/*
 * unix_efs.h: Declaration for processing efs raw data from wim in linux
 * using ntfs-3g xattr.
*/

#include "wimlib/encoding.h"
#include "wimlib/types.h"
#include "wimlib/util.h"

#define SIGNATURE_STREAM_NAME (utf16lechar[]){ 'N', 'T', 'F', 'S', '\0' }
#define SIGNATURE_STREAM_DATA (utf16lechar[]){ 'G', 'U', 'R', 'E', '\0' }


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
	u32 unknown_0x20;
	u32 unknown_0x24;
	u32 unknown_0x28;
	u32 name_size;
	// void *name;
} __attribute__((packed)) EFS_STREAM_NAME_HEADER;

typedef struct _EFS_STREAM_DATA_HEADER {
	u32 size; //* max 66048 bytes for efs data
	utf16lechar signature[4]; //*signature "GURE"
	u32 unknown_0x0c[4];
} __attribute__((packed)) EFS_STREAM_DATA_HEADER;

/* Can have more than one if file is bigger than 64KB */
typedef struct _DATA_ENTRY_HEADER {
	u32 size; //* max 66048 bytes
	utf16lechar signature[4]; //* signature "GURE"
	u32 unknown_0x0c[4]; //* "........ð........."
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
} __attribute__((packed)) EFS_DATA;

/* EFS_INFO part in encrypted file. */
typedef struct _EFS_INFO {
	EFS_STREAM_NAME_HEADER STREAM_NAME;

	struct __attribute__((packed)) {
		u32 size;
		utf16lechar signature[4]; //* unicode "GURE"
		u32 unknown_0x0c;
		// void *buffer; //* starting address of EFS_INFO
	} STREAM_DATA;
} __attribute__((packed)) EFS_INFO;

/* EFS_DATA part in encrypted file. */
typedef struct _EFS_DATA {
	EFS_STREAM_NAME_HEADER STREAM_NAME;

	/* Can have more than one if file is bigger than 64KB */
	struct __attribute__((packed)) {
		u32 size; //* max 66048 bytes
		utf16lechar signature[4]; //* signature "GURE"
		u32 unknown_0x0c[4]; //* "........ð........."
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
	} STREAM_DATA;
} __attribute__((packed)) EFS_DATA;

enum {
    ROOT_HEADER_STATE,
    STRM_HEADER_STATE,
    STRM_NAME_STATE,
	STRM_DATA_HEADER_STATE,
	STRM_DATA_VALUE_STATE
};

typedef int PARSE_STATE;

typedef struct _EFS_STREAM_NAME {
	EFS_STREAM_NAME_HEADER header;
	u8 data[];
} EFS_STREAM_NAME;

typedef struct _EFS_STREAM_DATA {
	EFS_STREAM_DATA_HEADER header;
	u32 datasize;
	u32 position;

	void *buffer;
	int fd;
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
} efs_context;

bool check_signature(utf16lechar *, utf16lechar *);

int efs_parse_chunk(const void *, size_t *, efs_context *);

