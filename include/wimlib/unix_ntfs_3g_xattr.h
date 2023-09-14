/*
 * unix_ntfs_3g_xattr.h - structs for processing ntfs features with ntfs-3g extended attributes.
 *
 * Copyright 2023 Zeronsoftn Corp
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

#include "wimlib/types.h"

/* FILE_FULL_EA_INFORMATION struct for extended attribute(EA) extraction. */
typedef struct _NTFS_EA_INFO {
	u32 EntrySize;
	u8 Flags;
	u8 EaNameLength;
	u16 EaValueLength;
	char EaName[1];
} __attribute__((packed)) NTFS_EA_INFO;


/* ENCRYPTION HEADER in encrypted file. */
typedef struct _EFS_HEADER {
    u32 version;
    utf16lechar signature[4]; //* unicode "ROBS"
    u32 unknown_0xc;
	u32 unknown_0x10;
} __attribute__((packed)) EFS_HEADER;

/* EFS_INFO part in encrypted file. */
struct _EFS_INFO {
	struct __attribute__((packed)) {
		u32 size;
		utf16lechar signature[4]; //* unicode "NTFS"
		u32 unknown_0x20;
		u32 unknown_0x24;
		u32 unknown_0x28;
		u32 name_size;
		u8 name[2]; //* NAME 0x10 0x19
	} STREAM_NAME;

	struct __attribute__((packed)) {
		u32 size;
		utf16lechar signature[4]; //* unicode "GURE"
		u32 unknown_0x0c;
	} STREAM_DATA;
} __attribute__((packed)) EFS_INFO;

/* EFS_DATA part in encrypted file. */
typedef struct _EFS_DATA {
	struct __attribute__((packed)) {
		u32 size;
		utf16lechar signature[4]; //* signature "NTFS"
		u32 unknown_0x0c;
		u32 unknown_0x10;
		u32 unknown_0x14;
		u32 name_size;
		utf16lechar flag[7]; //* ":.:.$.D.A.T.A"
	} STREAM_NAME;

	/* Can have more than one if file is bigger than 64KB */
	struct __attribute__((packed)) {
		u32 size;
		utf16lechar signature[4]; //* signature "GURE"
		u32 unknown_0x0c[4]; //* "........ð........."
		struct __attribute__((packed)) {
			u32 s1;
			u32 s2;
			/* s1 = s2(?) */
		} data_size; //* size of actual data, limited to 65536 bytes(64KB)
		u16 unknown_0x28;
		u8 unknown_0x32[2]; //* 0x09-0x10 when size is each 0-512,513-1024,...,32769-65536(64KB) bytes..?
		u8 unknown_zeros[456]; //* 456 zeros..?
	} STREAM_DATA;
} __attribute__((packed)) EFS_DATA;
