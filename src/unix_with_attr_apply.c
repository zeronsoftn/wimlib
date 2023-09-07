/*
 * unix_apply_with_attr.c - Code to apply files from a WIM image to directory on UNIX with NTFS attributes using xattr.
 * The target directory should be mounted with ntfs-3g, with efs_raw option for efs extraction to work.
 */

/*
 * Copyright (C) 2012-2018 Eric Biggers
 * Copyright (C) 2023 ZeronsoftN Corp
 *
 * This file is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option) any
 * later version.
 *
 * This file is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this file; if not, see https://www.gnu.org/licenses/.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#ifdef HAVE_SYS_XATTR_H
#  include <sys/xattr.h>
#endif
#include <unistd.h>

#include "wimlib/apply.h"
#include "wimlib/assert.h"
#include "wimlib/blob_table.h"
#include "wimlib/dentry.h"
#include "wimlib/encoding.h"
#include "wimlib/error.h"
#include "wimlib/file_io.h"
#include "wimlib/list.h"
#include "wimlib/metadata.h"
#include "wimlib/object_id.h"
#include "wimlib/reparse.h"
#include "wimlib/scan.h"
#include "wimlib/timestamp.h"
#include "wimlib/unix_data.h"
#include "wimlib/xattr.h"

/* We don't require O_NOFOLLOW, but the advantage of having it is that if we
 * need to extract a file to a location at which there exists a symbolic link,
 * open(..., O_NOFOLLOW | ...) recognizes the symbolic link rather than
 * following it and creating the file somewhere else.  (Equivalent to
 * FILE_OPEN_REPARSE_POINT on Windows.)  */
#ifndef O_NOFOLLOW
#  define O_NOFOLLOW 0
#endif

static int
unix_with_attr_get_supported_features(const char *target,
			    struct wim_features *supported_features)
{
	supported_features->readonly_files            = 1;
	supported_features->hidden_files              = 1;
	supported_features->system_files              = 1;
	supported_features->archive_files             = 1;
	supported_features->compressed_files          = 1;
	supported_features->encrypted_files           = 1;
	supported_features->encrypted_directories     = 1;
	supported_features->not_context_indexed_files = 1;
	supported_features->sparse_files              = 1;
	supported_features->named_data_streams        = 1;
	supported_features->hard_links                = 1;
	supported_features->reparse_points            = 1;
	supported_features->security_descriptors      = 1;
	supported_features->short_names               = 1;
	supported_features->object_ids                = 1;
	supported_features->timestamps                = 1;
	supported_features->case_sensitive_filenames  = 1;
#ifdef HAVE_LINUX_XATTR_SUPPORT
	supported_features->xattrs = 1;
#endif
	return 0;
}

#define NUM_PATHBUFS 2  /* We need 2 when creating hard links  */

struct unix_with_attr_apply_ctx {
	/* Extract flags, the pointer to the WIMStruct, etc.  */
	struct apply_ctx common;

	/* Buffers for building extraction paths (allocated).  */
	char *pathbufs[NUM_PATHBUFS];

	/* Index of next pathbuf to use  */
	unsigned which_pathbuf;

	/* Currently open file descriptors for extraction  */
	struct filedes open_fds[MAX_OPEN_FILES];

	/* Number of currently open file descriptors in open_fds, starting from
	 * the beginning of the array.  */
	unsigned num_open_fds;

	/* For each currently open file, whether we're writing to it in "sparse"
	 * mode or not.  */
	bool is_sparse_file[MAX_OPEN_FILES];

	/* Whether is_sparse_file[] is true for any currently open file  */
	bool any_sparse_files;

	/* Allocated buffer for reading blob data when it cannot be extracted
	 * directly  */
	u8 *data_buffer;

	/* Pointer to the next byte in @data_buffer to fill  */
	u8 *data_buffer_ptr;

	/* Size allocated in @data_buffer  */
	size_t data_buffer_size;

	/* Current offset in the raw encrypted file being written  */
	size_t encrypted_offset;

	/* Current size of the raw encrypted file being written  */
	size_t encrypted_size;	

	/* Temporary buffer for reparse data  */
	struct reparse_buffer_disk rpbuf;

	/* Temporary buffer for reparse data of "fixed" absolute symbolic links
	 * and junctions  */
	struct reparse_buffer_disk rpfixbuf;

	/* List of dentries, joined by @d_tmp_list, that need to have reparse
	 * data extracted as soon as the whole blob has been read into
	 * @data_buffer.  */
	struct list_head reparse_dentries;

	/* List of dentries, joined by @d_tmp_list, that need to have raw
	 * encrypted data extracted as soon as the whole blob has been read into
	 * @data_buffer.  */
	struct list_head encrypted_dentries;

	/* Absolute path to the target directory (allocated buffer).  Only set
	 * if needed for absolute symbolic link fixups.  */
	char *target_abspath;

	/* Number of characters in target_abspath.  */
	size_t target_abspath_nchars;

	/* Number of special files we couldn't create due to EPERM  */
	unsigned long num_special_files_ignored;
};

/* Returns the number of characters needed to represent the path to the
 * specified @dentry when extracted, not including the null terminator or the
 * path to the target directory itself.  */
static size_t
unix_dentry_path_length(const struct wim_dentry *dentry)
{
	size_t len = 0;
	const struct wim_dentry *d;

	d = dentry;
	do {
		len += d->d_extraction_name_nchars + 1;
		d = d->d_parent;
	} while (!dentry_is_root(d) && will_extract_dentry(d));

	return len;
}

/* Returns the maximum number of characters needed to represent the path to any
 * dentry in @dentry_list when extracted, including the null terminator and the
 * path to the target directory itself.  */
static size_t
unix_compute_path_max(const struct list_head *dentry_list,
		      const struct unix_with_attr_apply_ctx *ctx)
{
	size_t max = 0;
	size_t len;
	const struct wim_dentry *dentry;

	list_for_each_entry(dentry, dentry_list, d_extraction_list_node) {
		len = unix_dentry_path_length(dentry);
		if (len > max)
			max = len;
	}

	/* Account for target and null terminator.  */
	return ctx->common.target_nchars + max + 1;
}

/* Builds and returns the filesystem path to which to extract @dentry.
 * This cycles through NUM_PATHBUFS different buffers.  */
static const char *
unix_build_extraction_path(const struct wim_dentry *dentry,
			   struct unix_with_attr_apply_ctx *ctx)
{
	char *pathbuf;
	char *p;
	const struct wim_dentry *d;

	pathbuf = ctx->pathbufs[ctx->which_pathbuf];
	ctx->which_pathbuf = (ctx->which_pathbuf + 1) % NUM_PATHBUFS;

	p = &pathbuf[ctx->common.target_nchars +
		     unix_dentry_path_length(dentry)];
	*p = '\0';
	d = dentry;
	do {
		p -= d->d_extraction_name_nchars;
		if (d->d_extraction_name_nchars)
			memcpy(p, d->d_extraction_name,
			       d->d_extraction_name_nchars);
		*--p = '/';
		d = d->d_parent;
	} while (!dentry_is_root(d) && will_extract_dentry(d));

	return pathbuf;
}	/* Allocated buffer for reading blob data when it cannot be extracted
	 * directly  */
	u8 *data_buffer;

/* This causes the next call to unix_build_extraction_path() to use the same
 * path buffer as the previous call.  */
static void
unix_reuse_pathbuf(struct unix_with_attr_apply_ctx *ctx)
{
	ctx->which_pathbuf = (ctx->which_pathbuf - 1) % NUM_PATHBUFS;
}

/* Builds and returns the filesystem path to which to extract an unspecified
 * alias of the @inode.  This cycles through NUM_PATHBUFS different buffers.  */
static const char *
unix_build_inode_extraction_path(const struct wim_inode *inode,
				 struct unix_with_attr_apply_ctx *ctx)
{
	return unix_build_extraction_path(inode_first_extraction_dentry(inode), ctx);
}

/* Should the specified file be extracted as a directory on UNIX?  We extract
 *  the file as a directory if FILE_ATTRIBUTE_DIRECTORY is set and even when FILE_ATTRIBUTE_REPARSE_POINT is set
    as ntfs-3g driver process reparse points to symlinks in unix. It *may* have a different type
 * of reparse point.  */
static inline bool
should_extract_as_directory(const struct wim_inode *inode)
{
	return (inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY) &&
		!inode_is_symlink(inode);
}

/* Sets the timestamps on a file being extracted.
 *
 * Either @fd or @path must be specified (not -1 and not NULL, respectively).
 */
static int
unix_set_timestamps(int fd, const char *path, u64 atime, u64 mtime)
{
	{
		struct timespec times[2];

		times[0] = wim_timestamp_to_timespec(atime);
		times[1] = wim_timestamp_to_timespec(mtime);

		errno = ENOSYS;
#ifdef HAVE_FUTIMENS
		if (fd >= 0 && !futimens(fd, times))
			return 0;
#endif
#ifdef HAVE_UTIMENSAT
		if (fd < 0 && !utimensat(AT_FDCWD, path, times, AT_SYMLINK_NOFOLLOW))
			return 0;
#endif
		if (errno != ENOSYS)
			return WIMLIB_ERR_SET_TIMESTAMPS;
	}
	{
		struct timeval times[2];

		times[0] = wim_timestamp_to_timeval(atime);
		times[1] = wim_timestamp_to_timeval(mtime);

		if (fd >= 0 && !futimes(fd, times))
			return 0;
		if (fd < 0 && !lutimes(path, times))
			return 0;
		return WIMLIB_ERR_SET_TIMESTAMPS;
	}
}

static int
unix_set_owner_and_group(int fd, const char *path, uid_t uid, gid_t gid)
{
	if (fd >= 0 && !fchown(fd, uid, gid))
		return 0;
	if (fd < 0 && !lchown(path, uid, gid))
		return 0;
	return WIMLIB_ERR_SET_SECURITY;
}

static int
unix_set_mode(int fd, const char *path, mode_t mode)
{
	if (fd >= 0 && !fchmod(fd, mode))
		return 0;
	if (fd < 0 && !chmod(path, mode))
		return 0;
	return WIMLIB_ERR_SET_SECURITY;
}

#ifdef HAVE_LINUX_XATTR_SUPPORT
/* Apply extended attributes to a file */
static int
apply_linux_xattrs(int fd, const struct wim_inode *inode,
		   const char *path, struct unix_with_attr_apply_ctx *ctx,
		   const void *entries, size_t entries_size, bool is_old_format)
{
	const void * const entries_end = entries + entries_size;
	char name[WIM_XATTR_NAME_MAX + 1];

	for (const void *entry = entries;
	     entry < entries_end;
	     entry = is_old_format ? (const void *)old_xattr_entry_next(entry) :
				     (const void *)xattr_entry_next(entry))
	{
		bool valid;
		u16 name_len;
		const void *value;
		u32 value_len;
		int res;

		if (is_old_format) {
			valid = old_valid_xattr_entry(entry,
						      entries_end - entry);
		} else {
			valid = valid_xattr_entry(entry, entries_end - entry);
		}
		if (!valid) {
			if (!path) {
				path = unix_build_inode_extraction_path(inode,
									ctx);
			}
			ERROR("\"%s\": extended attribute is corrupt or unsupported",
			      path);
			return WIMLIB_ERR_INVALID_XATTR;
		}
		if (is_old_format) {
			const struct wimlib_xattr_entry_old *e = entry;

			name_len = le16_to_cpu(e->name_len);
			memcpy(name, e->name, name_len);
			value = e->name + name_len;
			value_len = le32_to_cpu(e->value_len);
		} else {
			const struct wim_xattr_entry *e = entry;

			name_len = e->name_len;
			memcpy(name, e->name, name_len);
			value = e->name + name_len + 1;
			value_len = le16_to_cpu(e->value_len);
		}
		name[name_len] = '\0';

		if (fd >= 0)
			res = fsetxattr(fd, name, value, value_len, 0);
		else
			res = lsetxattr(path, name, value, value_len, 0);

		if (unlikely(res != 0)) {
			if (!path) {
				path = unix_build_inode_extraction_path(inode,
									ctx);
			}
			if (is_linux_security_xattr(name) &&
			    (ctx->common.extract_flags &
			     WIMLIB_EXTRACT_FLAG_STRICT_ACLS))
			{
				ERROR_WITH_ERRNO("\"%s\": unable to set extended attribute \"%s\"",
						 path, name);
				return WIMLIB_ERR_SET_XATTR;
			}
			ERROR_WITH_ERRNO("\"%s\": unable to set extended attribute \"%s\"",
					   path, name);
		}
	}
	return 0;
}
#endif /* HAVE_LINUX_XATTR_SUPPORT */

/*
 * Apply UNIX-specific metadata to a file if available.  This includes standard
 * UNIX permissions (uid, gid, and mode) and possibly extended attributes too.
 *
 * Note that some xattrs which grant privileges, e.g. security.capability, are
 * cleared by Linux on chown(), even when running as root.  Also, when running
 * as non-root, if we need to chmod() the file to readonly, we can't do that
 * before setting xattrs because setxattr() requires write permission.  These
 * restrictions result in the following ordering which we follow: chown(),
 * setxattr(), then chmod().
 *
 * N.B. the file may be specified by either 'fd' (for regular files) or 'path',
 * and it may be a symlink.  For symlinks we need lchown() and lsetxattr() but
 * need to skip the chmod(), since mode bits are not meaningful for symlinks.
 */
static int
apply_unix_metadata(int fd, const struct wim_inode *inode,
		    const char *path, struct unix_with_attr_apply_ctx *ctx)
{
	bool have_dat;
	struct wimlib_unix_data dat;
#ifdef HAVE_LINUX_XATTR_SUPPORT
	const void *entries;
	u32 entries_size;
	bool is_old_format;
#endif
	int ret;

	have_dat = inode_get_unix_data(inode, &dat);

	if (have_dat) {
		ret = unix_set_owner_and_group(fd, path, dat.uid, dat.gid);
		if (ret) {
			if (!path)
				path = unix_build_inode_extraction_path(inode, ctx);
			if (ctx->common.extract_flags &
			    WIMLIB_EXTRACT_FLAG_STRICT_ACLS)
			{
				ERROR_WITH_ERRNO("\"%s\": unable to set uid=%"PRIu32" and gid=%"PRIu32,
						 path, dat.uid, dat.gid);
				return ret;
			}
			WARNING_WITH_ERRNO("\"%s\": unable to set uid=%"PRIu32" and gid=%"PRIu32,
					   path, dat.uid, dat.gid);
		}
	}

#ifdef HAVE_LINUX_XATTR_SUPPORT
	entries = inode_get_linux_xattrs(inode, &entries_size, &is_old_format);
	if (entries) {
		ret = apply_linux_xattrs(fd, inode, path, ctx,
					 entries, entries_size, is_old_format);
		if (ret)
			return ret;
	}
#endif

	if (have_dat && !inode_is_symlink(inode)) {
		ret = unix_set_mode(fd, path, dat.mode);
		if (ret) {
			if (!path)
				path = unix_build_inode_extraction_path(inode, ctx);
			if (ctx->common.extract_flags &
			    WIMLIB_EXTRACT_FLAG_STRICT_ACLS)
			{
				ERROR_WITH_ERRNO("\"%s\": unable to set mode=0%"PRIo32,
						 path, dat.mode);
				return ret;
			}
			WARNING_WITH_ERRNO("\"%s\": unable to set mode=0%"PRIo32,
					   path, dat.mode);
		}
	}

	return 0;
}

//* Set DOS name of the created file with ntfs-3g extended attribute
static void
unix_set_dos_name(const struct wim_dentry *dentry,
		  const char *path)
{
	if (dentry->d_short_name)
	{
		int ret;
		const char *dos_name;
		size_t dos_name_nbytes;

		ret = utf16le_get_tstr(dentry->d_short_name, dentry->d_short_name_nbytes, &dos_name, &dos_name_nbytes);

		if (!ret)
		{
			ret = lsetxattr(path, "system.ntfs_dos_name", dos_name, dos_name_nbytes, 0);
			if (unlikely(ret))
			{
				WARNING_WITH_ERRNO("Failed to set DOS name of \"%s\" in NTFS-3g mount point directory", path);
			}
		}
		utf16le_put_tstr(dos_name);
	}
}

/*
 * Set metadata on an extracted file.
 *
 * @fd is an open file descriptor to the extracted file, or -1.  @path is the
 * path to the extracted file, or NULL.  If valid, this function uses @fd.
 * Otherwise, if valid, it uses @path.  Otherwise, it calculates the path to one
 * alias of the extracted file and uses it.
 */
static int
unix_set_metadata(int fd, const struct wim_inode *inode,
		  const char *path, struct unix_with_attr_apply_ctx *ctx)
{
	int ret;

	if (fd < 0 && !path)
		path = unix_build_inode_extraction_path(inode, ctx);

	if (ctx->common.extract_flags & WIMLIB_EXTRACT_FLAG_UNIX_DATA) {
		ret = apply_unix_metadata(fd, inode, path, ctx);
		if (ret)
			return ret;
	}

	ret = unix_set_timestamps(fd, path, inode->i_last_access_time,
				  inode->i_last_write_time);
	if (ret) {
		if (!path)
			path = unix_build_inode_extraction_path(inode, ctx);
		if (ctx->common.extract_flags &
		    WIMLIB_EXTRACT_FLAG_STRICT_TIMESTAMPS)
		{
			ERROR_WITH_ERRNO("\"%s\": unable to set timestamps", path);
			return ret;
		}
		WARNING_WITH_ERRNO("\"%s\": unable to set timestamps", path);
	}

	//* set ntfs file attribute with ntfs-3g attribute - compression attribute handled here?
	ret =  fd > 0 ? fsetxattr(fd, "system.ntfs_attrib", &inode->i_attributes, sizeof(inode->i_attributes), 0) : 
	lsetxattr(path, "system.ntfs_attrib", &inode->i_attributes, sizeof(inode->i_attributes), 0);
	if (ret) {
		WARNING_WITH_ERRNO("\"%s\": unable to set ntfs attributes", path);
	}

	//* set ntfs file time with ntfs-3g attribute - automatically set when setting unix timestamp in ntfs-3g mount point?
	u64 buf[4] = { inode->i_creation_time, inode->i_last_write_time, inode->i_last_access_time, (u64)0 };
	ret = fd > 0 ? fsetxattr(fd, "system.ntfs_times", buf, sizeof(buf), 0) : 
	lsetxattr(path, "system.ntfs_times", buf, sizeof(buf), 0);
	if (ret) {
		WARNING_WITH_ERRNO("\"%s\": unable to set ntfs timestamp", path);
	}

	//* set ntfs object id with ntfs-3g attribute
	const void *object_id;
	u32 len;

	object_id = inode_get_object_id(inode, &len);
	if (unlikely(object_id != NULL)) {
		ret = fd > 0 ? fsetxattr(fd, "system.ntfs_object_id", object_id, len, 0) : 
		lsetxattr(path, "system.ntfs_object_id", object_id, len, 0);
		if (ret) {
			WARNING_WITH_ERRNO("\"%s\": unable to set ntfs object id", path);
		}
	}

	//* set ntfs extended attributes(EA) with ntfs-3g attribute
	const void *entries;

	entries = inode_get_xattrs(inode, &len);
	if (unlikely(entries != NULL && len != 0)) {
		ret = fd > 0 ? fsetxattr(fd, "system.ntfs_ea", entries, len, 0) : 
		lsetxattr(path, "system.ntfs_ea", object_id, len, 0);
		if (ret) {
			WARNING_WITH_ERRNO("\"%s\": unable to set ntfs extended attribute(EA)", path);
		}
	}
	
	//* set ntfs security descriptor with ntfs-3g attribute
	if (inode_has_security_descriptor(inode) && 
		!(ctx->common.extract_flags & WIMLIB_EXTRACT_FLAG_NO_ACLS))
	{
		const struct wim_security_data *sd;
		const void *desc;
		size_t desc_size;

		sd = wim_get_current_security_data(ctx->common.wim);
		desc = sd->descriptors[inode->i_security_id];
		desc_size = sd->sizes[inode->i_security_id];

		ret = fd > 0 ? fsetxattr(fd, "system.ntfs_acl", desc, desc_size, 0) : 
		lsetxattr(path, "system.ntfs_acl", desc, desc_size, 0);
		if (ret) {
			WARNING_WITH_ERRNO("Can't set security descriptor on \"%s\"", path);
		}
	}

	return 0;
}

/* Extract all needed aliases of the @inode, where one alias, corresponding to
 * @first_dentry, has already been extracted to @first_path.  */
static int
unix_create_hardlinks(const struct wim_inode *inode,
		      const struct wim_dentry *first_dentry,
		      const char *first_path, struct unix_with_attr_apply_ctx *ctx)
{
	const struct wim_dentry *dentry;
	const char *newpath;

	inode_for_each_extraction_alias(dentry, inode) {
		if (dentry == first_dentry)
			continue;

		newpath = unix_build_extraction_path(dentry, ctx);
	retry_link:
		if (link(first_path, newpath)) {
			if (errno == EEXIST && !unlink(newpath))
				goto retry_link;
			ERROR_WITH_ERRNO("Can't create hard link "
					 "\"%s\" => \"%s\"", newpath, first_path);
			return WIMLIB_ERR_LINK;
		}
		unix_reuse_pathbuf(ctx);
	}
	return 0;
}

/* Prepare file or directory to be used for reparse point
	as ntfs-3g needs a file entry to inject extended attribute. */
static int
unix_prepare_reparse_points(const struct wim_dentry *dentry,
			 struct unix_with_attr_apply_ctx *ctx)
{
	const char *path;
	struct stat stbuf;
	int ret;

	path = unix_build_extraction_path(dentry, ctx);

	if (inode_is_symlink(dentry->d_inode)) {
		if (dentry->d_inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			if (mkdir(path, 0755) &&
				!errno == EEXIST && !lstat(path, &stbuf) && S_ISDIR(stbuf.st_mode))
				{
					ERROR_WITH_ERRNO("Can't create directory \"%s\"", path);
					return WIMLIB_ERR_MKDIR;
				}
		}
		else
		{
			int fd;

retry_create:
			fd = open(path, O_EXCL | O_CREAT | O_WRONLY | O_NOFOLLOW, 0644);
			if (fd < 0) {
				if (errno == EEXIST && !unlink(path))
					goto retry_create;
				ERROR_WITH_ERRNO("Can't create regular file \"%s\"", path);
				return WIMLIB_ERR_OPEN;
			}
			/* On empty files, we can set timestamps immediately because we
			* don't need to write any data to them.  */
			ret = unix_set_metadata(fd, dentry->d_inode, path, ctx);
			if (close(fd) && !ret) {
				ERROR_WITH_ERRNO("Error closing \"%s\"", path);
				ret = WIMLIB_ERR_WRITE;
			}
		}
	}

	return 0;
}

/* If @dentry represents a directory, create it.  */
static int
unix_create_if_directory(const struct wim_dentry *dentry,
			 struct unix_with_attr_apply_ctx *ctx)
{
	const char *path;
	struct stat stbuf;

	if (!should_extract_as_directory(dentry->d_inode))
		return 0;

	path = unix_build_extraction_path(dentry, ctx);
	if (mkdir(path, 0755) &&
	    /* It's okay if the path already exists, as long as it's a
	     * directory.  */
	    !(errno == EEXIST && !lstat(path, &stbuf) && S_ISDIR(stbuf.st_mode)))
	{
		ERROR_WITH_ERRNO("Can't create directory \"%s\"", path);
		return WIMLIB_ERR_MKDIR;
	}

	unix_set_dos_name(dentry, path);

	return report_file_created(&ctx->common);
}

/* If @dentry represents an empty regular file or a special file, create it, set
 * its metadata, and create any needed hard links.  */
static int
unix_extract_if_empty_file(const struct wim_dentry *dentry,
			   struct unix_with_attr_apply_ctx *ctx)
{
	const struct wim_inode *inode;
	struct wimlib_unix_data unix_data;
	const char *path;
	int ret;

	inode = dentry->d_inode;

	/* Extract all aliases only when the "first" comes up.  */
	if (dentry != inode_first_extraction_dentry(inode))
		return 0;

	/* Is this a directory, a symbolic link, or any type of nonempty file?
	 */
	if (should_extract_as_directory(inode) || inode_is_symlink(inode) ||
	    inode_get_blob_for_unnamed_data_stream_resolved(inode))
		return 0;

	/* Recognize special files in UNIX_DATA mode  */
	if ((ctx->common.extract_flags & WIMLIB_EXTRACT_FLAG_UNIX_DATA) &&
	    inode_get_unix_data(inode, &unix_data) &&
	    !S_ISREG(unix_data.mode))
	{
		path = unix_build_extraction_path(dentry, ctx);
	retry_mknod:
		if (mknod(path, unix_data.mode, unix_data.rdev)) {
			if (errno == EPERM) {
				WARNING_WITH_ERRNO("Can't create special "
						   "file \"%s\"", path);
				ctx->num_special_files_ignored++;
				return 0;
			}
			if (errno == EEXIST && !unlink(path))
				goto retry_mknod;
			ERROR_WITH_ERRNO("Can't create special file \"%s\"",
					 path);
			return WIMLIB_ERR_MKNOD;
		}
		/* On special files, we can set timestamps immediately because
		 * we don't need to write any data to them.  */
		ret = unix_set_metadata(-1, inode, path, ctx);
	} else {
		int fd;

		path = unix_build_extraction_path(dentry, ctx);
	retry_create:
		fd = open(path, O_EXCL | O_CREAT | O_WRONLY | O_NOFOLLOW, 0644);
		if (fd < 0) {
			if (errno == EEXIST && !unlink(path))
				goto retry_create;
			ERROR_WITH_ERRNO("Can't create regular file \"%s\"", path);
			return WIMLIB_ERR_OPEN;
		}
		/* On empty files, we can set timestamps immediately because we
		 * don't need to write any data to them.  */
		ret = unix_set_metadata(fd, inode, path, ctx);
		if (close(fd) && !ret) {
			ERROR_WITH_ERRNO("Error closing \"%s\"", path);
			ret = WIMLIB_ERR_WRITE;
		}
	}
	if (ret)
		return ret;

	unix_set_dos_name(dentry, path);

	ret = unix_create_hardlinks(inode, dentry, path, ctx);
	if (ret)
		return ret;

	return report_file_created(&ctx->common);
}

static int
unix_create_dirs_and_empty_files(const struct list_head *dentry_list,
				 struct unix_with_attr_apply_ctx *ctx)
{
	const struct wim_dentry *dentry;
	int ret;

	list_for_each_entry(dentry, dentry_list, d_extraction_list_node) {
		ret = unix_create_if_directory(dentry, ctx);
		if (ret)
			return ret;
	}
	list_for_each_entry(dentry, dentry_list, d_extraction_list_node) {
		ret = unix_extract_if_empty_file(dentry, ctx);
		if (ret)
			return ret;
	}
	list_for_each_entry(dentry, dentry_list, d_extraction_list_node) {
		ret = unix_prepare_reparse_points(dentry, ctx);
		if (ret)
			return ret;
	}
	return 0;
}

static void
unix_count_dentries(const struct list_head *dentry_list,
		    u64 *dir_count_ret, u64 *empty_file_count_ret)
{
	const struct wim_dentry *dentry;
	u64 dir_count = 0;
	u64 empty_file_count = 0;

	list_for_each_entry(dentry, dentry_list, d_extraction_list_node) {

		const struct wim_inode *inode = dentry->d_inode;

		if (should_extract_as_directory(inode))
			dir_count++;
		else if ((dentry == inode_first_extraction_dentry(inode)) &&
			 !inode_is_symlink(inode) &&
			 !inode_get_blob_for_unnamed_data_stream_resolved(inode))
			empty_file_count++;
	}

	*dir_count_ret = dir_count;
	*empty_file_count_ret = empty_file_count;
}

/* As ntfs-3g automatically set reparse point as symlink or junction,
 * we don't have to create symlink manually. */
static int
unix_set_reparse_data(const struct wim_dentry *dentry,
	const struct reparse_buffer_disk *rpbuf,
	u16 rpbuflen,
	struct unix_with_attr_apply_ctx *ctx)
{
	int ret;
	const char *path;

	path = unix_build_extraction_path(dentry, ctx);
	ret = lsetxattr(path, "system.ntfs_reparse_data", rpbuf, rpbuflen, 0);
	if (ret) {
		ERROR_WITH_ERRNO("Failed to create reparse point for \"%s\"", path);
	}

	return ret;
}

static void
unix_cleanup_open_fds(struct unix_with_attr_apply_ctx *ctx, unsigned offset)
{
	for (unsigned i = offset; i < ctx->num_open_fds; i++)
		filedes_close(&ctx->open_fds[i]);
	ctx->num_open_fds = 0;
	ctx->any_sparse_files = false;
}

/* Prepare to read the next blob, which has size @blob_size, into an in-memory
 * buffer.  */
static bool
prepare_data_buffer(struct unix_with_attr_apply_ctx *ctx, u64 blob_size)
{
	if (blob_size > ctx->data_buffer_size) {
		/* Larger buffer needed.  */
		void *new_buffer;
		if ((size_t)blob_size != blob_size)
			return false;
		new_buffer = REALLOC(ctx->data_buffer, blob_size);
		if (!new_buffer)
			return false;
		ctx->data_buffer = new_buffer;
		ctx->data_buffer_size = blob_size;
	}
	/* On the first call this changes data_buffer_ptr from NULL, which tells
	 * extract_chunk() that the data buffer needs to be filled while reading
	 * the stream data.  */
	ctx->data_buffer_ptr = ctx->data_buffer;
	return true;
}

static int
unix_begin_extract_blob_instance(const struct blob_descriptor *blob,
				 struct wim_dentry *dentry,
				 const struct wim_inode_stream *strm,
				 struct unix_with_attr_apply_ctx *ctx)
{
	int fd;
	int ret;
	const char *path;

	if (unlikely(strm->stream_type == STREAM_TYPE_REPARSE_POINT)) {
		if (!prepare_data_buffer(ctx, blob->size))
			return WIMLIB_ERR_NOMEM;
		list_add_tail(&dentry->d_tmp_list, &ctx->reparse_dentries);
		return 0;
	}

	if (unlikely(strm->stream_type == STREAM_TYPE_EFSRPC_RAW_DATA)) {
		/* We can't write encrypted files directly; we must use
		 * WriteEncryptedFileRaw(), which requires providing the data
		 * through a callback function.  This can't easily be combined
		 * with our own callback-based approach.
		 *
		 * The current workaround is to simply read the blob into memory
		 * and write the encrypted file from that.
		 *
		 * TODO: This isn't sufficient for extremely large encrypted
		 * files.  Perhaps we should create an extra thread to write
		 * such files...  */
		if (!prepare_data_buffer(ctx, blob->size))
			return WIMLIB_ERR_NOMEM;
		list_add_tail(&dentry->d_tmp_list, &ctx->encrypted_dentries);
		return 0;
	}

	wimlib_assert(stream_is_unnamed_data_stream(strm));

	/* Unnamed data stream of "regular" file  */

	/* This should be ensured by extract_blob_list()  */
	wimlib_assert(ctx->num_open_fds < MAX_OPEN_FILES);

	path = unix_build_extraction_path(dentry, ctx);
retry_create:
	fd = open(path, O_EXCL | O_CREAT | O_WRONLY | O_NOFOLLOW, 0644);
	if (fd < 0) {
		if (errno == EEXIST && !unlink(path))
			goto retry_create;
		ERROR_WITH_ERRNO("Can't create regular file \"%s\"", path);
		return WIMLIB_ERR_OPEN;
	}
	if (dentry->d_inode->i_attributes & FILE_ATTRIBUTE_SPARSE_FILE) {
		ctx->is_sparse_file[ctx->num_open_fds] = true;
		ctx->any_sparse_files = true;
	} else {
		ctx->is_sparse_file[ctx->num_open_fds] = false;
#ifdef HAVE_POSIX_FALLOCATE
		posix_fallocate(fd, 0, blob->size);
#endif
	}
	filedes_init(&ctx->open_fds[ctx->num_open_fds++], fd);

	/* Set DOS name of file if exists */
	unix_set_dos_name(dentry, path);

	return 0;
}

/* Import the next block of raw encrypted data  */
static void
import_encrypted_data(char* pbData, void* pvCallbackContext, long *Length)
{
	struct unix_with_attr_apply_ctx *ctx = pvCallbackContext;
	long copy_len;

	copy_len = min(ctx->encrypted_size - ctx->encrypted_offset, *Length);
	memcpy(pbData, &ctx->data_buffer[ctx->encrypted_offset], copy_len);
	ctx->encrypted_offset += copy_len;
	*Length = copy_len;
}

/*
 * Write the raw encrypted data to the already-created file (or directory)
 * corresponding to @dentry.
 *
 * The raw encrypted data is provided in ctx->data_buffer, and its size is
 * ctx->encrypted_size.
 *
 * This function may close the target directory, in which case the caller needs
 * to re-open it if needed.
 */
static int
extract_encrypted_file(const struct wim_dentry *dentry,
					struct unix_with_attr_apply_ctx *ctx)
{
	void *rawctx;
	int ret;
	const char *path;
	// bool retried;

	path = unix_build_extraction_path(dentry, ctx);

	// *TODO
	return 0;
}

/* Called when starting to read a blob for extraction  */
static int
unix_begin_extract_blob(struct blob_descriptor *blob, void *_ctx)
{
	struct unix_with_attr_apply_ctx *ctx = _ctx;
	const struct blob_extraction_target *targets = blob_extraction_targets(blob);
	int ret;

	ctx->num_open_fds = 0;
	ctx->data_buffer_ptr = NULL;
	ctx->any_sparse_files = false;
	INIT_LIST_HEAD(&ctx->reparse_dentries);
	INIT_LIST_HEAD(&ctx->encrypted_dentries);

	for (u32 i = 0; i < blob->out_refcnt; i++) {
		const struct wim_inode *inode = targets[i].inode;
		const struct wim_inode_stream *strm = targets[i].stream;
		struct wim_dentry *dentry;
		dentry = inode_first_extraction_dentry(inode);
		ret = unix_begin_extract_blob_instance(blob, dentry, strm, ctx);
		if (ret) {
			unix_cleanup_open_fds(ctx, 0);
			return ret;
		}
	}
	return 0;
}

/* Called when the next chunk of a blob has been read for extraction  */
static int
unix_extract_chunk(const struct blob_descriptor *blob, u64 offset,
		   const void *chunk, size_t size, void *_ctx)
{
	struct unix_with_attr_apply_ctx *ctx = _ctx;
	const void * const end = chunk + size;
	const void *p;
	bool zeroes;
	size_t len;
	unsigned i;
	int ret;

	/*
	 * For sparse files, only write nonzero regions.  This lets the
	 * filesystem use holes to represent zero regions.
	 */
	for (p = chunk; p != end; p += len, offset += len) {
		zeroes = maybe_detect_sparse_region(p, end - p, &len,
						    ctx->any_sparse_files);
		for (i = 0; i < ctx->num_open_fds; i++) {
			if (!zeroes || !ctx->is_sparse_file[i]) {
				ret = full_pwrite(&ctx->open_fds[i],
						  p, len, offset);
				if (ret)
					goto err;
			}
		}
	}

	if (ctx->data_buffer_ptr)
		ctx->data_buffer_ptr = mempcpy(ctx->data_buffer_ptr, chunk, size);
	return 0;

err:
	ERROR_WITH_ERRNO("Error writing data to filesystem");
	return ret;
}

/* Called when a blob has been fully read for extraction  */
static int
unix_end_extract_blob(struct blob_descriptor *blob, int status, void *_ctx)
{
	struct unix_with_attr_apply_ctx *ctx = _ctx;
	int ret;
	const char *path;
	const struct blob_extraction_target *targets = blob_extraction_targets(blob);
	const struct wim_dentry *dentry;

	if (status) {
		unix_cleanup_open_fds(ctx, 0);
		return status;
	}

	for (unsigned i = 0; i < ctx->num_open_fds; i++) {
		struct wim_inode *inode = targets[i].inode;

		struct filedes *fd = &ctx->open_fds[i];

		/* If the file is sparse, extend it to its final size. */
		if (ctx->is_sparse_file[i] && ftruncate(fd->fd, blob->size)) {
			ERROR_WITH_ERRNO("Error extending \"%s\" to final size",
						unix_build_inode_extraction_path(inode, ctx));
			ret = WIMLIB_ERR_WRITE;
			break;
		}

		/* Set metadata on regular file just before closing.  */
		ret = unix_set_metadata(fd->fd, inode, NULL, ctx);
		if (ret)
			break;

		if (filedes_close(fd)) {
			ERROR_WITH_ERRNO("Error closing \"%s\"",
						unix_build_inode_extraction_path(inode, ctx));
			ret = WIMLIB_ERR_WRITE;
			break;
		}

	}

	unix_cleanup_open_fds(ctx, 0);

	if (likely(!ctx->data_buffer_ptr))
		return 0;

	if (!list_empty(&ctx->reparse_dentries)) {
		if (blob->size > REPARSE_DATA_MAX_SIZE) {
			dentry = list_first_entry(&ctx->reparse_dentries,
						  struct wim_dentry, d_tmp_list);
			path = unix_build_extraction_path(dentry, ctx);
			ERROR("Reparse data of \"%s\" has size "
			      "%"PRIu64" bytes (exceeds %u bytes)",
			      path, blob->size,
			      REPARSE_DATA_MAX_SIZE);
			ret = WIMLIB_ERR_INVALID_REPARSE_DATA;
			return ret;
		}

		/* Reparse data  */
		memcpy(ctx->rpbuf.rpdata, ctx->data_buffer, blob->size);

		list_for_each_entry(dentry, &ctx->reparse_dentries, d_tmp_list) {
			/* Reparse point header  */
			complete_reparse_point(&ctx->rpbuf, dentry->d_inode,
			        	    blob->size);

			ret = unix_set_reparse_data(dentry, &ctx->rpbuf,
						REPARSE_DATA_OFFSET + blob->size,
						ctx);
			if (ret) {
				return ret;
			}
		}
	}

	/* -----------TODO------------ 
		Extract efs files and directories.
	*/

	// if (!list_empty(&ctx->encrypted_dentries)) {
	// 	ctx->encrypted_size = blob->size;
	// 	list_for_each_entry(dentry, &ctx->encrypted_dentries, d_tmp_list) {
			
	// 	}
	// }

	return 0;
}

static int
unix_set_dir_metadata(struct list_head *dentry_list, struct unix_with_attr_apply_ctx *ctx)
{
	const struct wim_dentry *dentry;
	int ret;

	list_for_each_entry_reverse(dentry, dentry_list, d_extraction_list_node) {
		if (should_extract_as_directory(dentry->d_inode)) {
			ret = unix_set_metadata(-1, dentry->d_inode, NULL, ctx);
			if (ret)
				return ret;
			ret = report_file_metadata_applied(&ctx->common);
			if (ret)
				return ret;
		}
	}
	return 0;
}

static int
unix_with_attr_extract(struct list_head *dentry_list, struct apply_ctx *_ctx)
{
	int ret;
	struct unix_with_attr_apply_ctx *ctx = (struct unix_with_attr_apply_ctx *)_ctx;
	size_t path_max;
	u64 dir_count;
	u64 empty_file_count;

	/* Compute the maximum path length that will be needed, then allocate
	 * some path buffers.  */
	path_max = unix_compute_path_max(dentry_list, ctx);

	for (unsigned i = 0; i < NUM_PATHBUFS; i++) {
		ctx->pathbufs[i] = MALLOC(path_max);
		if (!ctx->pathbufs[i]) {
			ret = WIMLIB_ERR_NOMEM;
			goto out;
		}
		/* Pre-fill the target in each path buffer.  We'll just append
		 * the rest of the paths after this.  */
		memcpy(ctx->pathbufs[i],
		       ctx->common.target, ctx->common.target_nchars);
	}

	/* Extract directories and empty regular files.  Directories are needed
	 * because we can't extract any other files until their directories
	 * exist.  Empty files are needed because they don't have
	 * representatives in the blob list.  */

	unix_count_dentries(dentry_list, &dir_count, &empty_file_count);

	ret = start_file_structure_phase(&ctx->common, dir_count + empty_file_count);
	if (ret)
		goto out;

	ret = unix_create_dirs_and_empty_files(dentry_list, ctx);
	if (ret)
		goto out;

	ret = end_file_structure_phase(&ctx->common);
	if (ret)
		goto out;

	/* Get full path to target if needed for absolute symlink fixups.  */
	if ((ctx->common.extract_flags & WIMLIB_EXTRACT_FLAG_RPFIX) &&
	    ctx->common.required_features.symlink_reparse_points)
	{
		ctx->target_abspath = realpath(ctx->common.target, NULL);
		if (!ctx->target_abspath) {
			ret = WIMLIB_ERR_NOMEM;
			goto out;
		}
		ctx->target_abspath_nchars = strlen(ctx->target_abspath);
	}

	/* Extract nonempty regular files and symbolic links.  */

	struct read_blob_callbacks cbs = {
		.begin_blob	= unix_begin_extract_blob,
		.continue_blob	= unix_extract_chunk,
		.end_blob	= unix_end_extract_blob,
		.ctx		= ctx,
	};
	ret = extract_blob_list(&ctx->common, &cbs);
	if (ret)
		goto out;


	/* Set directory metadata.  We do this last so that we get the right
	 * directory timestamps.  */
	ret = start_file_metadata_phase(&ctx->common, dir_count);
	if (ret)
		goto out;

	ret = unix_set_dir_metadata(dentry_list, ctx);
	if (ret)
		goto out;

	ret = end_file_metadata_phase(&ctx->common);
	if (ret)
		goto out;

	if (ctx->num_special_files_ignored) {
		WARNING("%lu special files were not extracted due to EPERM!",
			ctx->num_special_files_ignored);
	}
out:
	for (unsigned i = 0; i < NUM_PATHBUFS; i++)
		FREE(ctx->pathbufs[i]);
	FREE(ctx->target_abspath);
	return ret;
}

const struct apply_operations unix_with_attr_apply_ops = {
	.name			= "UNIX_WITH_ATTR",
	.get_supported_features = unix_with_attr_get_supported_features,
	.extract                = unix_with_attr_extract,
	.context_size           = sizeof(struct unix_with_attr_apply_ctx),
};
