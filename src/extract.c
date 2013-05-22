/*
 * extract.c
 *
 * Support for extracting WIM images, or files or directories contained in a WIM
 * image.
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
 *
 * This file is part of wimlib, a library for working with WIM files.
 *
 * wimlib is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 *
 * wimlib is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wimlib; if not, see http://www.gnu.org/licenses/.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#ifdef __WIN32__
#  include "wimlib/win32_common.h" /* For GetFullPathName() */
#endif

#include "wimlib/apply.h"
#include "wimlib/dentry.h"
#include "wimlib/encoding.h"
#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/lookup_table.h"
#include "wimlib/paths.h"
#include "wimlib/resource.h"
#include "wimlib/swm.h"
#ifdef __WIN32__
#  include "wimlib/win32.h" /* for realpath() equivalent */
#endif
#include "wimlib/xml.h"

#include <errno.h>
#include <limits.h>
#ifdef WITH_NTFS_3G
#  include <ntfs-3g/volume.h> /* for ntfs_mount(), ntfs_umount() */
#endif
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_EXTRACT_LONG_PATH_WARNINGS 5

static int
do_apply_op(struct wim_dentry *dentry, struct apply_args *args,
	    int (*apply_dentry_func)(const tchar *, size_t,
				     struct wim_dentry *, struct apply_args *))
{
	tchar *p;
	size_t extraction_path_nchars;
	struct wim_dentry *d;
	LIST_HEAD(ancestor_list);
	const tchar *target;
	size_t target_nchars;

#ifdef __WIN32__
	if (args->target_lowlevel_path) {
		target = args->target_lowlevel_path;
		target_nchars = args->target_lowlevel_path_nchars;
	} else
#endif
	{
		target = args->target;
		target_nchars = args->target_nchars;
	}

	extraction_path_nchars = target_nchars;

	for (d = dentry; d != args->extract_root; d = d->parent) {
		if (d->not_extracted)
			return 0;
		extraction_path_nchars += d->extraction_name_nchars + 1;
		list_add(&d->tmp_list, &ancestor_list);
	}

	tchar extraction_path[extraction_path_nchars + 1];
	p = tmempcpy(extraction_path, target, target_nchars);


	list_for_each_entry(d, &ancestor_list, tmp_list) {
		*p++ = OS_PREFERRED_PATH_SEPARATOR;
		p = tmempcpy(p, d->extraction_name, d->extraction_name_nchars);
	}
	*p = T('\0');

#ifdef __WIN32__
	/* Warn the user if the path exceeds MAX_PATH */

	/* + 1 for '\0', -4 for \\?\.  */
	if (extraction_path_nchars + 1 - 4 > MAX_PATH) {
		if (dentry->needs_extraction &&
		    args->num_long_paths < MAX_EXTRACT_LONG_PATH_WARNINGS)
		{
			WARNING("Path \"%ls\" exceeds MAX_PATH and will not be accessible "
				"to most Windows software", extraction_path);
			if (++args->num_long_paths == MAX_EXTRACT_LONG_PATH_WARNINGS)
				WARNING("Suppressing further warnings about long paths");
		}
	}
#endif
	return (*apply_dentry_func)(extraction_path, extraction_path_nchars,
				    dentry, args);
}


/* Extracts a file, directory, or symbolic link from the WIM archive. */
static int
apply_dentry_normal(struct wim_dentry *dentry, void *arg)
{
#ifdef __WIN32__
	return do_apply_op(dentry, arg, win32_do_apply_dentry);
#else
	return do_apply_op(dentry, arg, unix_do_apply_dentry);
#endif
}


/* Apply timestamps to an extracted file or directory */
static int
apply_dentry_timestamps_normal(struct wim_dentry *dentry, void *arg)
{
#ifdef __WIN32__
	return do_apply_op(dentry, arg, win32_do_apply_dentry_timestamps);
#else
	return do_apply_op(dentry, arg, unix_do_apply_dentry_timestamps);
#endif
}

static bool
dentry_is_dot_or_dotdot(const struct wim_dentry *dentry)
{
	const utf16lechar *file_name = dentry->file_name;
	return file_name != NULL &&
		file_name[0] == cpu_to_le16('.') &&
		(file_name[1] == cpu_to_le16('\0') ||
		 (file_name[1] == cpu_to_le16('.') &&
		  file_name[2] == cpu_to_le16('\0')));
}

/* Extract a dentry if it hasn't already been extracted and either
 * WIMLIB_EXTRACT_FLAG_NO_STREAMS is not specified, or the dentry is a directory
 * and/or has no unnamed stream. */
static int
maybe_apply_dentry(struct wim_dentry *dentry, void *arg)
{
	struct apply_args *args = arg;
	int ret;

	if (!dentry->needs_extraction)
		return 0;

	if (args->extract_flags & WIMLIB_EXTRACT_FLAG_NO_STREAMS &&
	    !dentry_is_directory(dentry) &&
	    inode_unnamed_lte_resolved(dentry->d_inode) != NULL)
		return 0;

	if ((args->extract_flags & WIMLIB_EXTRACT_FLAG_VERBOSE) &&
	     args->progress_func) {
		ret = calculate_dentry_full_path(dentry);
		if (ret)
			return ret;
		args->progress.extract.cur_path = dentry->_full_path;
		args->progress_func(WIMLIB_PROGRESS_MSG_EXTRACT_DENTRY,
				    &args->progress);
	}
	ret = args->apply_dentry(dentry, args);
	if (ret == 0)
		dentry->needs_extraction = 0;
	return ret;
}

static void
calculate_bytes_to_extract(struct list_head *stream_list,
			   int extract_flags,
			   union wimlib_progress_info *progress)
{
	struct wim_lookup_table_entry *lte;
	u64 total_bytes = 0;
	u64 num_streams = 0;

	/* For each stream to be extracted... */
	list_for_each_entry(lte, stream_list, extraction_list) {
		if (extract_flags &
		    (WIMLIB_EXTRACT_FLAG_SYMLINK | WIMLIB_EXTRACT_FLAG_HARDLINK))
		{
			/* In the symlink or hard link extraction mode, each
			 * stream will be extracted one time regardless of how
			 * many dentries share the stream. */
			wimlib_assert(!(extract_flags & WIMLIB_EXTRACT_FLAG_NTFS));
			if (!lte->extracted_file) {
				num_streams++;
				total_bytes += wim_resource_size(lte);
			}
		} else {
			num_streams += lte->out_refcnt;
			total_bytes += lte->out_refcnt * wim_resource_size(lte);
		}
	}
	progress->extract.num_streams = num_streams;
	progress->extract.total_bytes = total_bytes;
	progress->extract.completed_bytes = 0;
}

static void
maybe_add_stream_for_extraction(struct wim_lookup_table_entry *lte,
				struct list_head *stream_list)
{
	if (++lte->out_refcnt == 1) {
		INIT_LIST_HEAD(&lte->lte_dentry_list);
		list_add_tail(&lte->extraction_list, stream_list);
	}
}

struct find_streams_ctx {
	struct list_head stream_list;
	int extract_flags;
};

static int
dentry_find_streams_to_extract(struct wim_dentry *dentry, void *_ctx)
{
	struct find_streams_ctx *ctx = _ctx;
	struct wim_inode *inode = dentry->d_inode;
	struct wim_lookup_table_entry *lte;
	bool dentry_added = false;
	struct list_head *stream_list = &ctx->stream_list;
	int extract_flags = ctx->extract_flags;

	if (!dentry->needs_extraction)
		return 0;

	lte = inode_unnamed_lte_resolved(inode);
	if (lte) {
		if (!inode->i_visited)
			maybe_add_stream_for_extraction(lte, stream_list);
		list_add_tail(&dentry->extraction_stream_list, &lte->lte_dentry_list);
		dentry_added = true;
	}

	/* Determine whether to include alternate data stream entries or not.
	 *
	 * UNIX:  Include them if extracting using NTFS-3g.
	 *
	 * Windows: Include them undconditionally, although if the filesystem is
	 * not NTFS we won't actually be able to extract them. */
#if defined(WITH_NTFS_3G)
	if (extract_flags & WIMLIB_EXTRACT_FLAG_NTFS)
#elif defined(__WIN32__)
	if (1)
#else
	if (0)
#endif
	{
		for (unsigned i = 0; i < inode->i_num_ads; i++) {
			if (inode->i_ads_entries[i].stream_name_nbytes != 0) {
				lte = inode->i_ads_entries[i].lte;
				if (lte) {
					if (!inode->i_visited) {
						maybe_add_stream_for_extraction(lte,
										stream_list);
					}
					if (!dentry_added) {
						list_add_tail(&dentry->extraction_stream_list,
							      &lte->lte_dentry_list);
						dentry_added = true;
					}
				}
			}
		}
	}
	inode->i_visited = 1;
	return 0;
}

static int
dentry_resolve_and_zero_lte_refcnt(struct wim_dentry *dentry, void *_lookup_table)
{
	struct wim_inode *inode = dentry->d_inode;
	struct wim_lookup_table *lookup_table = _lookup_table;
	struct wim_lookup_table_entry *lte;
	int ret;

	ret = inode_resolve_ltes(inode, lookup_table);
	if (ret)
		return ret;
	for (unsigned i = 0; i <= inode->i_num_ads; i++) {
		lte = inode_stream_lte_resolved(inode, i);
		if (lte)
			lte->out_refcnt = 0;
	}
	return 0;
}

static int
find_streams_for_extraction(struct wim_dentry *root,
			    struct list_head *stream_list,
			    struct wim_lookup_table *lookup_table,
			    int extract_flags)
{
	struct find_streams_ctx ctx;
	int ret;

	INIT_LIST_HEAD(&ctx.stream_list);
	ctx.extract_flags = extract_flags;
	ret = for_dentry_in_tree(root, dentry_resolve_and_zero_lte_refcnt, lookup_table);
	if (ret)
		return ret;
	for_dentry_in_tree(root, dentry_find_streams_to_extract, &ctx);
	list_transfer(&ctx.stream_list, stream_list);
	return 0;
}

struct apply_operations {
	int (*apply_dentry)(struct wim_dentry *dentry, void *arg);
	int (*apply_dentry_timestamps)(struct wim_dentry *dentry, void *arg);
};

static const struct apply_operations normal_apply_operations = {
	.apply_dentry = apply_dentry_normal,
	.apply_dentry_timestamps = apply_dentry_timestamps_normal,
};

#ifdef WITH_NTFS_3G
static const struct apply_operations ntfs_apply_operations = {
	.apply_dentry = apply_dentry_ntfs,
	.apply_dentry_timestamps = apply_dentry_timestamps_ntfs,
};
#endif

static int
apply_stream_list(struct list_head *stream_list,
		  struct apply_args *args,
		  const struct apply_operations *ops,
		  wimlib_progress_func_t progress_func)
{
	uint64_t bytes_per_progress = args->progress.extract.total_bytes / 100;
	uint64_t next_progress = bytes_per_progress;
	struct wim_lookup_table_entry *lte;
	struct wim_dentry *dentry;
	int ret;

	/* This complicated loop is essentially looping through the dentries,
	 * although dentries may be visited more than once (if a dentry contains
	 * two different nonempty streams) or not at all (if a dentry contains
	 * no non-empty streams).
	 *
	 * The outer loop is over the distinct streams to be extracted so that
	 * sequential reading of the WIM can be implemented. */

	/* For each distinct stream to be extracted */
	list_for_each_entry(lte, stream_list, extraction_list) {
		/* For each dentry to be extracted that is a name for an inode
		 * containing the stream */
		list_for_each_entry(dentry, &lte->lte_dentry_list, extraction_stream_list) {
			/* Extract the dentry if it was not already
			 * extracted */
			ret = maybe_apply_dentry(dentry, args);
			if (ret)
				return ret;
			if (progress_func &&
			    args->progress.extract.completed_bytes >= next_progress)
			{
				progress_func(WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS,
					      &args->progress);
				if (args->progress.extract.completed_bytes >=
				    args->progress.extract.total_bytes)
				{
					next_progress = ~0ULL;
				} else {
					next_progress =
						min (args->progress.extract.completed_bytes +
						     bytes_per_progress,
						     args->progress.extract.total_bytes);
				}
			}
		}
	}
	return 0;
}

static int
sort_stream_list_by_wim_position(struct list_head *stream_list)
{
	struct list_head *cur;
	size_t num_streams;
	struct wim_lookup_table_entry **array;
	size_t i;
	size_t array_size;

	num_streams = 0;
	list_for_each(cur, stream_list)
		num_streams++;
	array_size = num_streams * sizeof(array[0]);
	array = MALLOC(array_size);
	if (!array) {
		ERROR("Failed to allocate %zu bytes to sort stream entries",
		      array_size);
		return WIMLIB_ERR_NOMEM;
	}
	cur = stream_list->next;
	for (i = 0; i < num_streams; i++) {
		array[i] = container_of(cur, struct wim_lookup_table_entry, extraction_list);
		cur = cur->next;
	}

	qsort(array, num_streams, sizeof(array[0]), cmp_streams_by_wim_position);

	INIT_LIST_HEAD(stream_list);
	for (i = 0; i < num_streams; i++)
		list_add_tail(&array[i]->extraction_list, stream_list);
	FREE(array);
	return 0;
}

/*
 * Extract a dentry to standard output.
 *
 * This obviously doesn't make sense in all cases.  We return an error if the
 * dentry does not correspond to a regular file.  Otherwise we extract the
 * unnamed data stream only.
 */
static int
extract_dentry_to_stdout(struct wim_dentry *dentry)
{
	int ret = 0;
	if (!dentry_is_regular_file(dentry)) {
		ERROR("\"%"TS"\" is not a regular file and therefore cannot be "
		      "extracted to standard output", dentry->_full_path);
		ret = WIMLIB_ERR_NOT_A_REGULAR_FILE;
	} else {
		struct wim_lookup_table_entry *lte;

		lte = inode_unnamed_lte_resolved(dentry->d_inode);
		if (lte) {
			ret = extract_wim_resource_to_fd(lte, STDOUT_FILENO,
							 wim_resource_size(lte));
		}
	}
	return ret;
}

#ifdef __WIN32__
static const utf16lechar replacement_char = cpu_to_le16(0xfffd);
#else
static const utf16lechar replacement_char = cpu_to_le16('?');
#endif

static bool
file_name_valid(utf16lechar *name, size_t num_chars, bool fix)
{
	size_t i;

	if (num_chars == 0)
		return true;
	for (i = 0; i < num_chars; i++) {
		switch (name[i]) {
	#ifdef __WIN32__
		case cpu_to_le16('\\'):
		case cpu_to_le16(':'):
		case cpu_to_le16('*'):
		case cpu_to_le16('?'):
		case cpu_to_le16('"'):
		case cpu_to_le16('<'):
		case cpu_to_le16('>'):
		case cpu_to_le16('|'):
	#endif
		case cpu_to_le16('/'):
		case cpu_to_le16('\0'):
			if (fix)
				name[i] = replacement_char;
			else
				return false;
		}
	}

#ifdef __WIN32__
	if (name[num_chars - 1] == cpu_to_le16(' ') ||
	    name[num_chars - 1] == cpu_to_le16('.'))
	{
		if (fix)
			name[num_chars - 1] = replacement_char;
		else
			return false;
	}
#endif
	return true;
}

/*
 * dentry_calculate_extraction_path-
 *
 * Calculate the actual filename component at which a WIM dentry will be
 * extracted, handling invalid filenames "properly".
 *
 * dentry->extraction_name usually will be set the same as dentry->file_name (on
 * UNIX, converted into the platform's multibyte encoding).  However, if the
 * file name contains characters that are not valid on the current platform or
 * has some other format that is not valid, leave dentry->extraction_name as
 * NULL and clear dentry->needs_extraction to indicate that this dentry should
 * not be extracted, unless the appropriate flag
 * WIMLIB_EXTRACT_FLAG_REPLACE_INVALID_FILENAMES is set in the extract flags, in
 * which case a substitute filename will be created and set instead.
 *
 * Conflicts with case-insensitive names on Windows are handled similarly; see
 * below.
 */
static int
dentry_calculate_extraction_path(struct wim_dentry *dentry, void *_args)
{
	struct apply_args *args = _args;
	int ret;

	dentry->needs_extraction = 1;

	if (dentry == args->extract_root)
		return 0;

	if (dentry_is_dot_or_dotdot(dentry)) {
		/* WIM files shouldn't contain . or .. entries.  But if they are
		 * there, don't attempt to extract them. */
		WARNING("Skipping extraction of unexpected . or .. file \"%"TS"\"",
			dentry_full_path(dentry));
		goto skip_dentry;
	}

#ifdef __WIN32__
	struct wim_dentry *other;
	list_for_each_entry(other, &dentry->case_insensitive_conflict_list,
			    case_insensitive_conflict_list)
	{
		if (other->needs_extraction) {
			if (args->extract_flags & WIMLIB_EXTRACT_FLAG_ALL_CASE_CONFLICTS)
			{
				WARNING("\"%"TS"\" has the same case-insensitive "
					"name as \"%"TS"\"; extracting dummy name instead",
					dentry_full_path(dentry),
					dentry_full_path(other));
				goto out_replace;
			} else {
				WARNING("Not extracting \"%"TS"\": has same case-insensitive "
					"name as \"%"TS"\"",
					dentry_full_path(dentry),
					dentry_full_path(other));
				goto skip_dentry;
			}
		}
	}
#endif

	if (file_name_valid(dentry->file_name, dentry->file_name_nbytes / 2, false)) {
#ifdef __WIN32__
		dentry->extraction_name = dentry->file_name;
		dentry->extraction_name_nchars = dentry->file_name_nbytes / 2;
		return 0;
#else
		return utf16le_to_tstr(dentry->file_name,
				       dentry->file_name_nbytes,
				       &dentry->extraction_name,
				       &dentry->extraction_name_nchars);
#endif
	} else {
		if (args->extract_flags & WIMLIB_EXTRACT_FLAG_REPLACE_INVALID_FILENAMES)
		{
			WARNING("\"%"TS"\" has an invalid filename "
				"that is not supported on this platform; "
				"extracting dummy name instead",
				dentry_full_path(dentry));
			goto out_replace;
		} else {
			WARNING("Not extracting \"%"TS"\": has an invalid filename "
				"that is not supported on this platform",
				dentry_full_path(dentry));
			goto skip_dentry;
		}
	}

out_replace:
	{
		utf16lechar utf16_name_copy[dentry->file_name_nbytes / 2];

		memcpy(utf16_name_copy, dentry->file_name, dentry->file_name_nbytes);
		file_name_valid(utf16_name_copy, dentry->file_name_nbytes / 2, true);

		tchar *tchar_name;
		size_t tchar_nchars;
	#ifdef __WIN32__
		tchar_name = utf16_name_copy;
		tchar_nchars = dentry->file_name_nbytes / 2;
	#else
		ret = utf16le_to_tstr(utf16_name_copy,
				      dentry->file_name_nbytes,
				      &tchar_name, &tchar_nchars);
		if (ret)
			return ret;
	#endif
		size_t fixed_name_num_chars = tchar_nchars;
		tchar fixed_name[tchar_nchars + 50];

		tmemcpy(fixed_name, tchar_name, tchar_nchars);
		fixed_name_num_chars += tsprintf(fixed_name + tchar_nchars,
						 T(" (invalid filename #%lu)"),
						 ++args->invalid_sequence);
	#ifndef __WIN32__
		FREE(tchar_name);
	#endif
		dentry->extraction_name = memdup(fixed_name, 2 * fixed_name_num_chars + 2);
		if (!dentry->extraction_name)
			return WIMLIB_ERR_NOMEM;
		dentry->extraction_name_nchars = fixed_name_num_chars;
	}
	return 0;
skip_dentry:
	dentry->needs_extraction = 0;
	dentry->not_extracted = 1;
	return 0;
}

static int
dentry_reset_needs_extraction(struct wim_dentry *dentry, void *_ignore)
{
	struct wim_inode *inode = dentry->d_inode;

	dentry->needs_extraction = 0;
	dentry->not_extracted = 0;
	inode->i_visited = 0;
	inode->i_dos_name_extracted = 0;
	FREE(inode->i_extracted_file);
	inode->i_extracted_file = NULL;
	if ((void*)dentry->extraction_name != (void*)dentry->file_name)
		FREE(dentry->extraction_name);
	dentry->extraction_name = NULL;
	return 0;
}

#define WINDOWS_NT_MAX_PATH 32768

/*
 * extract_tree - Extract a file or directory tree from the currently selected
 *		  WIM image.
 *
 * @wim:	WIMStruct for the WIM file, with the desired image selected
 *		(as wim->current_image).
 * @wim_source_path:
 *		"Canonical" (i.e. no leading or trailing slashes, path
 *		separators forwald slashes) path inside the WIM image to
 *		extract.  An empty string means the full image.
 * @target:
 *		Filesystem path to extract the file or directory tree to.
 *
 * @extract_flags:
 *		WIMLIB_EXTRACT_FLAG_*.  Also, the private flag
 *		WIMLIB_EXTRACT_FLAG_MULTI_IMAGE will be set if this is being
 *		called through wimlib_extract_image() with WIMLIB_ALL_IMAGES as
 *		the image.
 *
 * @progress_func:
 *		If non-NULL, progress function for the extraction.  The messages
 *		we may in this function are:
 *
 *		WIMLIB_PROGRESS_MSG_EXTRACT_TREE_BEGIN or
 *			WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_BEGIN;
 *		WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_BEGIN;
 *		WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_END;
 *		WIMLIB_PROGRESS_MSG_EXTRACT_DENTRY;
 *		WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS;
 *		WIMLIB_PROGRESS_MSG_APPLY_TIMESTAMPS;
 *		WIMLIB_PROGRESS_MSG_EXTRACT_TREE_END or
 *			WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_END.
 *
 * Returns 0 on success; nonzero on failure.
 */
static int
extract_tree(WIMStruct *wim, const tchar *wim_source_path, const tchar *target,
	     int extract_flags, wimlib_progress_func_t progress_func)
{
	int ret;
	struct list_head stream_list;
	struct apply_args args;
	const struct apply_operations *ops;
	struct wim_dentry *root;

	memset(&args, 0, sizeof(args));


	args.w                      = wim;
	args.target                 = target;
	args.target_nchars          = tstrlen(target);
	args.extract_flags          = extract_flags;
	args.progress_func          = progress_func;

#ifdef __WIN32__
	/* Work around defective behavior in Windows where paths longer than 260
	 * characters are not supported by default; instead they need to be
	 * turned into absolute paths and prefixed with "\\?\".  */
	args.target_lowlevel_path = MALLOC(WINDOWS_NT_MAX_PATH * sizeof(wchar_t));
	if (!args.target_lowlevel_path)
	{
		ret = WIMLIB_ERR_NOMEM;
		goto out;
	}
	args.target_lowlevel_path_nchars =
		GetFullPathName(args.target, WINDOWS_NT_MAX_PATH - 4,
				&args.target_lowlevel_path[4], NULL);

	if (args.target_lowlevel_path_nchars == 0 ||
	    args.target_lowlevel_path_nchars >= WINDOWS_NT_MAX_PATH - 4)
	{
		WARNING("Can't get full path name for \"%ls\"", args.target);
		FREE(args.target_lowlevel_path);
		args.target_lowlevel_path = NULL;
	} else {
		wmemcpy(args.target_lowlevel_path, L"\\\\?\\", 4);
		args.target_lowlevel_path_nchars += 4;
	}
#endif

	if (progress_func) {
		args.progress.extract.wimfile_name = wim->filename;
		args.progress.extract.image = wim->current_image;
		args.progress.extract.extract_flags = (extract_flags &
						       WIMLIB_EXTRACT_MASK_PUBLIC);
		args.progress.extract.image_name = wimlib_get_image_name(wim,
									 wim->current_image);
		args.progress.extract.extract_root_wim_source_path = wim_source_path;
		args.progress.extract.target = target;
	}

#ifdef WITH_NTFS_3G
	if (extract_flags & WIMLIB_EXTRACT_FLAG_NTFS) {
		args.vol = ntfs_mount(target, 0);
		if (!args.vol) {
			ERROR_WITH_ERRNO("Failed to mount NTFS volume `%"TS"'",
					 target);
			ret = WIMLIB_ERR_NTFS_3G;
			goto out_free_target_lowlevel_path;
		}
		ops = &ntfs_apply_operations;
	} else
#endif
		ops = &normal_apply_operations;

	root = get_dentry(wim, wim_source_path);
	if (!root) {
		ERROR("Path \"%"TS"\" does not exist in WIM image %d",
		      wim_source_path, wim->current_image);
		ret = WIMLIB_ERR_PATH_DOES_NOT_EXIST;
		goto out_ntfs_umount;
	}
	args.extract_root = root;

	/* Calculate the actual filename component of each extracted dentry, and
	 * in the process set the dentry->needs_extraction flag on dentries that
	 * will be extracted. */
	ret = for_dentry_in_tree(root, dentry_calculate_extraction_path, &args);
	if (ret)
		goto out_dentry_reset_needs_extraction;

	/* Build a list of the streams that need to be extracted */
	ret = find_streams_for_extraction(root,
					  &stream_list,
					  wim->lookup_table, extract_flags);
	if (ret)
		goto out_dentry_reset_needs_extraction;

	/* Calculate the number of bytes of data that will be extracted */
	calculate_bytes_to_extract(&stream_list, extract_flags,
				   &args.progress);

	if (extract_flags & WIMLIB_EXTRACT_FLAG_TO_STDOUT) {
		ret = extract_dentry_to_stdout(root);
		goto out_dentry_reset_needs_extraction;
	}

	if (progress_func) {
		progress_func(*wim_source_path ? WIMLIB_PROGRESS_MSG_EXTRACT_TREE_BEGIN :
			      WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_BEGIN,
			      &args.progress);
	}

	/* If a sequential extraction was specified, sort the streams to be
	 * extracted by their position in the WIM file, so that the WIM file can
	 * be read sequentially. */
	if (extract_flags & WIMLIB_EXTRACT_FLAG_SEQUENTIAL) {
		ret = sort_stream_list_by_wim_position(&stream_list);
		if (ret != 0) {
			WARNING("Falling back to non-sequential extraction");
			extract_flags &= ~WIMLIB_EXTRACT_FLAG_SEQUENTIAL;
		}
	}

	if (progress_func) {
		progress_func(WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_BEGIN,
			      &args.progress);
	}

	/* Make the directory structure and extract empty files */
	args.extract_flags |= WIMLIB_EXTRACT_FLAG_NO_STREAMS;
	args.apply_dentry = ops->apply_dentry;
	ret = for_dentry_in_tree(root, maybe_apply_dentry, &args);
	args.extract_flags &= ~WIMLIB_EXTRACT_FLAG_NO_STREAMS;
	if (ret)
		goto out_dentry_reset_needs_extraction;

	if (progress_func) {
		progress_func(WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_END,
			      &args.progress);
	}

	if (extract_flags & WIMLIB_EXTRACT_FLAG_RPFIX) {
		args.target_realpath = realpath(target, NULL);
		if (!args.target_realpath) {
			ret = WIMLIB_ERR_NOMEM;
			goto out_dentry_reset_needs_extraction;
		}
		args.target_realpath_len = tstrlen(args.target_realpath);
	}

	/* Extract non-empty files */
	ret = apply_stream_list(&stream_list, &args, ops, progress_func);
	if (ret)
		goto out_free_target_realpath;

	if (progress_func) {
		progress_func(WIMLIB_PROGRESS_MSG_APPLY_TIMESTAMPS,
			      &args.progress);
	}

	/* Apply timestamps */
	ret = for_dentry_in_tree_depth(root,
				       ops->apply_dentry_timestamps, &args);
	if (ret)
		goto out_free_target_realpath;

	if (progress_func) {
		progress_func(*wim_source_path ? WIMLIB_PROGRESS_MSG_EXTRACT_TREE_END :
			      WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_END,
			      &args.progress);
	}
out_free_target_realpath:
	FREE(args.target_realpath);
out_dentry_reset_needs_extraction:
	for_dentry_in_tree(root, dentry_reset_needs_extraction, NULL);
out_ntfs_umount:
#ifdef WITH_NTFS_3G
	/* Unmount the NTFS volume */
	if (extract_flags & WIMLIB_EXTRACT_FLAG_NTFS) {
		if (ntfs_umount(args.vol, FALSE) != 0) {
			ERROR_WITH_ERRNO("Failed to unmount NTFS volume `%"TS"'",
					 args.target);
			if (ret == 0)
				ret = WIMLIB_ERR_NTFS_3G;
		}
	}
#endif
out_free_target_lowlevel_path:
#ifdef __WIN32__
	FREE(args.target_lowlevel_path);
#endif
out:
	return ret;
}

/* Validates a single wimlib_extract_command, mostly checking to make sure the
 * extract flags make sense. */
static int
check_extract_command(struct wimlib_extract_command *cmd, int wim_header_flags)
{
	int extract_flags;
	bool is_entire_image = (cmd->wim_source_path[0] == T('\0'));

	/* Empty destination path? */
	if (cmd->fs_dest_path[0] == T('\0'))
		return WIMLIB_ERR_INVALID_PARAM;

	extract_flags = cmd->extract_flags;

	/* Specified both symlink and hardlink modes? */
	if ((extract_flags &
	     (WIMLIB_EXTRACT_FLAG_SYMLINK |
	      WIMLIB_EXTRACT_FLAG_HARDLINK)) == (WIMLIB_EXTRACT_FLAG_SYMLINK |
						 WIMLIB_EXTRACT_FLAG_HARDLINK))
		return WIMLIB_ERR_INVALID_PARAM;

#ifdef __WIN32__
	/* Wanted UNIX data on Windows? */
	if (extract_flags & WIMLIB_EXTRACT_FLAG_UNIX_DATA) {
		ERROR("Extracting UNIX data is not supported on Windows");
		return WIMLIB_ERR_INVALID_PARAM;
	}
	/* Wanted linked extraction on Windows?  (XXX This is possible, just not
	 * implemented yet.) */
	if (extract_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK |
			     WIMLIB_EXTRACT_FLAG_HARDLINK))
	{
		ERROR("Linked extraction modes are not supported on Windows");
		return WIMLIB_ERR_INVALID_PARAM;
	}
#endif

	if (extract_flags & WIMLIB_EXTRACT_FLAG_NTFS) {
		/* NTFS-3g extraction mode requested */
#ifdef WITH_NTFS_3G
		if ((extract_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK |
				      WIMLIB_EXTRACT_FLAG_HARDLINK))) {
			ERROR("Cannot specify symlink or hardlink flags when applying\n"
			      "        directly to a NTFS volume");
			return WIMLIB_ERR_INVALID_PARAM;
		}
		if (!is_entire_image &&
		    (extract_flags & WIMLIB_EXTRACT_FLAG_NTFS))
		{
			ERROR("When applying directly to a NTFS volume you can "
			      "only extract a full image, not part of one");
			return WIMLIB_ERR_INVALID_PARAM;
		}
		if (extract_flags & WIMLIB_EXTRACT_FLAG_UNIX_DATA) {
			ERROR("Cannot restore UNIX-specific data in "
			      "the NTFS extraction mode");
			return WIMLIB_ERR_INVALID_PARAM;
		}
#else
		ERROR("wimlib was compiled without support for NTFS-3g, so");
		ERROR("we cannot apply a WIM image directly to a NTFS volume");
		return WIMLIB_ERR_UNSUPPORTED;
#endif
	}

	if ((extract_flags & (WIMLIB_EXTRACT_FLAG_RPFIX |
			      WIMLIB_EXTRACT_FLAG_NORPFIX)) ==
		(WIMLIB_EXTRACT_FLAG_RPFIX | WIMLIB_EXTRACT_FLAG_NORPFIX))
	{
		ERROR("Cannot specify RPFIX and NORPFIX flags at the same time!");
		return WIMLIB_ERR_INVALID_PARAM;
	}

	if ((extract_flags & (WIMLIB_EXTRACT_FLAG_RPFIX |
			      WIMLIB_EXTRACT_FLAG_NORPFIX)) == 0)
	{
		/* Do reparse point fixups by default if the WIM header says
		 * they are enabled and we are extracting a full image. */
		if ((wim_header_flags & WIM_HDR_FLAG_RP_FIX) && is_entire_image)
			extract_flags |= WIMLIB_EXTRACT_FLAG_RPFIX;
	}

	if (!is_entire_image && (extract_flags & WIMLIB_EXTRACT_FLAG_RPFIX)) {
		ERROR("Cannot specify --rpfix when not extracting entire image");
		return WIMLIB_ERR_INVALID_PARAM;
	}

	cmd->extract_flags = extract_flags;
	return 0;
}


/* Internal function to execute extraction commands for a WIM image. */
static int
do_wimlib_extract_files(WIMStruct *wim,
			int image,
			struct wimlib_extract_command *cmds,
			size_t num_cmds,
			wimlib_progress_func_t progress_func)
{
	int ret;
	bool found_link_cmd = false;
	bool found_nolink_cmd = false;

	/* Select the image from which we are extracting files */
	ret = select_wim_image(wim, image);
	if (ret)
		return ret;

	/* Make sure there are no streams in the WIM that have not been
	 * checksummed yet. */
	ret = wim_checksum_unhashed_streams(wim);
	if (ret)
		return ret;

	/* Check for problems with the extraction commands */
	for (size_t i = 0; i < num_cmds; i++) {
		ret = check_extract_command(&cmds[i], wim->hdr.flags);
		if (ret)
			return ret;
		if (cmds[i].extract_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK |
					     WIMLIB_EXTRACT_FLAG_HARDLINK)) {
			found_link_cmd = true;
		} else {
			found_nolink_cmd = true;
		}
		if (found_link_cmd && found_nolink_cmd) {
			ERROR("Symlink or hardlink extraction mode must "
			      "be set on all extraction commands");
			return WIMLIB_ERR_INVALID_PARAM;
		}
	}

	/* Execute the extraction commands */
	for (size_t i = 0; i < num_cmds; i++) {
		ret = extract_tree(wim,
				   cmds[i].wim_source_path,
				   cmds[i].fs_dest_path,
				   cmds[i].extract_flags,
				   progress_func);
		if (ret)
			return ret;
	}
	return 0;
}

/* Extract files or directories from a WIM image. */
WIMLIBAPI int
wimlib_extract_files(WIMStruct *wim,
		     int image,
		     const struct wimlib_extract_command *cmds,
		     size_t num_cmds,
		     int default_extract_flags,
		     WIMStruct **additional_swms,
		     unsigned num_additional_swms,
		     wimlib_progress_func_t progress_func)
{
	int ret;
	struct wimlib_extract_command *cmds_copy;
	int all_flags = 0;

	default_extract_flags &= WIMLIB_EXTRACT_MASK_PUBLIC;

	ret = verify_swm_set(wim, additional_swms, num_additional_swms);
	if (ret)
		goto out;

	if (num_cmds == 0)
		goto out;

	if (num_additional_swms)
		merge_lookup_tables(wim, additional_swms, num_additional_swms);

	cmds_copy = CALLOC(num_cmds, sizeof(cmds[0]));
	if (!cmds_copy) {
		ret = WIMLIB_ERR_NOMEM;
		goto out_restore_lookup_table;
	}

	for (size_t i = 0; i < num_cmds; i++) {
		cmds_copy[i].extract_flags = (default_extract_flags |
						 cmds[i].extract_flags)
						& WIMLIB_EXTRACT_MASK_PUBLIC;
		all_flags |= cmds_copy[i].extract_flags;

		cmds_copy[i].wim_source_path = canonicalize_wim_path(cmds[i].wim_source_path);
		if (!cmds_copy[i].wim_source_path) {
			ret = WIMLIB_ERR_NOMEM;
			goto out_free_cmds_copy;
		}

		cmds_copy[i].fs_dest_path = canonicalize_fs_path(cmds[i].fs_dest_path);
		if (!cmds_copy[i].fs_dest_path) {
			ret = WIMLIB_ERR_NOMEM;
			goto out_free_cmds_copy;
		}

	}
	ret = do_wimlib_extract_files(wim, image,
				      cmds_copy, num_cmds,
				      progress_func);

	if (all_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK |
			 WIMLIB_EXTRACT_FLAG_HARDLINK))
	{
		for_lookup_table_entry(wim->lookup_table,
				       lte_free_extracted_file, NULL);
	}
out_free_cmds_copy:
	for (size_t i = 0; i < num_cmds; i++) {
		FREE(cmds_copy[i].wim_source_path);
		FREE(cmds_copy[i].fs_dest_path);
	}
	FREE(cmds_copy);
out_restore_lookup_table:
	if (num_additional_swms)
		unmerge_lookup_table(wim);
out:
	return ret;
}

/*
 * Extracts an image from a WIM file.
 *
 * @wim:		WIMStruct for the WIM file.
 *
 * @image:		Number of the single image to extract.
 *
 * @target:		Directory or NTFS volume to extract the image to.
 *
 * @extract_flags:	Bitwise or of WIMLIB_EXTRACT_FLAG_*.
 *
 * @progress_func:	If non-NULL, a progress function to be called
 *			periodically.
 *
 * Returns 0 on success; nonzero on failure.
 */
static int
extract_single_image(WIMStruct *wim, int image,
		     const tchar *target, int extract_flags,
		     wimlib_progress_func_t progress_func)
{
	int ret;
	tchar *target_copy = canonicalize_fs_path(target);
	if (!target_copy)
		return WIMLIB_ERR_NOMEM;
	struct wimlib_extract_command cmd = {
		.wim_source_path = T(""),
		.fs_dest_path = target_copy,
		.extract_flags = extract_flags,
	};
	ret = do_wimlib_extract_files(wim, image, &cmd, 1, progress_func);
	FREE(target_copy);
	return ret;
}

static const tchar * const filename_forbidden_chars =
T(
#ifdef __WIN32__
"<>:\"/\\|?*"
#else
"/"
#endif
);

/* This function checks if it is okay to use a WIM image's name as a directory
 * name.  */
static bool
image_name_ok_as_dir(const tchar *image_name)
{
	return image_name && *image_name &&
		!tstrpbrk(image_name, filename_forbidden_chars) &&
		tstrcmp(image_name, T(".")) &&
		tstrcmp(image_name, T(".."));
}

/* Extracts all images from the WIM to the directory @target, with the images
 * placed in subdirectories named by their image names. */
static int
extract_all_images(WIMStruct *wim,
		   const tchar *target,
		   int extract_flags,
		   wimlib_progress_func_t progress_func)
{
	size_t image_name_max_len = max(xml_get_max_image_name_len(wim), 20);
	size_t output_path_len = tstrlen(target);
	tchar buf[output_path_len + 1 + image_name_max_len + 1];
	int ret;
	int image;
	const tchar *image_name;
	struct stat stbuf;

	if (tstat(target, &stbuf)) {
		if (errno == ENOENT)
		{
			if (tmkdir(target, S_IRWXU | S_IRGRP | S_IXGRP |
				   	   S_IROTH | S_IXOTH))
			{
				ERROR_WITH_ERRNO("Failed to create directory \"%"TS"\"", target);
				return WIMLIB_ERR_MKDIR;
			}
		} else {
			ERROR_WITH_ERRNO("Failed to stat \"%"TS"\"", target);
			return WIMLIB_ERR_STAT;
		}
	} else if (!S_ISDIR(stbuf.st_mode)) {
		ERROR("\"%"TS"\" is not a directory", target);
		return WIMLIB_ERR_NOTDIR;
	}

	tmemcpy(buf, target, output_path_len);
	buf[output_path_len] = OS_PREFERRED_PATH_SEPARATOR;
	for (image = 1; image <= wim->hdr.image_count; image++) {
		image_name = wimlib_get_image_name(wim, image);
		if (image_name_ok_as_dir(image_name)) {
			tstrcpy(buf + output_path_len + 1, image_name);
		} else {
			/* Image name is empty or contains forbidden characters.
			 * Use image number instead. */
			tsprintf(buf + output_path_len + 1, T("%d"), image);
		}
		ret = extract_single_image(wim, image, buf, extract_flags,
					   progress_func);
		if (ret)
			return ret;
	}
	return 0;
}

/* Extracts a single image or all images from a WIM file to a directory or NTFS
 * volume. */
WIMLIBAPI int
wimlib_extract_image(WIMStruct *wim,
		     int image,
		     const tchar *target,
		     int extract_flags,
		     WIMStruct **additional_swms,
		     unsigned num_additional_swms,
		     wimlib_progress_func_t progress_func)
{
	int ret;

	extract_flags &= WIMLIB_EXTRACT_MASK_PUBLIC;

	ret = verify_swm_set(wim, additional_swms, num_additional_swms);
	if (ret)
		return ret;

	if (num_additional_swms)
		merge_lookup_tables(wim, additional_swms, num_additional_swms);

	if (image == WIMLIB_ALL_IMAGES) {
		ret = extract_all_images(wim, target,
					 extract_flags | WIMLIB_EXTRACT_FLAG_MULTI_IMAGE,
					 progress_func);
	} else {
		ret = extract_single_image(wim, image, target, extract_flags,
					   progress_func);
	}

	if (extract_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK |
			     WIMLIB_EXTRACT_FLAG_HARDLINK))
	{
		for_lookup_table_entry(wim->lookup_table,
				       lte_free_extracted_file,
				       NULL);
	}
	if (num_additional_swms)
		unmerge_lookup_table(wim);
	return ret;
}
