#ifndef _WIMLIB_PROGRESS_H
#define _WIMLIB_PROGRESS_H

#include "wimlib.h"
#include "wimlib/paths.h"
#include "wimlib/timestamp.h"
#include "wimlib/types.h"

/* If specified, call the user-provided progress function and check its result.
 */
static inline int
call_progress(wimlib_progress_func_t progfunc,
	      enum wimlib_progress_msg msg,
	      union wimlib_progress_info *info,
	      void *progctx)
{
	if (progfunc) {
		enum wimlib_progress_status status;

		status = (*progfunc)(msg, info, progctx);

		switch (status) {
		case WIMLIB_PROGRESS_STATUS_CONTINUE:
			return 0;
		case WIMLIB_PROGRESS_STATUS_ABORT:
			return WIMLIB_ERR_ABORTED_BY_PROGRESS;
		default:
			return WIMLIB_ERR_UNKNOWN_PROGRESS_STATUS;
		}
	}
	return 0;
}

extern int
report_error(wimlib_progress_func_t progfunc,
	     void *progctx, int error_code, const tchar *path);

/* Rate-limiting of byte-count based progress messages.  We update the progress
 * at most 5 times per second.  */
static inline bool
should_update_progress(u64 completed_bytes, u64 total_bytes,
		       u64 *last_progress_time)
{
	u64 now = now_as_wim_timestamp();

	if (completed_bytes < total_bytes &&
	    now - *last_progress_time < 200 * TICKS_PER_MILLISECOND)
		return false;

	*last_progress_time = now;
	return true;
}

/* Windows: temporarily remove the stream name from the path  */
static inline tchar *
progress_get_streamless_path(const tchar *path)
{
	tchar *cookie = NULL;
#ifdef __WIN32__
	cookie = (wchar_t *)path_stream_name(path);
	if (cookie)
		*--cookie = L'\0'; /* Overwrite the colon  */
#endif
	return cookie;
}

/* Windows: temporarily replace \??\ with \\?\ (to make an NT namespace path
 * into a Win32 namespace path)  */
static inline tchar *
progress_get_win32_path(const tchar *path)
{
#ifdef __WIN32__
	if (!wcsncmp(path, L"\\??\\", 4)) {
		((wchar_t *)path)[1] = L'\\';
		return (wchar_t *)&path[1];
	}
#endif
	return NULL;
}

/* Windows: restore the NT namespace path  */
static inline void
progress_put_win32_path(tchar *cookie)
{
#ifdef __WIN32__
	if (cookie)
		*cookie = L'?';
#endif
}

/* Windows: restore the stream name part of the path  */
static inline void
progress_put_streamless_path(tchar *cookie)
{
#ifdef __WIN32__
	if (cookie)
		*cookie = L':';
#endif
}

#endif /* _WIMLIB_PROGRESS_H */
