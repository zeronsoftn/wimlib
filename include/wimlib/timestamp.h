/*
 * timestamp.h
 *
 * Conversion between Windows NT timestamps and UNIX timestamps.
 */

#ifndef _WIMLIB_TIMESTAMP_H
#define _WIMLIB_TIMESTAMP_H

#include <sys/time.h>
#include <time.h>

#include "wimlib/types.h"

/*
 * Timestamps in WIM files are Windows NT timestamps, or FILETIMEs: 64-bit
 * values storing the number of 100-nanosecond ticks since January 1, 1601.
 *
 * Note: UNIX timestamps are signed; Windows timestamps are not.  Negative UNIX
 * timestamps represent times before 1970-01-01.  When such a timestamp is
 * converted to a Windows timestamp, we can preserve the correct date provided
 * that it is not also before 1601-01-01.
 */

#define NANOSECONDS_PER_TICK	100
#define TICKS_PER_SECOND	(1000000000 / NANOSECONDS_PER_TICK)
#define TICKS_PER_MILLISECOND	(TICKS_PER_SECOND / 1000)
#define TICKS_PER_MICROSECOND	(TICKS_PER_SECOND / 1000000)

/*
 * EPOCH_DISTANCE is the number of seconds separating the Windows NT and UNIX
 * epochs.  This is equal to ((1970-1601)*365+89)*24*60*60.  89 is the number
 * of leap years between 1970 and 1601.
 */
#define EPOCH_DISTANCE		11644473600

struct wimlib_timespec;

extern time_t
wim_timestamp_to_time_t(u64 timestamp);

extern void
wim_timestamp_to_wimlib_timespec(u64 timestamp, struct wimlib_timespec *wts,
				 s32 *high_part_ret);

extern struct timeval
wim_timestamp_to_timeval(u64 timestamp);

extern struct timespec
wim_timestamp_to_timespec(u64 timestamp);

extern u64
time_t_to_wim_timestamp(time_t t);

extern u64
timeval_to_wim_timestamp(const struct timeval *tv);

extern u64
timespec_to_wim_timestamp(const struct timespec *ts);

extern u64
now_as_wim_timestamp(void);

extern void
wim_timestamp_to_str(u64 timestamp, tchar *buf, size_t len);

#endif /* _WIMLIB_TIMESTAMP_H */
