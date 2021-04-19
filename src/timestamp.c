/*
 * timestamp.c
 *
 * Conversion between Windows NT timestamps and UNIX timestamps.
 */

/*
 * Copyright (C) 2012-2017 Eric Biggers
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
 * along with this file; if not, see http://www.gnu.org/licenses/.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib.h" /* for struct wimlib_timespec */
#include "wimlib/timestamp.h"

/* Windows NT timestamps to UNIX timestamps  */

time_t
wim_timestamp_to_time_t(u64 timestamp)
{
	return (timestamp / TICKS_PER_SECOND) - EPOCH_DISTANCE;
}

void
wim_timestamp_to_wimlib_timespec(u64 timestamp, struct wimlib_timespec *wts,
				 s32 *high_part_ret)
{
	s64 sec = (timestamp / TICKS_PER_SECOND) - EPOCH_DISTANCE;

	wts->tv_sec = sec;
	wts->tv_nsec = (timestamp % TICKS_PER_SECOND) * NANOSECONDS_PER_TICK;

	if (sizeof(wts->tv_sec) == 4)
		*high_part_ret = sec >> 32;
}

#ifdef __WIN32__
static _unused_attribute void
check_sizeof_time_t(void)
{
	/* Windows builds should always be using 64-bit time_t now. */
	STATIC_ASSERT(sizeof(time_t) == 8);
}
#else
struct timeval
wim_timestamp_to_timeval(u64 timestamp)
{
	return (struct timeval) {
		.tv_sec = wim_timestamp_to_time_t(timestamp),
		.tv_usec = (timestamp % TICKS_PER_SECOND) / TICKS_PER_MICROSECOND,
	};
}

struct timespec
wim_timestamp_to_timespec(u64 timestamp)
{
	return (struct timespec) {
		.tv_sec = wim_timestamp_to_time_t(timestamp),
		.tv_nsec = (timestamp % TICKS_PER_SECOND) * NANOSECONDS_PER_TICK,
	};
}

/* UNIX timestamps to Windows NT timestamps  */

u64
time_t_to_wim_timestamp(time_t t)
{
	return ((u64)t + EPOCH_DISTANCE) * TICKS_PER_SECOND;
}

u64
timeval_to_wim_timestamp(const struct timeval *tv)
{
	return time_t_to_wim_timestamp(tv->tv_sec) +
		(u32)tv->tv_usec * TICKS_PER_MICROSECOND;
}

u64
timespec_to_wim_timestamp(const struct timespec *ts)
{
	return time_t_to_wim_timestamp(ts->tv_sec) +
		(u32)ts->tv_nsec / NANOSECONDS_PER_TICK;
}

/* Retrieve the current time as a WIM timestamp.  */
u64
now_as_wim_timestamp(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return timeval_to_wim_timestamp(&tv);
}
#endif /* !__WIN32__ */

/* Translate a WIM timestamp into a human-readable string.  */
void
wim_timestamp_to_str(u64 timestamp, tchar *buf, size_t len)
{
	struct tm tm;
	time_t t = wim_timestamp_to_time_t(timestamp);

	gmtime_r(&t, &tm);
	tstrftime(buf, len, T("%a %b %d %H:%M:%S %Y UTC"), &tm);
}
