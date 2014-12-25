/*
 * lzms_constants.h
 *
 * Constants for the LZMS compression format.
 */

#ifndef _LZMS_CONSTANTS_H
#define _LZMS_CONSTANTS_H

#define LZMS_NUM_RECENT_OFFSETS			3
#define LZMS_MAX_INIT_RECENT_OFFSET		(LZMS_NUM_RECENT_OFFSETS + 1)
#define LZMS_OFFSET_OFFSET			(LZMS_NUM_RECENT_OFFSETS - 1)

#define LZMS_PROBABILITY_BITS			6
#define LZMS_PROBABILITY_MAX			(1U << LZMS_PROBABILITY_BITS)
#define LZMS_INITIAL_PROBABILITY		48
#define LZMS_INITIAL_RECENT_BITS		0x0000000055555555ULL

#define LZMS_NUM_MAIN_STATES			16
#define LZMS_NUM_MATCH_STATES			32
#define LZMS_NUM_LZ_MATCH_STATES		64
#define LZMS_NUM_LZ_REPEAT_MATCH_STATES		64
#define LZMS_NUM_DELTA_MATCH_STATES		64
#define LZMS_NUM_DELTA_REPEAT_MATCH_STATES	64
#define LZMS_MAX_NUM_STATES			64

#define LZMS_NUM_LITERAL_SYMS			256
#define LZMS_NUM_LEN_SYMS			54
#define LZMS_NUM_DELTA_POWER_SYMS		8
#define LZMS_MAX_NUM_OFFSET_SYMS		799
#define LZMS_MAX_NUM_SYMS			799

#define LZMS_MAX_CODEWORD_LEN			15

#define LZMS_LITERAL_CODE_REBUILD_FREQ		1024
#define LZMS_LZ_OFFSET_CODE_REBUILD_FREQ	1024
#define LZMS_LENGTH_CODE_REBUILD_FREQ		512
#define LZMS_DELTA_OFFSET_CODE_REBUILD_FREQ	1024
#define LZMS_DELTA_POWER_CODE_REBUILD_FREQ	512

#define LZMS_X86_ID_WINDOW_SIZE			65535
#define LZMS_X86_MAX_TRANSLATION_OFFSET		1023

#endif /* _LZMS_CONSTANTS_H */
