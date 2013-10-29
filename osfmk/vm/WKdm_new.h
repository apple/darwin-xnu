/*
 * Copyright (c) 2000-2013 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

/* direct-mapped partial matching compressor with simple 22/10 split
 *
 *  Compresses buffers using a dictionary based match and partial match
 *  (high bits only or full match) scheme.
 *
 *  Paul Wilson -- wilson@cs.utexas.edu
 *  Scott F. Kaplan -- sfkaplan@cs.utexas.edu
 *  September 1997
 */

/* compressed output format, in memory order
 *  1. a four-word HEADER containing four one-word values:
 *     i.   a one-word code saying what algorithm compressed the data
 *     ii.  an integer WORD offset into the page saying
 *          where the queue position area starts
 *     iii. an integer WORD offset into the page saying where
 *          the low-bits area starts
 *     iv.  an integer WORD offset into the page saying where the
 *          low-bits area ends
 *
 *  2. a 64-word TAGS AREA holding one two-bit tag for each word in 
 *     the original (1024-word) page, packed 16 per word
 *
 *  3. a variable-sized FULL WORDS AREA (always word aligned and an
 *     integral number of words) holding full-word patterns that
 *     were not in the dictionary when encoded (i.e., dictionary misses)
 *
 *  4. a variable-sized QUEUE POSITIONS AREA (always word aligned and
 *     an integral number of words) holding four-bit queue positions,
 *     packed eight per word.
 *
 *  5. a variable-sized LOW BITS AREA (always word aligned and an
 *     integral number of words) holding ten-bit low-bit patterns
 *     (from partial matches), packed three per word. 
 */


#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================ */
/* Included files */

#ifdef WK_DEBUG
#include <stdio.h>
#include <unistd.h>
#include <math.h>
#include <strings.h>
#endif

typedef unsigned int WK_word;

/* at the moment we have dependencies on the page size.  That should
 * be changed to work for any power-of-two size that's at least 16
 * words, or something like that
 */

#define PAGE_SIZE_IN_WORDS 1024
#define PAGE_SIZE_IN_BYTES 4096

#define DICTIONARY_SIZE 16

/*
 * macros defining the basic layout of stuff in a page
 */
#define HEADER_SIZE_IN_WORDS 3
#define TAGS_AREA_OFFSET 3
#define TAGS_AREA_SIZE 64

/* the next few are used during compression to write the header */
#define SET_QPOS_AREA_START(compr_dest_buf,qpos_start_addr)  \
        (compr_dest_buf[0] = qpos_start_addr - compr_dest_buf)
#define SET_LOW_BITS_AREA_START(compr_dest_buf,lb_start_addr) \
        (compr_dest_buf[1] = lb_start_addr - compr_dest_buf)
#define SET_LOW_BITS_AREA_END(compr_dest_buf,lb_end_addr) \
        (compr_dest_buf[2] = lb_end_addr - compr_dest_buf)

/* the next few are only use during decompression to read the header */
#define TAGS_AREA_START(decomp_src_buf)       \
        (decomp_src_buf + TAGS_AREA_OFFSET)
#define TAGS_AREA_END(decomp_src_buf)         \
        (TAGS_AREA_START(decomp_src_buf) + TAGS_AREA_SIZE)
#define FULL_WORD_AREA_START(the_buf) TAGS_AREA_END(the_buf)
#define QPOS_AREA_START(decomp_src_buf)       \
        (decomp_src_buf + decomp_src_buf[0])   
#define LOW_BITS_AREA_START(decomp_src_buf)   \
        (decomp_src_buf + (decomp_src_buf[1]))
#define QPOS_AREA_END(the_buf) LOW_BITS_AREA_START(the_buf)
#define LOW_BITS_AREA_END(decomp_src_buf)     \
        (decomp_src_buf + (decomp_src_buf[2]))

/* ============================================================ */
/* Types and structures */

/* A structure to store each element of the dictionary. */
typedef WK_word DictionaryElement;

/* ============================================================ */
/* Misc constants */

#define BITS_PER_WORD 32
#define BYTES_PER_WORD 4
#define NUM_LOW_BITS 10
#define LOW_BITS_MASK 0x3FF
#define ALL_ONES_MASK 0xFFFFFFFF

#define TWO_BITS_PACKING_MASK 0x03030303
#define FOUR_BITS_PACKING_MASK 0x0F0F0F0F
#define TEN_LOW_BITS_MASK 0x000003FF
#define TWENTY_TWO_HIGH_BITS_MASK 0xFFFFFC00

/* Tag values.  NOTE THAT CODE MAY DEPEND ON THE NUMBERS USED.
 * Check for conditionals doing arithmetic on these things
 * before changing them
 */
#define ZERO_TAG 0x0
#define PARTIAL_TAG 0x1
#define MISS_TAG 0x2
#define EXACT_TAG 0x3

#define BITS_PER_BYTE 8

/* ============================================================ */
/* Global macros */

/* Shift out the low bits of a pattern to give the high bits pattern.
   The stripped patterns are used for initial tests of partial
   matches. */
#define HIGH_BITS(word_pattern) (word_pattern >> NUM_LOW_BITS)

/* String the high bits of a pattern so the low order bits can
   be included in an encoding of a partial match. */
#define LOW_BITS(word_pattern) (word_pattern & LOW_BITS_MASK)

#if defined DEBUG_WK
#define DEBUG_PRINT_1(string) printf (string)
#define DEBUG_PRINT_2(string,value) printf(string, value)
#else
#define DEBUG_PRINT_1(string)
#define DEBUG_PRINT_2(string, value)
#endif

/* Set up the dictionary before performing compression or
   decompression.  Each element is loaded with some value, the
   high-bits version of that value, and a next pointer. */
#define PRELOAD_DICTIONARY { \
  dictionary[0] = 1; \
  dictionary[1] = 1; \
  dictionary[2] = 1; \
  dictionary[3] = 1; \
  dictionary[4] = 1; \
  dictionary[5] = 1; \
  dictionary[6] = 1; \
  dictionary[7] = 1; \
  dictionary[8] = 1; \
  dictionary[9] = 1; \
  dictionary[10] = 1; \
  dictionary[11] = 1; \
  dictionary[12] = 1; \
  dictionary[13] = 1; \
  dictionary[14] = 1; \
  dictionary[15] = 1; \
}

/* these are the constants for the hash function lookup table.
 * Only zero maps to zero.  The rest of the tabale is the result
 * of appending 17 randomizations of the multiples of 4 from
 * 4 to 56.  Generated by a Scheme script in hash.scm. 
 */
#define HASH_LOOKUP_TABLE_CONTENTS { \
   0, 52,  8, 56, 16, 12, 28, 20,  4, 36, 48, 24, 44, 40, 32, 60, \
   8, 12, 28, 20,  4, 60, 16, 36, 24, 48, 44, 32, 52, 56, 40, 12, \
   8, 48, 16, 52, 60, 28, 56, 32, 20, 24, 36, 40, 44,  4,  8, 40, \
  60, 32, 20, 44,  4, 36, 52, 24, 16, 56, 48, 12, 28, 16,  8, 40, \
  36, 28, 32, 12,  4, 44, 52, 20, 24, 48, 60, 56, 40, 48,  8, 32, \
  28, 36,  4, 44, 20, 56, 60, 24, 52, 16, 12, 12,  4, 48, 20,  8, \
  52, 16, 60, 24, 36, 44, 28, 56, 40, 32, 36, 20, 24, 60, 40, 44, \
  52, 16, 32,  4, 48,  8, 28, 56, 12, 28, 32, 40, 52, 36, 16, 20, \
  48,  8,  4, 60, 24, 56, 44, 12,  8, 36, 24, 28, 16, 60, 20, 56, \
  32, 40, 48, 12,  4, 44, 52, 44, 40, 12, 56,  8, 36, 24, 60, 28, \
  48,  4, 32, 20, 16, 52, 60, 12, 24, 36,  8,  4, 16, 56, 48, 44, \
  40, 52, 32, 20, 28, 32, 12, 36, 28, 24, 56, 40, 16, 52, 44,  4, \
  20, 60,  8, 48, 48, 52, 12, 20, 32, 44, 36, 28,  4, 40, 24,  8, \
  56, 60, 16, 36, 32,  8, 40,  4, 52, 24, 44, 20, 12, 28, 48, 56, \
  16, 60,  4, 52, 60, 48, 20, 16, 56, 44, 24,  8, 40, 12, 32, 28, \
  36, 24, 32, 12,  4, 20, 16, 60, 36, 28,  8, 52, 40, 48, 44, 56  \
}

#define HASH_TO_DICT_BYTE_OFFSET(pattern) \
        (hashLookupTable[((pattern) >> 10) & 0xFF])

extern const char hashLookupTable[];

/* EMIT... macros emit bytes or words into the intermediate arrays
 */

#define EMIT_BYTE(fill_ptr, byte_value) {*fill_ptr++ = byte_value; }
#define EMIT_WORD(fill_ptr,word_value) {*fill_ptr++ = word_value; }

/* RECORD... macros record the results of modeling in the intermediate
 * arrays
 */

#define RECORD_ZERO { EMIT_BYTE(next_tag,ZERO_TAG); }

#define RECORD_EXACT(queue_posn)  EMIT_BYTE(next_tag,EXACT_TAG);  \
                                  EMIT_BYTE(next_qp,(queue_posn)); 

#define RECORD_PARTIAL(queue_posn,low_bits_pattern) { \
   EMIT_BYTE(next_tag,PARTIAL_TAG);                   \
   EMIT_BYTE(next_qp,(queue_posn));                   \
   EMIT_WORD(next_low_bits,(low_bits_pattern))  }

#define RECORD_MISS(word_pattern) EMIT_BYTE(next_tag,MISS_TAG); \
                                  EMIT_WORD(next_full_patt,(word_pattern)); 
				  

#define	WKdm_SCRATCH_BUF_SIZE	4096

void
WKdm_decompress_new (WK_word* src_buf,
		 WK_word* dest_buf,
		 WK_word* scratch,
		 unsigned int bytes);
int
WKdm_compress_new (WK_word* src_buf,
               WK_word* dest_buf,
	       WK_word* scratch,
	       unsigned int limit);

#ifdef __cplusplus
} /* extern "C" */
#endif
