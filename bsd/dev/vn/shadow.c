/*
 * Copyright (c) 2001-2006 Apple Computer, Inc. All rights reserved.
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

/*
 * shadow.c
 *
 * Implement copy-on-write shadow map to allow a disk image to be
 * mounted read-only, yet be writable by transferring writes to a
 * "shadow" file.  Subsequent reads from blocks that have been
 * written will then go the "shadow" file.
 *
 * The map has two parts:
 * 1) a bit map to track which blocks have been written
 * 2) a band map to map a "band" within the original file to a corresponding
 *    "band" in the shadow file.  Each band has the same size.
 *
 * The band map is used to ensure that blocks that are contiguous in the
 * original file will remain contiguous in the shadow file.
 *
 * For debugging purposes, this file can be compiled standalone using:
 * cc -o shadow shadow.c -DTEST_SHADOW
 */

/*
 * Modification History
 *
 * December 21, 2001    Dieter Siegmund (dieter@apple.com)
 * - initial revision
 */
#include <sys/param.h>
#include <sys/types.h>
#include <mach/boolean.h>

#include <string.h>

#ifdef TEST_SHADOW
#include <unistd.h>
#include <stdlib.h>
#define my_malloc(a)    malloc(a)
#define my_free(a)      free(a)
#else /* !TEST_SHADOW */
#include <sys/malloc.h>
#define my_malloc(a)    _MALLOC(a, M_TEMP, M_WAITOK)
#define my_free(a)      FREE(a, M_TEMP)
#include <libkern/libkern.h>
#endif /* TEST_SHADOW */

#include "shadow.h"

#define UINT32_ALL_ONES                 ((uint32_t)(-1))
#define USHORT_ALL_ONES                 ((u_short)(-1))
#define UCHAR_ALL_ONES                  ((u_char)(-1))

#define my_trunc(value, divisor)        ((value) / (divisor) * (divisor))

/* a band size of 128K can represent a file up to 8GB */
#define BAND_SIZE_DEFAULT_POWER_2       17
#define BAND_SIZE_DEFAULT               (1 << BAND_SIZE_DEFAULT_POWER_2)

typedef u_short band_number_t;
#define BAND_ZERO                       ((band_number_t)0)
#define BAND_MAX                        ((band_number_t)65535)

struct shadow_map {
	uint32_t            blocks_per_band;/* size in blocks */
	uint32_t            block_size;
	u_char *            block_bitmap;       /* 1 bit per block; 1=written */
	band_number_t *     bands;              /* band map array */
	uint32_t            file_size_blocks;   /* size of file in bands */
	uint32_t            shadow_size_bands;  /* size of shadow in bands */
	uint32_t            next_band;          /* next free band */
	uint32_t            zeroth_band;        /* special-case 0th band */
};


typedef struct {
	uint32_t    byte;
	uint32_t    bit;
} bitmap_offset_t;

static __inline__ u_char
bit(int b)
{
	return (u_char)(1 << b);
}

/*
 * Function: bits_lower
 * Purpose:
 *   Return a byte value in which bits numbered lower than 'b' are set.
 */
static __inline__ u_char
bits_lower(int b)
{
	return (u_char)(bit(b) - 1);
}

/*
 * Function: byte_set_bits
 * Purpose:
 *   Set the given range of bits within a byte.
 */
static __inline__ u_char
byte_set_bits(int start, int end)
{
	return (u_char)((~bits_lower(start)) & (bits_lower(end) | bit(end)));
}

static __inline__ bitmap_offset_t
bitmap_offset(off_t where)
{
	bitmap_offset_t     b;

	b.byte = where / NBBY;
	b.bit = where % NBBY;
	return b;
}

/*
 * Function: bitmap_set
 *
 * Purpose:
 *   Set the given range of bits.
 *
 *   This algorithm tries to set the extents using the biggest
 *   units, using longs, then a short, then a byte, then bits.
 */
static void
bitmap_set(u_char * map, uint32_t start_bit, uint32_t bit_count)
{
	bitmap_offset_t     start;
	bitmap_offset_t     end;

	start = bitmap_offset(start_bit);
	end = bitmap_offset(start_bit + bit_count);
	if (start.byte < end.byte) {
		uint32_t n_bytes;

		if (start.bit) {
			map[start.byte] |= byte_set_bits(start.bit, NBBY - 1);
			start.bit = 0;
			start.byte++;
			if (start.byte == end.byte) {
				goto end;
			}
		}

		n_bytes = end.byte - start.byte;

		while (n_bytes >= (sizeof(uint32_t))) {
			*((uint32_t *)(map + start.byte)) = UINT32_ALL_ONES;
			start.byte += sizeof(uint32_t);
			n_bytes -= sizeof(uint32_t);
		}
		if (n_bytes >= sizeof(u_short)) {
			*((u_short *)(map + start.byte)) = USHORT_ALL_ONES;
			start.byte += sizeof(u_short);
			n_bytes -= sizeof(u_short);
		}
		if (n_bytes == 1) {
			map[start.byte] = UCHAR_ALL_ONES;
			start.byte++;
			n_bytes = 0;
		}
	}

end:
	if (end.bit > start.bit) {
		map[start.byte] |= byte_set_bits(start.bit, end.bit - 1);
	}

	return;
}

/*
 * Function: bitmap_get
 *
 * Purpose:
 *   Return the number of bits in the range that are the same e.g.
 *   11101 returns 3 because the first 3 bits are the same (1's), whereas
 *   001100 returns 2 because the first 2 bits are the same.
 *   This algorithm tries to count things in as big a chunk as possible,
 *   first aligning to a byte offset, then trying to count longs, a short,
 *   a byte, then any remaining bits to find the bit that is different.
 */

static uint32_t
bitmap_get(u_char * map, uint32_t start_bit, uint32_t bit_count,
    boolean_t * ret_is_set)
{
	uint32_t            count;
	int                 i;
	boolean_t           is_set;
	bitmap_offset_t     start;
	bitmap_offset_t     end;

	start = bitmap_offset(start_bit);
	end = bitmap_offset(start_bit + bit_count);

	is_set = (map[start.byte] & bit(start.bit)) ? TRUE : FALSE;
	count = 0;

	if (start.byte < end.byte) {
		uint32_t n_bytes;

		if (start.bit) { /* try to align to a byte */
			for (i = start.bit; i < NBBY; i++) {
				boolean_t       this_is_set;

				this_is_set = (map[start.byte] & bit(i)) ? TRUE : FALSE;
				if (this_is_set != is_set) {
					goto done; /* found bit that was different, we're done */
				}
				count++;
			}
			start.bit = 0; /* made it to the next byte */
			start.byte++;
			if (start.byte == end.byte) {
				goto end; /* no more bytes, check for any leftover bits */
			}
		}
		/* calculate how many bytes are left in the range */
		n_bytes = end.byte - start.byte;

		/* check for 4 bytes of the same bits */
		while (n_bytes >= sizeof(uint32_t)) {
			uint32_t * valPtr = (uint32_t *)(map + start.byte);
			if ((is_set && *valPtr == UINT32_ALL_ONES)
			    || (!is_set && *valPtr == 0)) {
				count += sizeof(*valPtr) * NBBY;
				start.byte += sizeof(*valPtr);
				n_bytes -= sizeof(*valPtr);
			} else {
				break; /* bits differ */
			}
		}
		/* check for 2 bytes of the same bits */
		if (n_bytes >= sizeof(u_short)) {
			u_short * valPtr = (u_short *)(map + start.byte);

			if ((is_set && *valPtr == USHORT_ALL_ONES)
			    || (!is_set && (*valPtr == 0))) {
				count += sizeof(*valPtr) * NBBY;
				start.byte += sizeof(*valPtr);
				n_bytes -= sizeof(*valPtr);
			}
		}

		/* check for 1 byte of the same bits */
		if (n_bytes) {
			if ((is_set && map[start.byte] == UCHAR_ALL_ONES)
			    || (!is_set && map[start.byte] == 0)) {
				count += NBBY;
				start.byte++;
				n_bytes--;
			}
			/* we found bits that were different, find the first one */
			if (n_bytes) {
				for (i = 0; i < NBBY; i++) {
					boolean_t   this_is_set;

					this_is_set = (map[start.byte] & bit(i)) ? TRUE : FALSE;
					if (this_is_set != is_set) {
						break;
					}
					count++;
				}
				goto done;
			}
		}
	}

end:
	for (i = start.bit; i < (int)end.bit; i++) {
		boolean_t this_is_set = (map[start.byte] & bit(i)) ? TRUE : FALSE;

		if (this_is_set != is_set) {
			break;
		}
		count++;
	}

done:
	*ret_is_set = is_set;
	return count;
}

static __inline__ band_number_t
shadow_map_block_to_band(shadow_map_t * map, uint32_t block)
{
	return block / map->blocks_per_band;
}

/*
 * Function: shadow_map_mapped_band
 * Purpose:
 *   Return the mapped band for the given band.
 *   If map_it is FALSE, and the band is not mapped, return FALSE.
 *   If map_it is TRUE, then this function will always return TRUE.
 */
static boolean_t
shadow_map_mapped_band(shadow_map_t * map, band_number_t band,
    boolean_t map_it, band_number_t * mapped_band)
{
	boolean_t           is_mapped = FALSE;

	if (band == map->zeroth_band) {
		*mapped_band = BAND_ZERO;
		is_mapped = TRUE;
	} else {
		*mapped_band = map->bands[band];
		if (*mapped_band == BAND_ZERO) {
			if (map_it) {
				/* grow the file */
				if (map->next_band == 0) {
					/* remember the zero'th band */
					map->zeroth_band = band;
				}
				*mapped_band = map->bands[band] = map->next_band++;
				is_mapped = TRUE;
			}
		} else {
			is_mapped = TRUE;
		}
	}
	return is_mapped;
}

/*
 * Function: shadow_map_contiguous
 *
 * Purpose:
 *   Return the first offset within the range position..(position + count)
 *   that is not a contiguous mapped band.
 *
 *   If called with is_write = TRUE, this function will map bands as it goes.
 */
static uint32_t
shadow_map_contiguous(shadow_map_t * map, uint32_t start_block,
    uint32_t num_blocks, boolean_t is_write)
{
	band_number_t       band = shadow_map_block_to_band(map, start_block);
	uint32_t            end_block = start_block + num_blocks;
	boolean_t           is_mapped;
	band_number_t       mapped_band;
	uint32_t            ret_end_block = end_block;
	uint32_t            p;

	is_mapped = shadow_map_mapped_band(map, band, is_write, &mapped_band);
	if (is_write == FALSE && is_mapped == FALSE) {
		static int happened = 0;
		/* this can't happen */
		if (happened == 0) {
			printf("shadow_map_contiguous: this can't happen!\n");
			happened = 1;
		}
		return start_block;
	}
	for (p = my_trunc(start_block + map->blocks_per_band,
	    map->blocks_per_band);
	    p < end_block; p += map->blocks_per_band) {
		band_number_t   next_mapped_band;

		band++;
		is_mapped = shadow_map_mapped_band(map, band, is_write,
		    &next_mapped_band);
		if (is_write == FALSE && is_mapped == FALSE) {
			return p;
		}
		if ((mapped_band + 1) != next_mapped_band) {
			/* not contiguous */
			ret_end_block = p;
			break;
		}
		mapped_band = next_mapped_band;
	}
	return ret_end_block;
}


/*
 * Function: block_bitmap_size
 * Purpose:
 *   The number of bytes required in a block bitmap to represent a file of size
 *   file_size.
 *
 *   The bytes required is the number of blocks in the file,
 *   divided by the number of bits per byte.
 * Note:
 *   An 8GB file requires (assuming 512 byte block):
 *   2^33 / 2^9 / 2^3 = 2^21 = 2MB
 *   of bitmap space.  This is a non-trival amount of memory,
 *   particularly since most of the bits will be zero.
 *   A sparse bitmap would really help in this case.
 */
static __inline__ uint32_t
block_bitmap_size(off_t file_size, uint32_t block_size)
{
	off_t blocks = howmany(file_size, block_size);
	return howmany(blocks, NBBY);
}

/*
 * Function: shadow_map_read
 *
 * Purpose:
 *   Calculate the block offset within the shadow to read, and the number
 *   blocks to read.  The input values (block_offset, block_count) refer
 *   to the original file.
 *
 *   The output values (*incr_block_offset, *incr_block_count) refer to the
 *   shadow file if the return value is TRUE.  They refer to the original
 *   file if the return value is FALSE.
 *
 *   Blocks within a band may or may not have been written, in addition,
 *   Bands are not necessarily contiguous, therefore:
 *      *incr_block_count <= block_count
 *   The caller must be prepared to call this function interatively
 *   to complete the whole i/o.
 * Returns:
 *   TRUE if the shadow file should be read, FALSE if the original file
 *   should be read.
 */
boolean_t
shadow_map_read(shadow_map_t * map, uint32_t block_offset, uint32_t block_count,
    uint32_t * incr_block_offset, uint32_t * incr_block_count)
{
	boolean_t           written = FALSE;
	uint32_t            n_blocks;

	if (block_offset >= map->file_size_blocks
	    || (block_offset + block_count) > map->file_size_blocks) {
		printf("shadow_map_read: request (%d, %d) exceeds file size %d\n",
		    block_offset, block_count, map->file_size_blocks);
		*incr_block_count = 0;
	}
	n_blocks = bitmap_get(map->block_bitmap, block_offset, block_count,
	    &written);
	if (written == FALSE) {
		*incr_block_count = n_blocks;
		*incr_block_offset = block_offset;
	} else { /* start has been written, and therefore mapped */
		band_number_t   mapped_band;
		uint32_t                band_limit;

		mapped_band = map->bands[shadow_map_block_to_band(map, block_offset)];
		*incr_block_offset = mapped_band * map->blocks_per_band
		    + (block_offset % map->blocks_per_band);
		band_limit
		        = shadow_map_contiguous(map, block_offset, block_count, FALSE);
		*incr_block_count = band_limit - block_offset;
		if (*incr_block_count > n_blocks) {
			*incr_block_count = n_blocks;
		}
	}
	return written;
}

/*
 * Function: shadow_map_write
 *
 * Purpose:
 *   Calculate the block offset within the shadow to write, and the number
 *   blocks to write.  The input values (block_offset, block_count) refer
 *   to the original file.  The output values
 *   (*incr_block_offset, *incr_block_count) refer to the shadow file.
 *
 *   Bands are not necessarily contiguous, therefore:
 *      *incr_block_count <= block_count
 *   The caller must be prepared to call this function interatively
 *   to complete the whole i/o.
 * Returns:
 *   TRUE if the shadow file was grown, FALSE otherwise.
 */
boolean_t
shadow_map_write(shadow_map_t * map, uint32_t block_offset,
    uint32_t block_count, uint32_t * incr_block_offset,
    uint32_t * incr_block_count)
{
	uint32_t            band_limit;
	band_number_t       mapped_band;
	boolean_t           shadow_grew = FALSE;

	if (block_offset >= map->file_size_blocks
	    || (block_offset + block_count) > map->file_size_blocks) {
		printf("shadow_map_write: request (%d, %d) exceeds file size %d\n",
		    block_offset, block_count, map->file_size_blocks);
		*incr_block_count = 0;
	}

	band_limit = shadow_map_contiguous(map, block_offset, block_count, TRUE);
	mapped_band = map->bands[shadow_map_block_to_band(map, block_offset)];
	*incr_block_offset = mapped_band * map->blocks_per_band
	    + (block_offset % map->blocks_per_band);
	*incr_block_count = band_limit - block_offset;

	/* mark these blocks as written */
	bitmap_set(map->block_bitmap, block_offset, *incr_block_count);

	if (map->next_band > map->shadow_size_bands) {
		map->shadow_size_bands = map->next_band;
		shadow_grew = TRUE;
	}
	return shadow_grew;
}

boolean_t
shadow_map_is_written(shadow_map_t * map, uint32_t block_offset)
{
	bitmap_offset_t     b;

	b = bitmap_offset(block_offset);
	return (map->block_bitmap[b.byte] & bit(b.bit)) ? TRUE : FALSE;
}

/*
 * Function: shadow_map_shadow_size
 *
 * Purpose:
 *   To return the size of the shadow file in blocks.
 */
uint32_t
shadow_map_shadow_size(shadow_map_t * map)
{
	return map->shadow_size_bands * map->blocks_per_band;
}

/*
 * Function: shadow_map_create
 *
 * Purpose:
 *   Allocate the dynamic data for keeping track of the shadow dirty blocks
 *   and the band mapping table.
 * Returns:
 *   NULL if an error occurred.
 */
shadow_map_t *
shadow_map_create(off_t file_size, off_t shadow_size,
    uint32_t band_size, uint32_t block_size)
{
	void *              block_bitmap = NULL;
	uint32_t            bitmap_size;
	band_number_t *     bands = NULL;
	shadow_map_t *      map;
	uint32_t            n_bands = 0;

	if (band_size == 0) {
		band_size = BAND_SIZE_DEFAULT;
	}

	n_bands = howmany(file_size, band_size);
	if (n_bands > (BAND_MAX + 1)) {
		printf("file is too big: %d > %d\n",
		    n_bands, BAND_MAX);
		goto failure;
	}

	/* create a block bitmap, one bit per block */
	bitmap_size = block_bitmap_size(file_size, block_size);
	block_bitmap = my_malloc(bitmap_size);
	if (block_bitmap == NULL) {
		printf("failed to allocate bitmap\n");
		goto failure;
	}
	bzero(block_bitmap, bitmap_size);

	/* get the band map */
	bands = (band_number_t *)my_malloc(n_bands * sizeof(band_number_t));
	if (bands == NULL) {
		printf("failed to allocate bands\n");
		goto failure;
	}
	bzero(bands, n_bands * sizeof(band_number_t));

	map = my_malloc(sizeof(*map));
	if (map == NULL) {
		printf("failed to allocate map\n");
		goto failure;
	}
	map->blocks_per_band = band_size / block_size;
	map->block_bitmap = block_bitmap;
	map->bands = bands;
	map->file_size_blocks = n_bands * map->blocks_per_band;
	map->next_band = 0;
	map->zeroth_band = -1;
	map->shadow_size_bands = howmany(shadow_size, band_size);
	map->block_size = block_size;
	return map;

failure:
	if (block_bitmap) {
		my_free(block_bitmap);
	}
	if (bands) {
		my_free(bands);
	}
	return NULL;
}

/*
 * Function: shadow_map_free
 * Purpose:
 *   Frees the data structure to deal with the shadow map.
 */
void
shadow_map_free(shadow_map_t * map)
{
	if (map->block_bitmap) {
		my_free(map->block_bitmap);
	}
	if (map->bands) {
		my_free(map->bands);
	}
	map->block_bitmap = NULL;
	map->bands = NULL;
	my_free(map);
	return;
}

#ifdef TEST_SHADOW
#define BAND_SIZE_BLOCKS        (BAND_SIZE_DEFAULT / 512)

enum {
	ReadRequest,
	WriteRequest,
};

typedef struct {
	int         type;
	uint32_t    offset;
	uint32_t    count;
} block_request_t;

int
main()
{
	shadow_map_t *      map;
	int                 i;
	block_request_t     requests[] = {
		{ WriteRequest, BAND_SIZE_BLOCKS * 2, 1 },
		{ ReadRequest, BAND_SIZE_BLOCKS / 2, BAND_SIZE_BLOCKS * 2 - 2 },
		{ WriteRequest, BAND_SIZE_BLOCKS * 1, 5 * BAND_SIZE_BLOCKS + 3},
		{ ReadRequest, 0, BAND_SIZE_BLOCKS * 10 },
		{ WriteRequest, BAND_SIZE_BLOCKS * (BAND_MAX - 1),
		  BAND_SIZE_BLOCKS * 2},
		{ 0, 0 },
	};

	map = shadow_map_create(1024 * 1024 * 1024 * 8ULL, 0, 0, 512);
	if (map == NULL) {
		printf("shadow_map_create failed\n");
		exit(1);
	}
	for (i = 0; TRUE; i++) {
		uint32_t                offset;
		uint32_t                resid;
		boolean_t       shadow_grew;
		boolean_t       read_shadow;

		if (requests[i].count == 0) {
			break;
		}
		offset = requests[i].offset;
		resid = requests[i].count;
		printf("\n%s REQUEST (%ld, %ld)\n",
		    requests[i].type == WriteRequest ? "WRITE" : "READ",
		    offset, resid);
		switch (requests[i].type) {
		case WriteRequest:
			while (resid > 0) {
				uint32_t this_offset;
				uint32_t this_count;

				shadow_grew = shadow_map_write(map, offset,
				    resid,
				    &this_offset,
				    &this_count);
				printf("\t(%ld, %ld) => (%ld, %ld)",
				    offset, resid, this_offset, this_count);
				resid -= this_count;
				offset += this_count;
				if (shadow_grew) {
					printf(" shadow grew to %ld", shadow_map_shadow_size(map));
				}
				printf("\n");
			}
			break;
		case ReadRequest:
			while (resid > 0) {
				uint32_t this_offset;
				uint32_t this_count;

				read_shadow = shadow_map_read(map, offset,
				    resid,
				    &this_offset,
				    &this_count);
				printf("\t(%ld, %ld) => (%ld, %ld)%s\n",
				    offset, resid, this_offset, this_count,
				    read_shadow ? " from shadow" : "");
				if (this_count == 0) {
					printf("this_count is 0, aborting\n");
					break;
				}
				resid -= this_count;
				offset += this_count;
			}
			break;
		default:
			break;
		}
	}
	if (map) {
		shadow_map_free(map);
	}
	exit(0);
	return 0;
}
#endif
