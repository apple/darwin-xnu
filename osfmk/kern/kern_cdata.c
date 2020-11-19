/*
 * Copyright (c) 2015 Apple Inc. All rights reserved.
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

#include <kern/assert.h>
#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/vm_param.h>
#include <kern/kern_types.h>
#include <kern/mach_param.h>
#include <kern/thread.h>
#include <kern/task.h>
#include <kern/kern_cdata.h>
#include <kern/kalloc.h>
#include <mach/mach_vm.h>

static kern_return_t kcdata_get_memory_addr_with_flavor(kcdata_descriptor_t data, uint32_t type, uint32_t size, uint64_t flags, mach_vm_address_t *user_addr);
static size_t kcdata_get_memory_size_for_data(uint32_t size);
static kern_return_t kcdata_compress_chunk_with_flags(kcdata_descriptor_t data, uint32_t type, const void *input_data, uint32_t input_size, uint64_t flags);
static kern_return_t kcdata_compress_chunk(kcdata_descriptor_t data, uint32_t type, const void *input_data, uint32_t input_size);
static kern_return_t kcdata_write_compression_stats(kcdata_descriptor_t data);
static kern_return_t kcdata_get_compression_stats(kcdata_descriptor_t data, uint64_t *totalout, uint64_t *totalin);

/*
 * zlib will need to store its metadata and this value is indifferent from the
 * window bits and other zlib internals
 */
#define ZLIB_METADATA_SIZE 1440

/* #define kcdata_debug_printf printf */
#define kcdata_debug_printf(...) ;

#pragma pack(push, 4)

/* Internal structs for convenience */
struct _uint64_with_description_data {
	char desc[KCDATA_DESC_MAXLEN];
	uint64_t data;
};

struct _uint32_with_description_data {
	char     desc[KCDATA_DESC_MAXLEN];
	uint32_t data;
};

#pragma pack(pop)

/*
 * Estimates how large of a buffer that should be allocated for a buffer that will contain
 * num_items items of known types with overall length payload_size.
 *
 * NOTE: This function will not give an accurate estimate for buffers that will
 *       contain unknown types (those with string descriptions).
 */
uint32_t
kcdata_estimate_required_buffer_size(uint32_t num_items, uint32_t payload_size)
{
	/*
	 * In the worst case each item will need (KCDATA_ALIGNMENT_SIZE - 1) padding
	 */
	uint32_t max_padding_bytes = 0;
	uint32_t max_padding_with_item_description_bytes = 0;
	uint32_t estimated_required_buffer_size = 0;
	const uint32_t begin_and_end_marker_bytes = 2 * sizeof(struct kcdata_item);

	if (os_mul_overflow(num_items, KCDATA_ALIGNMENT_SIZE - 1, &max_padding_bytes)) {
		panic("%s: Overflow in required buffer size estimate", __func__);
	}

	if (os_mul_and_add_overflow(num_items, sizeof(struct kcdata_item), max_padding_bytes, &max_padding_with_item_description_bytes)) {
		panic("%s: Overflow in required buffer size estimate", __func__);
	}

	if (os_add3_overflow(max_padding_with_item_description_bytes, begin_and_end_marker_bytes, payload_size, &estimated_required_buffer_size)) {
		panic("%s: Overflow in required buffer size estimate", __func__);
	}

	return estimated_required_buffer_size;
}

kcdata_descriptor_t
kcdata_memory_alloc_init(mach_vm_address_t buffer_addr_p, unsigned data_type, unsigned size, unsigned flags)
{
	kcdata_descriptor_t data = NULL;
	mach_vm_address_t user_addr = 0;
	uint16_t clamped_flags = (uint16_t) flags;

	data = kalloc_flags(sizeof(struct kcdata_descriptor), Z_WAITOK | Z_ZERO);
	if (data == NULL) {
		return NULL;
	}
	data->kcd_addr_begin = buffer_addr_p;
	data->kcd_addr_end = buffer_addr_p;
	data->kcd_flags = (clamped_flags & KCFLAG_USE_COPYOUT) ? clamped_flags : clamped_flags | KCFLAG_USE_MEMCOPY;
	data->kcd_length = size;

	/* Initialize the BEGIN header */
	if (KERN_SUCCESS != kcdata_get_memory_addr(data, data_type, 0, &user_addr)) {
		kcdata_memory_destroy(data);
		return NULL;
	}

	return data;
}

kern_return_t
kcdata_memory_static_init(kcdata_descriptor_t data, mach_vm_address_t buffer_addr_p, unsigned data_type, unsigned size, unsigned flags)
{
	mach_vm_address_t user_addr = 0;
	uint16_t clamped_flags = (uint16_t) flags;

	if (data == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	bzero(data, sizeof(struct kcdata_descriptor));
	data->kcd_addr_begin = buffer_addr_p;
	data->kcd_addr_end = buffer_addr_p;
	data->kcd_flags = (clamped_flags & KCFLAG_USE_COPYOUT) ? clamped_flags : clamped_flags | KCFLAG_USE_MEMCOPY;
	data->kcd_length = size;

	/* Initialize the BEGIN header */
	return kcdata_get_memory_addr(data, data_type, 0, &user_addr);
}

void *
kcdata_memory_get_begin_addr(kcdata_descriptor_t data)
{
	if (data == NULL) {
		return NULL;
	}

	return (void *)data->kcd_addr_begin;
}

uint64_t
kcdata_memory_get_used_bytes(kcdata_descriptor_t kcd)
{
	assert(kcd != NULL);
	return ((uint64_t)kcd->kcd_addr_end - (uint64_t)kcd->kcd_addr_begin) + sizeof(struct kcdata_item);
}

uint64_t
kcdata_memory_get_uncompressed_bytes(kcdata_descriptor_t kcd)
{
	kern_return_t kr;

	assert(kcd != NULL);
	if (kcd->kcd_flags & KCFLAG_USE_COMPRESSION) {
		uint64_t totalout, totalin;

		kr = kcdata_get_compression_stats(kcd, &totalout, &totalin);
		if (kr == KERN_SUCCESS) {
			return totalin;
		} else {
			return 0;
		}
	} else {
		/* If compression wasn't used, get the number of bytes used  */
		return kcdata_memory_get_used_bytes(kcd);
	}
}

/*
 * Free up the memory associated with kcdata
 */
kern_return_t
kcdata_memory_destroy(kcdata_descriptor_t data)
{
	if (!data) {
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * data->kcd_addr_begin points to memory in not tracked by
	 * kcdata lib. So not clearing that here.
	 */
	kfree(data, sizeof(struct kcdata_descriptor));
	return KERN_SUCCESS;
}

/* Used by zlib to allocate space in its metadata section */
static void *
kcdata_compress_zalloc(void *opaque, u_int items, u_int size)
{
	void *result;
	struct kcdata_compress_descriptor *cd = opaque;
	int alloc_size = ~31L & (31 + (items * size));

	result = (void *)(cd->kcd_cd_base + cd->kcd_cd_offset);
	if ((uintptr_t) result + alloc_size > (uintptr_t) cd->kcd_cd_base + cd->kcd_cd_maxoffset) {
		result = Z_NULL;
	} else {
		cd->kcd_cd_offset += alloc_size;
	}

	kcdata_debug_printf("%s: %d * %d = %d  => %p\n", __func__, items, size, items * size, result);

	return result;
}

/* Used by zlib to free previously allocated space in its metadata section */
static void
kcdata_compress_zfree(void *opaque, void *ptr)
{
	(void) opaque;
	(void) ptr;

	kcdata_debug_printf("%s: ptr %p\n", __func__, ptr);

	/*
	 * Since the buffers we are using are temporary, we don't worry about
	 * freeing memory for now. Besides, testing has shown that zlib only calls
	 * this at the end, near deflateEnd() or a Z_FINISH deflate() call.
	 */
}

/* Used to initialize the selected compression algorithm's internal state (if any) */
static kern_return_t
kcdata_init_compress_state(kcdata_descriptor_t data, void (*memcpy_f)(void *, const void *, size_t), uint64_t type, mach_vm_address_t totalout_addr, mach_vm_address_t totalin_addr)
{
	kern_return_t ret = KERN_SUCCESS;
	size_t size;
	int wbits = 12, memlevel = 3;
	struct kcdata_compress_descriptor *cd = &data->kcd_comp_d;

	cd->kcd_cd_memcpy_f = memcpy_f;
	cd->kcd_cd_compression_type = type;
	cd->kcd_cd_totalout_addr = totalout_addr;
	cd->kcd_cd_totalin_addr = totalin_addr;

	switch (type) {
	case KCDCT_ZLIB:
		/* allocate space for the metadata used by zlib */
		size = round_page(ZLIB_METADATA_SIZE + zlib_deflate_memory_size(wbits, memlevel));
		kcdata_debug_printf("%s: size = %zu kcd_length: %d\n", __func__, size, data->kcd_length);
		kcdata_debug_printf("%s: kcd buffer [%p - %p]\n", __func__, (void *) data->kcd_addr_begin, (void *) data->kcd_addr_begin + data->kcd_length);

		if (4 * size > data->kcd_length) {
			return KERN_INSUFFICIENT_BUFFER_SIZE;
		}

		cd->kcd_cd_zs.avail_in = 0;
		cd->kcd_cd_zs.next_in = NULL;
		cd->kcd_cd_zs.avail_out = 0;
		cd->kcd_cd_zs.next_out = NULL;
		cd->kcd_cd_zs.opaque = cd;
		cd->kcd_cd_zs.zalloc = kcdata_compress_zalloc;
		cd->kcd_cd_zs.zfree = kcdata_compress_zfree;
		cd->kcd_cd_base = (void *) data->kcd_addr_begin + data->kcd_length - size;
		data->kcd_length -= size;
		cd->kcd_cd_offset = 0;
		cd->kcd_cd_maxoffset = size;
		cd->kcd_cd_flags = 0;

		kcdata_debug_printf("%s: buffer [%p - %p]\n", __func__, cd->kcd_cd_base, cd->kcd_cd_base + size);

		if (deflateInit2(&cd->kcd_cd_zs, Z_BEST_SPEED, Z_DEFLATED, wbits, memlevel, Z_DEFAULT_STRATEGY) != Z_OK) {
			kcdata_debug_printf("EMERGENCY: deflateInit2 failed!\n");
			ret = KERN_INVALID_ARGUMENT;
		}
		break;
	default:
		panic("kcdata_init_compress_state: invalid compression type: %d", (int) type);
	}

	return ret;
}


/*
 * Turn on the compression logic for kcdata
 */
kern_return_t
kcdata_init_compress(kcdata_descriptor_t data, int hdr_tag, void (*memcpy_f)(void *, const void *, size_t), uint64_t type)
{
	kern_return_t kr;
	mach_vm_address_t user_addr, totalout_addr, totalin_addr;
	struct _uint64_with_description_data save_data;
	const uint64_t size_req = sizeof(save_data);

	assert(data && (data->kcd_flags & KCFLAG_USE_COMPRESSION) == 0);

	/* reset the compression descriptor */
	bzero(&data->kcd_comp_d, sizeof(struct kcdata_compress_descriptor));

	/* add the header information */
	kcdata_add_uint64_with_description(data, type, "kcd_c_type");

	/* reserve space to write total out */
	bzero(&save_data, size_req);
	strlcpy(&(save_data.desc[0]), "kcd_c_totalout", sizeof(save_data.desc));
	kr = kcdata_get_memory_addr(data, KCDATA_TYPE_UINT64_DESC, size_req, &totalout_addr);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	memcpy((void *)totalout_addr, &save_data, size_req);

	/* space for total in */
	bzero(&save_data, size_req);
	strlcpy(&(save_data.desc[0]), "kcd_c_totalin", sizeof(save_data.desc));
	kr = kcdata_get_memory_addr(data, KCDATA_TYPE_UINT64_DESC, size_req, &totalin_addr);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	memcpy((void *)totalin_addr, &save_data, size_req);

	/* add the inner buffer */
	kcdata_get_memory_addr(data, hdr_tag, 0, &user_addr);

	/* save the flag */
	data->kcd_flags |= KCFLAG_USE_COMPRESSION;

	/* initialize algorithm specific state */
	kr = kcdata_init_compress_state(data, memcpy_f, type, totalout_addr + offsetof(struct _uint64_with_description_data, data), totalin_addr + offsetof(struct _uint64_with_description_data, data));
	if (kr != KERN_SUCCESS) {
		kcdata_debug_printf("%s: failed to initialize compression state!\n", __func__);
		return kr;
	}

	return KERN_SUCCESS;
}

static inline
int
kcdata_zlib_translate_kcd_cf_flag(enum kcdata_compression_flush flush)
{
	switch (flush) {
	case KCDCF_NO_FLUSH: return Z_NO_FLUSH;
	case KCDCF_SYNC_FLUSH: return Z_SYNC_FLUSH;
	case KCDCF_FINISH: return Z_FINISH;
	default: panic("invalid kcdata_zlib_translate_kcd_cf_flag flag");
	}
}

static inline
int
kcdata_zlib_translate_kcd_cf_expected_ret(enum kcdata_compression_flush flush)
{
	switch (flush) {
	case KCDCF_NO_FLUSH:         /* fall through */
	case KCDCF_SYNC_FLUSH: return Z_OK;
	case KCDCF_FINISH: return Z_STREAM_END;
	default: panic("invalid kcdata_zlib_translate_kcd_cf_expected_ret flag");
	}
}

/* Called by kcdata_do_compress() when the configured compression algorithm is zlib */
static kern_return_t
kcdata_do_compress_zlib(kcdata_descriptor_t data, void *inbuffer,
    size_t insize, void *outbuffer, size_t outsize, size_t *wrote,
    enum kcdata_compression_flush flush)
{
	struct kcdata_compress_descriptor *cd = &data->kcd_comp_d;
	z_stream *zs = &cd->kcd_cd_zs;
	int expected_ret, ret;

	zs->next_out = outbuffer;
	zs->avail_out = (unsigned int) outsize;
	zs->next_in = inbuffer;
	zs->avail_in = (unsigned int) insize;
	ret = deflate(zs, kcdata_zlib_translate_kcd_cf_flag(flush));
	if (zs->avail_in != 0 || zs->avail_out <= 0) {
		return KERN_INSUFFICIENT_BUFFER_SIZE;
	}

	expected_ret = kcdata_zlib_translate_kcd_cf_expected_ret(flush);
	if (ret != expected_ret) {
		/*
		 * Should only fail with catastrophic, unrecoverable cases (i.e.,
		 * corrupted z_stream, or incorrect configuration)
		 */
		panic("zlib kcdata compression ret = %d\n", ret);
	}

	kcdata_debug_printf("%s: %p (%zu) <- %p (%zu); flush: %d; ret = %ld\n",
	    __func__, outbuffer, outsize, inbuffer, insize, flush, outsize - zs->avail_out);
	if (wrote) {
		*wrote = outsize - zs->avail_out;
	}
	return KERN_SUCCESS;
}

/*
 * Compress the buffer at @inbuffer (of size @insize) into the kcdata buffer
 * @outbuffer (of size @outsize). Flush based on the @flush parameter.
 *
 * Returns KERN_SUCCESS on success, or KERN_INSUFFICIENT_BUFFER_SIZE if
 * @outsize isn't sufficient. Also, writes the number of bytes written in the
 * @outbuffer to @wrote.
 */
static kern_return_t
kcdata_do_compress(kcdata_descriptor_t data, void *inbuffer, size_t insize,
    void *outbuffer, size_t outsize, size_t *wrote, enum kcdata_compression_flush flush)
{
	struct kcdata_compress_descriptor *cd = &data->kcd_comp_d;

	assert(data->kcd_flags & KCFLAG_USE_COMPRESSION);

	kcdata_debug_printf("%s: %p (%zu) <- %p (%zu); flush: %d\n",
	    __func__, outbuffer, outsize, inbuffer, insize, flush);

	/* don't compress if we are in a window */
	if (cd->kcd_cd_flags & KCD_CD_FLAG_IN_MARK || data->kcd_comp_d.kcd_cd_compression_type == KCDCT_NONE) {
		assert(cd->kcd_cd_memcpy_f);
		if (outsize >= insize) {
			cd->kcd_cd_memcpy_f(outbuffer, inbuffer, insize);
			if (wrote) {
				*wrote = insize;
			}
			return KERN_SUCCESS;
		} else {
			return KERN_INSUFFICIENT_BUFFER_SIZE;
		}
	}

	switch (data->kcd_comp_d.kcd_cd_compression_type) {
	case KCDCT_ZLIB:
		return kcdata_do_compress_zlib(data, inbuffer, insize, outbuffer, outsize, wrote, flush);
	default:
		panic("invalid compression type 0x%llx in kcdata_do_compress", data->kcd_comp_d.kcd_cd_compression_type);
	}
}

static size_t
kcdata_compression_bound_zlib(kcdata_descriptor_t data, size_t size)
{
	struct kcdata_compress_descriptor *cd = &data->kcd_comp_d;
	z_stream *zs = &cd->kcd_cd_zs;

	return (size_t) deflateBound(zs, (unsigned long) size);
}


/*
 * returns the worst-case, maximum length of the compressed data when
 * compressing a buffer of size @size using the configured algorithm.
 */
static size_t
kcdata_compression_bound(kcdata_descriptor_t data, size_t size)
{
	switch (data->kcd_comp_d.kcd_cd_compression_type) {
	case KCDCT_ZLIB:
		return kcdata_compression_bound_zlib(data, size);
	case KCDCT_NONE:
		return size;
	default:
		panic("%s: unknown compression method", __func__);
	}
}

/*
 * kcdata_compress_chunk_with_flags:
 *		Compress buffer found at @input_data (length @input_size) to the kcdata
 *		buffer described by @data. This method will construct the kcdata_item_t
 *		required by parsers using the type information @type and flags @flags.
 *
 *	Returns KERN_SUCCESS when successful. Currently, asserts on failure.
 */
kern_return_t
kcdata_compress_chunk_with_flags(kcdata_descriptor_t data, uint32_t type, const void *input_data, uint32_t input_size, uint64_t kcdata_flags)
{
	assert(data);
	assert((data->kcd_flags & KCFLAG_USE_COMPRESSION));
	assert(input_data);
	struct kcdata_item info;
	char padding_data[16] = {0};
	struct kcdata_compress_descriptor *cd = &data->kcd_comp_d;
	size_t wrote = 0;
	kern_return_t kr;

	kcdata_debug_printf("%s: type: %d input_data: %p (%d) kcdata_flags: 0x%llx\n",
	    __func__, type, input_data, input_size, kcdata_flags);

	/*
	 * first, get memory space. The uncompressed size must fit in the remained
	 * of the kcdata buffer, in case the compression algorithm doesn't actually
	 * compress the data at all.
	 */
	size_t total_uncompressed_size = kcdata_compression_bound(data, (size_t) kcdata_get_memory_size_for_data(input_size));
	if (total_uncompressed_size > data->kcd_length ||
	    data->kcd_length - total_uncompressed_size < data->kcd_addr_end - data->kcd_addr_begin) {
		kcdata_debug_printf("%s: insufficient buffer size: kcd_length => %d e-b=> %lld our size: %zu\n",
		    __func__, data->kcd_length, data->kcd_addr_end - data->kcd_addr_begin, total_uncompressed_size);
		return KERN_INSUFFICIENT_BUFFER_SIZE;
	}
	uint32_t padding = kcdata_calc_padding(input_size);
	assert(padding < sizeof(padding_data));

	void *space_start = (void *) data->kcd_addr_end;
	void *space_ptr = space_start;

	/* create the output stream */
	size_t total_uncompressed_space_remaining = total_uncompressed_size;

	/* create the info data */
	bzero(&info, sizeof(info));
	info.type = type;
	info.size = input_size + padding;
	info.flags = kcdata_flags;

	/*
	 * The next possibly three compresses are needed separately because of the
	 * scatter-gather nature of this operation. The kcdata item header (info)
	 * and padding are on the stack, while the actual data is somewhere else.
	 * */

	/* create the input stream for info & compress */
	enum kcdata_compression_flush flush = (padding || input_size) ? KCDCF_NO_FLUSH :
	    cd->kcd_cd_flags & KCD_CD_FLAG_FINALIZE ? KCDCF_FINISH :
	    KCDCF_SYNC_FLUSH;
	kr = kcdata_do_compress(data, &info, sizeof(info), space_ptr, total_uncompressed_space_remaining, &wrote, flush);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	kcdata_debug_printf("%s: first wrote = %zu\n", __func__, wrote);
	space_ptr  += wrote;
	total_uncompressed_space_remaining -= wrote;

	/* If there is input provided, compress that here */
	if (input_size) {
		flush = padding ? KCDCF_NO_FLUSH :
		    cd->kcd_cd_flags & KCD_CD_FLAG_FINALIZE ? KCDCF_FINISH :
		    KCDCF_SYNC_FLUSH;
		kr = kcdata_do_compress(data, (void *) (uintptr_t) input_data, input_size, space_ptr, total_uncompressed_space_remaining, &wrote, flush);
		if (kr != KERN_SUCCESS) {
			return kr;
		}
		kcdata_debug_printf("%s: 2nd wrote = %zu\n", __func__, wrote);
		space_ptr  += wrote;
		total_uncompressed_space_remaining -= wrote;
	}

	/* If the item and its data require padding to maintain alignment,
	 * "compress" that into the output buffer. */
	if (padding) {
		/* write the padding */
		kr = kcdata_do_compress(data, padding_data, padding, space_ptr, total_uncompressed_space_remaining, &wrote,
		    cd->kcd_cd_flags & KCD_CD_FLAG_FINALIZE ? KCDCF_FINISH : KCDCF_SYNC_FLUSH);
		if (kr != KERN_SUCCESS) {
			return kr;
		}
		kcdata_debug_printf("%s: 3rd wrote = %zu\n", __func__, wrote);
		if (wrote == 0) {
			return KERN_FAILURE;
		}
		space_ptr  += wrote;
		total_uncompressed_space_remaining -= wrote;
	}

	assert((size_t)(space_ptr - space_start) <= total_uncompressed_size);

	/* move the end marker forward */
	data->kcd_addr_end = (mach_vm_address_t) (space_start + (total_uncompressed_size - total_uncompressed_space_remaining));

	return KERN_SUCCESS;
}

/*
 * kcdata_compress_chunk:
 *		Like kcdata_compress_chunk_with_flags(), but uses the default set of kcdata flags,
 *		i.e. padding and also saves the amount of padding bytes.
 *
 * Returns are the same as in kcdata_compress_chunk_with_flags()
 */
kern_return_t
kcdata_compress_chunk(kcdata_descriptor_t data, uint32_t type, const void *input_data, uint32_t input_size)
{
	/* these flags are for kcdata - store that the struct is padded and store the amount of padding bytes */
	uint64_t flags = (KCDATA_FLAGS_STRUCT_PADDING_MASK & kcdata_calc_padding(input_size)) | KCDATA_FLAGS_STRUCT_HAS_PADDING;
	return kcdata_compress_chunk_with_flags(data, type, input_data, input_size, flags);
}

kern_return_t
kcdata_push_data(kcdata_descriptor_t data, uint32_t type, uint32_t size, const void *input_data)
{
	if (data->kcd_flags & KCFLAG_USE_COMPRESSION) {
		return kcdata_compress_chunk(data, type, input_data, size);
	} else {
		kern_return_t ret;
		mach_vm_address_t uaddr = 0;
		ret = kcdata_get_memory_addr(data, type, size, &uaddr);
		if (ret != KERN_SUCCESS) {
			return ret;
		}

		kcdata_memcpy(data, uaddr, input_data, size);
		return KERN_SUCCESS;
	}
}

kern_return_t
kcdata_push_array(kcdata_descriptor_t data, uint32_t type_of_element, uint32_t size_of_element, uint32_t count, const void *input_data)
{
	uint64_t flags      = type_of_element;
	flags               = (flags << 32) | count;
	uint32_t total_size = count * size_of_element;
	uint32_t pad        = kcdata_calc_padding(total_size);

	if (data->kcd_flags & KCFLAG_USE_COMPRESSION) {
		return kcdata_compress_chunk_with_flags(data, KCDATA_TYPE_ARRAY_PAD0 | pad, input_data, total_size, flags);
	} else {
		kern_return_t ret;
		mach_vm_address_t uaddr = 0;
		ret = kcdata_get_memory_addr_with_flavor(data, KCDATA_TYPE_ARRAY_PAD0 | pad, total_size, flags, &uaddr);
		if (ret != KERN_SUCCESS) {
			return ret;
		}

		kcdata_memcpy(data, uaddr, input_data, total_size);
		return KERN_SUCCESS;
	}
}

/* A few words on how window compression works:
 *
 * This is how the buffer looks when the window is opened:
 *
 * X---------------------------------------------------------------------X
 * |                                |                                    |
 * |   Filled with stackshot data   |            Zero bytes              |
 * |                                |                                    |
 * X---------------------------------------------------------------------X
 *                                  ^
 *									\ - kcd_addr_end
 *
 * Opening a window will save the current kcd_addr_end to kcd_cd_mark_begin.
 *
 * Any kcdata_* operation will then push data to the buffer like normal. (If
 * you call any compressing functions they will pass-through, i.e. no
 * compression will be done) Once the window is closed, the following takes
 * place:
 *
 * X---------------------------------------------------------------------X
 * |               |                    |                    |           |
 * | Existing data |     New data       |   Scratch buffer   |           |
 * |               |                    |                    |           |
 * X---------------------------------------------------------------------X
 *				   ^                    ^                    ^
 *				   |                    |                    |
 *				   \ -kcd_cd_mark_begin |                    |
 *							            |                    |
 *							            \ - kcd_addr_end     |
 *							                                 |
 *		 kcd_addr_end + (kcd_addr_end - kcd_cd_mark_begin) - /
 *
 *	(1) The data between kcd_cd_mark_begin and kcd_addr_end is fed to the
 *      compression algorithm to compress to the scratch buffer.
 *  (2) The scratch buffer's contents are copied into the area denoted "New
 *      data" above. Effectively overwriting the uncompressed data with the
 *      compressed one.
 *  (3) kcd_addr_end is then rewound to kcd_cd_mark_begin + sizeof_compressed_data
 */

/* Record the state, and restart compression from this later */
void
kcdata_compression_window_open(kcdata_descriptor_t data)
{
	struct kcdata_compress_descriptor *cd = &data->kcd_comp_d;
	assert((cd->kcd_cd_flags & KCD_CD_FLAG_IN_MARK) == 0);

	if (data->kcd_flags & KCFLAG_USE_COMPRESSION) {
		cd->kcd_cd_flags |= KCD_CD_FLAG_IN_MARK;
		cd->kcd_cd_mark_begin = data->kcd_addr_end;
	}
}

/* Compress the region between the mark and the current end */
kern_return_t
kcdata_compression_window_close(kcdata_descriptor_t data)
{
	struct kcdata_compress_descriptor *cd = &data->kcd_comp_d;
	uint64_t total_size, max_size;
	void *space_start, *space_ptr;
	size_t total_uncompressed_space_remaining, wrote = 0;
	kern_return_t kr;

	if ((data->kcd_flags & KCFLAG_USE_COMPRESSION) == 0) {
		return KERN_SUCCESS;
	}

	assert(cd->kcd_cd_flags & KCD_CD_FLAG_IN_MARK);

	if (data->kcd_addr_end == (mach_vm_address_t) cd->kcd_cd_mark_begin) {
		/* clear the window marker and return, this is a no-op */
		cd->kcd_cd_flags &= ~KCD_CD_FLAG_IN_MARK;
		return KERN_SUCCESS;
	}

	assert(cd->kcd_cd_mark_begin < data->kcd_addr_end);
	total_size = data->kcd_addr_end - (uint64_t) cd->kcd_cd_mark_begin;
	max_size = (uint64_t) kcdata_compression_bound(data, total_size);
	kcdata_debug_printf("%s: total_size = %lld\n", __func__, total_size);

	/*
	 * first, get memory space. The uncompressed size must fit in the remained
	 * of the kcdata buffer, in case the compression algorithm doesn't actually
	 * compress the data at all.
	 */
	if (max_size > data->kcd_length ||
	    data->kcd_length - max_size < data->kcd_addr_end - data->kcd_addr_begin) {
		kcdata_debug_printf("%s: insufficient buffer size: kcd_length => %d e-b=> %lld our size: %lld\n",
		    __func__, data->kcd_length, data->kcd_addr_end - data->kcd_addr_begin, max_size);
		return KERN_INSUFFICIENT_BUFFER_SIZE;
	}

	/* clear the window marker */
	cd->kcd_cd_flags &= ~KCD_CD_FLAG_IN_MARK;

	space_start = (void *) data->kcd_addr_end;
	space_ptr = space_start;
	total_uncompressed_space_remaining = (unsigned int) max_size;
	kr = kcdata_do_compress(data, (void *) cd->kcd_cd_mark_begin, total_size, space_ptr,
	    total_uncompressed_space_remaining, &wrote, KCDCF_SYNC_FLUSH);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	kcdata_debug_printf("%s: first wrote = %zu\n", __func__, wrote);
	if (wrote == 0) {
		return KERN_FAILURE;
	}
	space_ptr   += wrote;
	total_uncompressed_space_remaining  -= wrote;

	assert((size_t)(space_ptr - space_start) <= max_size);

	/* copy to the original location */
	kcdata_memcpy(data, cd->kcd_cd_mark_begin, space_start, (uint32_t) (max_size - total_uncompressed_space_remaining));

	/* rewind the end marker */
	data->kcd_addr_end = cd->kcd_cd_mark_begin + (max_size - total_uncompressed_space_remaining);

	return KERN_SUCCESS;
}

static kern_return_t
kcdata_get_compression_stats_zlib(kcdata_descriptor_t data, uint64_t *totalout, uint64_t *totalin)
{
	struct kcdata_compress_descriptor *cd = &data->kcd_comp_d;
	z_stream *zs = &cd->kcd_cd_zs;

	assert((cd->kcd_cd_flags & KCD_CD_FLAG_IN_MARK) == 0);

	*totalout = (uint64_t) zs->total_out;
	*totalin = (uint64_t) zs->total_in;

	return KERN_SUCCESS;
}

static kern_return_t
kcdata_get_compression_stats(kcdata_descriptor_t data, uint64_t *totalout, uint64_t *totalin)
{
	kern_return_t kr;

	switch (data->kcd_comp_d.kcd_cd_compression_type) {
	case KCDCT_ZLIB:
		kr = kcdata_get_compression_stats_zlib(data, totalout, totalin);
		break;
	case KCDCT_NONE:
		kr = KERN_SUCCESS;
		break;
	default:
		panic("invalid compression flag 0x%llx in kcdata_write_compression_stats", (data->kcd_comp_d.kcd_cd_compression_type));
	}

	return kr;
}

kern_return_t
kcdata_write_compression_stats(kcdata_descriptor_t data)
{
	kern_return_t kr;
	uint64_t totalout, totalin;

	kr = kcdata_get_compression_stats(data, &totalout, &totalin);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	*(uint64_t *)data->kcd_comp_d.kcd_cd_totalout_addr = totalout;
	*(uint64_t *)data->kcd_comp_d.kcd_cd_totalin_addr = totalin;

	return kr;
}

static kern_return_t
kcdata_finish_compression_zlib(kcdata_descriptor_t data)
{
	struct kcdata_compress_descriptor *cd = &data->kcd_comp_d;
	z_stream *zs = &cd->kcd_cd_zs;

	/*
	 * macOS on x86 w/ coprocessor ver. 2 and later context: Stackshot compression leaves artifacts
	 * in the panic buffer which interferes with CRC checks. The CRC is calculated here over the full
	 * buffer but only the portion with valid panic data is sent to iBoot via the SMC. When iBoot
	 * calculates the CRC to compare with the value in the header it uses a zero-filled buffer.
	 * The stackshot compression leaves non-zero bytes behind so those must be cleared prior to the CRC calculation.
	 *
	 * All other contexts: The stackshot compression artifacts are present in its panic buffer but the CRC check
	 * is done on the same buffer for the before and after calculation so there's nothing functionally
	 * broken. The same buffer cleanup is done here for completeness' sake.
	 * From rdar://problem/64381661
	 */

	void* stackshot_end = (char*)data->kcd_addr_begin + kcdata_memory_get_used_bytes(data);
	uint32_t zero_fill_size = data->kcd_length - kcdata_memory_get_used_bytes(data);
	bzero(stackshot_end, zero_fill_size);

	if (deflateEnd(zs) == Z_OK) {
		return KERN_SUCCESS;
	} else {
		return KERN_FAILURE;
	}
}

kern_return_t
kcdata_finish_compression(kcdata_descriptor_t data)
{
	kcdata_write_compression_stats(data);

	switch (data->kcd_comp_d.kcd_cd_compression_type) {
	case KCDCT_ZLIB:
		data->kcd_length += data->kcd_comp_d.kcd_cd_maxoffset;
		return kcdata_finish_compression_zlib(data);
	case KCDCT_NONE:
		return KERN_SUCCESS;
	default:
		panic("invalid compression type 0x%llxin kcdata_finish_compression", data->kcd_comp_d.kcd_cd_compression_type);
	}
}

void
kcd_finalize_compression(kcdata_descriptor_t data)
{
	if (data->kcd_flags & KCFLAG_USE_COMPRESSION) {
		data->kcd_comp_d.kcd_cd_flags |= KCD_CD_FLAG_FINALIZE;
	}
}

/*
 * Routine: kcdata_get_memory_addr
 * Desc: get memory address in the userspace memory for corpse info
 *       NOTE: The caller is responsible for zeroing the resulting memory or
 *             using other means to mark memory if it has failed populating the
 *             data in middle of operation.
 * params:  data - pointer describing the crash info allocation
 *	        type - type of data to be put. See corpse.h for defined types
 *          size - size requested. The header describes this size
 * returns: mach_vm_address_t address in user memory for copyout().
 */
kern_return_t
kcdata_get_memory_addr(kcdata_descriptor_t data, uint32_t type, uint32_t size, mach_vm_address_t * user_addr)
{
	/* record number of padding bytes as lower 4 bits of flags */
	uint64_t flags = (KCDATA_FLAGS_STRUCT_PADDING_MASK & kcdata_calc_padding(size)) | KCDATA_FLAGS_STRUCT_HAS_PADDING;
	return kcdata_get_memory_addr_with_flavor(data, type, size, flags, user_addr);
}

/*
 * Routine: kcdata_add_buffer_end
 *
 * Desc: Write buffer end marker.  This does not advance the end pointer in the
 * kcdata_descriptor_t, so it may be used conservatively before additional data
 * is added, as long as it is at least called after the last time data is added.
 *
 * params:  data - pointer describing the crash info allocation
 */

kern_return_t
kcdata_write_buffer_end(kcdata_descriptor_t data)
{
	struct kcdata_item info;
	bzero(&info, sizeof(info));
	info.type = KCDATA_TYPE_BUFFER_END;
	info.size = 0;
	return kcdata_memcpy(data, data->kcd_addr_end, &info, sizeof(info));
}

/*
 * Routine: kcdata_get_memory_addr_with_flavor
 * Desc: internal function with flags field. See documentation for kcdata_get_memory_addr for details
 */

static kern_return_t
kcdata_get_memory_addr_with_flavor(
	kcdata_descriptor_t data,
	uint32_t type,
	uint32_t size,
	uint64_t flags,
	mach_vm_address_t *user_addr)
{
	kern_return_t kr;
	struct kcdata_item info;

	uint32_t orig_size = size;
	/* make sure 16 byte aligned */
	uint32_t padding = kcdata_calc_padding(size);
	size += padding;
	uint32_t total_size  = size + sizeof(info);

	if (user_addr == NULL || data == NULL || total_size + sizeof(info) < orig_size) {
		return KERN_INVALID_ARGUMENT;
	}

	assert(((data->kcd_flags & KCFLAG_USE_COMPRESSION) && (data->kcd_comp_d.kcd_cd_flags & KCD_CD_FLAG_IN_MARK))
	    || ((data->kcd_flags & KCFLAG_USE_COMPRESSION) == 0));

	bzero(&info, sizeof(info));
	info.type  = type;
	info.size = size;
	info.flags = flags;

	/* check available memory, including trailer size for KCDATA_TYPE_BUFFER_END */
	if (total_size + sizeof(info) > data->kcd_length ||
	    data->kcd_length - (total_size + sizeof(info)) < data->kcd_addr_end - data->kcd_addr_begin) {
		return KERN_INSUFFICIENT_BUFFER_SIZE;
	}

	kr = kcdata_memcpy(data, data->kcd_addr_end, &info, sizeof(info));
	if (kr) {
		return kr;
	}

	data->kcd_addr_end += sizeof(info);

	if (padding) {
		kr = kcdata_bzero(data, data->kcd_addr_end + size - padding, padding);
		if (kr) {
			return kr;
		}
	}

	*user_addr = data->kcd_addr_end;
	data->kcd_addr_end += size;

	if (!(data->kcd_flags & KCFLAG_NO_AUTO_ENDBUFFER)) {
		/* setup the end header as well */
		return kcdata_write_buffer_end(data);
	} else {
		return KERN_SUCCESS;
	}
}

/* Routine: kcdata_get_memory_size_for_data
 * Desc: returns the amount of memory that is required to store the information
 *       in kcdata
 */
static size_t
kcdata_get_memory_size_for_data(uint32_t size)
{
	return size + kcdata_calc_padding(size) + sizeof(struct kcdata_item);
}

/*
 * Routine: kcdata_get_memory_addr_for_array
 * Desc: get memory address in the userspace memory for corpse info
 *       NOTE: The caller is responsible to zero the resulting memory or
 *             user other means to mark memory if it has failed populating the
 *             data in middle of operation.
 * params:  data - pointer describing the crash info allocation
 *          type_of_element - type of data to be put. See kern_cdata.h for defined types
 *          size_of_element - size of element. The header describes this size
 *          count - num of elements in array.
 * returns: mach_vm_address_t address in user memory for copyout().
 */

kern_return_t
kcdata_get_memory_addr_for_array(
	kcdata_descriptor_t data,
	uint32_t type_of_element,
	uint32_t size_of_element,
	uint32_t count,
	mach_vm_address_t *user_addr)
{
	/* for arrays we record the number of padding bytes as the low-order 4 bits
	 * of the type field.  KCDATA_TYPE_ARRAY_PAD{x} means x bytes of pad. */
	uint64_t flags      = type_of_element;
	flags               = (flags << 32) | count;
	uint32_t total_size = count * size_of_element;
	uint32_t pad        = kcdata_calc_padding(total_size);

	return kcdata_get_memory_addr_with_flavor(data, KCDATA_TYPE_ARRAY_PAD0 | pad, total_size, flags, user_addr);
}

/*
 * Routine: kcdata_add_container_marker
 * Desc: Add a container marker in the buffer for type and identifier.
 * params:  data - pointer describing the crash info allocation
 *          header_type - one of (KCDATA_TYPE_CONTAINER_BEGIN ,KCDATA_TYPE_CONTAINER_END)
 *          container_type - type of data to be put. See kern_cdata.h for defined types
 *          identifier - unique identifier. This is required to match nested containers.
 * returns: return value of kcdata_get_memory_addr()
 */

kern_return_t
kcdata_add_container_marker(
	kcdata_descriptor_t data,
	uint32_t header_type,
	uint32_t container_type,
	uint64_t identifier)
{
	mach_vm_address_t user_addr;
	kern_return_t kr;
	uint32_t data_size;

	assert(header_type == KCDATA_TYPE_CONTAINER_END || header_type == KCDATA_TYPE_CONTAINER_BEGIN);

	data_size = (header_type == KCDATA_TYPE_CONTAINER_BEGIN)? sizeof(uint32_t): 0;

	if (!(data->kcd_flags & KCFLAG_USE_COMPRESSION)) {
		kr = kcdata_get_memory_addr_with_flavor(data, header_type, data_size, identifier, &user_addr);
		if (kr != KERN_SUCCESS) {
			return kr;
		}

		if (data_size) {
			kr = kcdata_memcpy(data, user_addr, &container_type, data_size);
		}
	} else {
		kr = kcdata_compress_chunk_with_flags(data, header_type, &container_type, data_size, identifier);
	}

	return kr;
}

/*
 * Routine: kcdata_undo_addcontainer_begin
 * Desc: call this after adding a container begin but before adding anything else to revert.
 */
kern_return_t
kcdata_undo_add_container_begin(kcdata_descriptor_t data)
{
	/*
	 * the payload of a container begin is a single uint64_t.  It is padded out
	 * to 16 bytes.
	 */
	const mach_vm_address_t padded_payload_size = 16;
	data->kcd_addr_end -= sizeof(struct kcdata_item) + padded_payload_size;

	if (!(data->kcd_flags & KCFLAG_NO_AUTO_ENDBUFFER)) {
		/* setup the end header as well */
		return kcdata_write_buffer_end(data);
	} else {
		return KERN_SUCCESS;
	}
}

/*
 * Routine: kcdata_memcpy
 * Desc: a common function to copy data out based on either copyout or memcopy flags
 * params:  data - pointer describing the kcdata buffer
 *          dst_addr - destination address
 *          src_addr - source address
 *          size - size in bytes to copy.
 * returns: KERN_NO_ACCESS if copyout fails.
 */

kern_return_t
kcdata_memcpy(kcdata_descriptor_t data, mach_vm_address_t dst_addr, const void *src_addr, uint32_t size)
{
	if (data->kcd_flags & KCFLAG_USE_COPYOUT) {
		if (copyout(src_addr, dst_addr, size)) {
			return KERN_NO_ACCESS;
		}
	} else {
		memcpy((void *)dst_addr, src_addr, size);
	}
	return KERN_SUCCESS;
}

/*
 * Routine: kcdata_bzero
 * Desc: zero out a portion of a kcdata buffer.
 */
kern_return_t
kcdata_bzero(kcdata_descriptor_t data, mach_vm_address_t dst_addr, uint32_t size)
{
	kern_return_t kr = KERN_SUCCESS;
	if (data->kcd_flags & KCFLAG_USE_COPYOUT) {
		uint8_t zeros[16] = {};
		while (size) {
			uint32_t block_size = MIN(size, 16);
			kr = copyout(&zeros, dst_addr, block_size);
			if (kr) {
				return KERN_NO_ACCESS;
			}
			size -= block_size;
		}
		return KERN_SUCCESS;
	} else {
		bzero((void*)dst_addr, size);
		return KERN_SUCCESS;
	}
}

/*
 * Routine: kcdata_add_type_definition
 * Desc: add type definition to kcdata buffer.
 *       see feature description in documentation above.
 * params:  data - pointer describing the kcdata buffer
 *          type_id - unique type identifier for this data
 *          type_name - a string of max KCDATA_DESC_MAXLEN size for name of type
 *          elements_array - address to descriptors for each field in struct
 *          elements_count - count of how many fields are there in struct.
 * returns: return code from kcdata_get_memory_addr in case of failure.
 */

kern_return_t
kcdata_add_type_definition(
	kcdata_descriptor_t data,
	uint32_t type_id,
	char *type_name,
	struct kcdata_subtype_descriptor *elements_array_addr,
	uint32_t elements_count)
{
	kern_return_t kr = KERN_SUCCESS;
	struct kcdata_type_definition kc_type_definition;
	mach_vm_address_t user_addr;
	uint32_t total_size = sizeof(struct kcdata_type_definition);
	bzero(&kc_type_definition, sizeof(kc_type_definition));

	if (strlen(type_name) >= KCDATA_DESC_MAXLEN) {
		return KERN_INVALID_ARGUMENT;
	}
	strlcpy(&kc_type_definition.kct_name[0], type_name, KCDATA_DESC_MAXLEN);
	kc_type_definition.kct_num_elements = elements_count;
	kc_type_definition.kct_type_identifier = type_id;

	total_size += elements_count * sizeof(struct kcdata_subtype_descriptor);
	/* record number of padding bytes as lower 4 bits of flags */
	if (KERN_SUCCESS != (kr = kcdata_get_memory_addr_with_flavor(data, KCDATA_TYPE_TYPEDEFINTION, total_size,
	    kcdata_calc_padding(total_size), &user_addr))) {
		return kr;
	}
	if (KERN_SUCCESS != (kr = kcdata_memcpy(data, user_addr, (void *)&kc_type_definition, sizeof(struct kcdata_type_definition)))) {
		return kr;
	}
	user_addr += sizeof(struct kcdata_type_definition);
	if (KERN_SUCCESS != (kr = kcdata_memcpy(data, user_addr, (void *)elements_array_addr, elements_count * sizeof(struct kcdata_subtype_descriptor)))) {
		return kr;
	}
	return kr;
}

kern_return_t
kcdata_add_uint64_with_description(kcdata_descriptor_t data_desc, uint64_t data, const char * description)
{
	if (strlen(description) >= KCDATA_DESC_MAXLEN) {
		return KERN_INVALID_ARGUMENT;
	}

	kern_return_t kr = 0;
	mach_vm_address_t user_addr;
	struct _uint64_with_description_data save_data;
	const uint64_t size_req = sizeof(save_data);
	bzero(&save_data, size_req);

	strlcpy(&(save_data.desc[0]), description, sizeof(save_data.desc));
	save_data.data = data;

	if (data_desc->kcd_flags & KCFLAG_USE_COMPRESSION) {
		/* allocate space for the output */
		return kcdata_compress_chunk(data_desc, KCDATA_TYPE_UINT64_DESC, &save_data, size_req);
	}

	kr = kcdata_get_memory_addr(data_desc, KCDATA_TYPE_UINT64_DESC, size_req, &user_addr);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	if (data_desc->kcd_flags & KCFLAG_USE_COPYOUT) {
		if (copyout(&save_data, user_addr, size_req)) {
			return KERN_NO_ACCESS;
		}
	} else {
		memcpy((void *)user_addr, &save_data, size_req);
	}
	return KERN_SUCCESS;
}

kern_return_t
kcdata_add_uint32_with_description(
	kcdata_descriptor_t data_desc,
	uint32_t data,
	const char *description)
{
	assert(strlen(description) < KCDATA_DESC_MAXLEN);
	if (strlen(description) >= KCDATA_DESC_MAXLEN) {
		return KERN_INVALID_ARGUMENT;
	}
	kern_return_t kr = 0;
	mach_vm_address_t user_addr;
	struct _uint32_with_description_data save_data;
	const uint64_t size_req = sizeof(save_data);

	bzero(&save_data, size_req);
	strlcpy(&(save_data.desc[0]), description, sizeof(save_data.desc));
	save_data.data = data;

	if (data_desc->kcd_flags & KCFLAG_USE_COMPRESSION) {
		/* allocate space for the output */
		return kcdata_compress_chunk(data_desc, KCDATA_TYPE_UINT32_DESC, &save_data, size_req);
	}

	kr = kcdata_get_memory_addr(data_desc, KCDATA_TYPE_UINT32_DESC, size_req, &user_addr);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	if (data_desc->kcd_flags & KCFLAG_USE_COPYOUT) {
		if (copyout(&save_data, user_addr, size_req)) {
			return KERN_NO_ACCESS;
		}
	} else {
		memcpy((void *)user_addr, &save_data, size_req);
	}

	return KERN_SUCCESS;
}


/* end buffer management api */
