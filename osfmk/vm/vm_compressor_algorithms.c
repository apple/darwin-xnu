/*
 * Copyright (c) 2010-2016 Apple Inc. All rights reserved.
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
/* This module implements a hybrid/adaptive compression scheme, using WKdm where
 * profitable and, currently, an LZ4 variant elsewhere.
 * (Created 2016, Derek Kumar)
 */
#include "lz4.h"
#include "WKdm_new.h"
#include <vm/vm_compressor_algorithms.h>
#include <vm/vm_compressor.h>

#define MZV_MAGIC (17185)
#define LZ4_SCRATCH_ALIGN (64)
#define WKC_SCRATCH_ALIGN (64)

#define LZ4_SCRATCH_ALIGN (64)
#define WKC_SCRATCH_ALIGN (64)

#define memcpy_T_NT memcpy
#define memcpy_NT_T memcpy

typedef union {
	uint8_t lz4state[lz4_encode_scratch_size]__attribute((aligned(LZ4_SCRATCH_ALIGN)));
	uint8_t wkscratch[0] __attribute((aligned(WKC_SCRATCH_ALIGN))); // TODO
} compressor_encode_scratch_t;

typedef union {
	uint8_t lz4decodestate[lz4_encode_scratch_size]__attribute((aligned(64)));
	uint8_t wkdecompscratch[0] __attribute((aligned(64)));
} compressor_decode_scratch_t;

typedef struct {
	uint16_t lz4_selection_run;
	uint16_t lz4_run_length;
	uint16_t lz4_preselects;
	uint32_t lz4_total_preselects;
	uint16_t lz4_failure_skips;
	uint32_t lz4_total_failure_skips;
	uint16_t lz4_failure_run_length;
	uint16_t lz4_total_unprofitables;
	uint32_t lz4_total_negatives;
	uint32_t lz4_total_failures;
} compressor_state_t;

compressor_tuneables_t vmctune = {
	.lz4_threshold = 2048,
	.wkdm_reeval_threshold = 1536,
	.lz4_max_failure_skips = 0,
	.lz4_max_failure_run_length = ~0U,
	.lz4_max_preselects = 0,
	.lz4_run_preselection_threshold = ~0U,
	.lz4_run_continue_bytes = 0,
	.lz4_profitable_bytes = 0,
};

compressor_state_t vmcstate = {
	.lz4_selection_run = 0,
	.lz4_run_length = 0,
	.lz4_preselects = 0,
	.lz4_total_preselects = 0,
	.lz4_failure_skips = 0,
	.lz4_total_failure_skips = 0,
	.lz4_failure_run_length = 0,
	.lz4_total_unprofitables = 0,
	.lz4_total_negatives = 0,
};

compressor_stats_t compressor_stats;

enum compressor_preselect_t {
	CPRESELLZ4 = 0,
	CSKIPLZ4 = 1,
	CPRESELWK = 2,
};

vm_compressor_mode_t vm_compressor_current_codec = VM_COMPRESSOR_DEFAULT_CODEC;

boolean_t verbose = FALSE;

#if DEVELOPMENT || DEBUG
#define VERBOSE(x...)							\
	do {								\
		if (verbose)						\
			printf(x);					\
	} while(0)
#define VM_COMPRESSOR_STAT(x...)					\
	do {								\
		(x);							\
	} while(0)
//TODO make atomic where needed, decompression paths
#define VM_DECOMPRESSOR_STAT(x...)					\
	do {								\
		(x);							\
	} while(0)
#else
#define VERBOSE(x...)							\
	do {								\
	}while (0)
#define VM_COMPRESSOR_STAT(x...)					\
	do {								\
	}while (0)
#define VM_DECOMPRESSOR_STAT(x...)					\
	do {								\
	}while (0)
#endif

static inline enum compressor_preselect_t compressor_preselect(void) {
	if (vmcstate.lz4_failure_skips >= vmctune.lz4_max_failure_skips) {
		vmcstate.lz4_failure_skips = 0;
		vmcstate.lz4_failure_run_length = 0;
	}

	if (vmcstate.lz4_failure_run_length >= vmctune.lz4_max_failure_run_length) {
		vmcstate.lz4_failure_skips++;
		vmcstate.lz4_total_failure_skips++;
		return CSKIPLZ4;
	}

	if (vmcstate.lz4_preselects >= vmctune.lz4_max_preselects) {
		vmcstate.lz4_preselects = 0;
		return CPRESELWK;
	}

	if (vmcstate.lz4_run_length >= vmctune.lz4_run_preselection_threshold) {
		vmcstate.lz4_preselects++;
		vmcstate.lz4_total_preselects++;
		return CPRESELLZ4;
	}
	return CPRESELWK;
}

static inline void compressor_selector_update(int lz4sz, int didwk, int wksz) {
	VM_COMPRESSOR_STAT(compressor_stats.lz4_compressions++);

	if (lz4sz == 0) {
		VM_COMPRESSOR_STAT(compressor_stats.lz4_compressed_bytes+=PAGE_SIZE);
		VM_COMPRESSOR_STAT(compressor_stats.lz4_compression_failures++);
		vmcstate.lz4_failure_run_length++;
		VM_COMPRESSOR_STAT(vmcstate.lz4_total_failures++);
		vmcstate.lz4_run_length = 0;
	} else {
		vmcstate.lz4_failure_run_length = 0;

		VM_COMPRESSOR_STAT(compressor_stats.lz4_compressed_bytes+=lz4sz);

		if (lz4sz <= vmctune.wkdm_reeval_threshold) {
			vmcstate.lz4_run_length = 0;
		} else {
			if (!didwk) {
				vmcstate.lz4_run_length++;
			}
		}

		if (didwk) {
			if (__probable(wksz > lz4sz)) {
				uint32_t lz4delta = wksz - lz4sz;
				VM_COMPRESSOR_STAT(compressor_stats.lz4_wk_compression_delta+=lz4delta);
				if (lz4delta >= vmctune.lz4_run_continue_bytes) {
					vmcstate.lz4_run_length++;
				} else if (lz4delta <= vmctune.lz4_profitable_bytes) {
					vmcstate.lz4_failure_run_length++;
					VM_COMPRESSOR_STAT(vmcstate.lz4_total_unprofitables++);
					vmcstate.lz4_run_length = 0;
				} else {
					vmcstate.lz4_run_length = 0;
				}
			} else {
				VM_COMPRESSOR_STAT(compressor_stats.lz4_wk_compression_negative_delta+=(lz4sz-wksz));
				vmcstate.lz4_failure_run_length++;
				VM_COMPRESSOR_STAT(vmcstate.lz4_total_negatives++);
				vmcstate.lz4_run_length = 0;
			}
		}
	}
}

//todo fix clang diagnostic
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wincompatible-pointer-types"

static inline void WKdmD(WK_word* src_buf, WK_word* dest_buf, WK_word* scratch, unsigned int bytes) {
#if DEVELOPMENT || DEBUG
	uint32_t *inw = (uint32_t *) src_buf;
	if (*inw != MZV_MAGIC) {
		if ((*inw | *(inw+1) | *(inw+2)) & 0xFFFF0000) {
			panic("WKdmDecompress: invalid header 0x%x 0x%x 0x%x\n", *inw, *(inw +1), *(inw+2));
		}
	}
#endif /* DEVELOPMENT || DEBUG */
	WKdm_decompress_new(src_buf, dest_buf, scratch, bytes);
}

static inline int WKdmC(WK_word* src_buf, WK_word* dest_buf, WK_word* scratch, unsigned int limit) {
	return WKdm_compress_new(src_buf, dest_buf, scratch, limit);
}


int metacompressor(const uint8_t *in, uint8_t *cdst, int32_t outbufsz, uint16_t *codec, void *cscratchin) {
	int sz = -1;
	int dowk = FALSE, dolz4 = FALSE, skiplz4 = FALSE;
	int insize = PAGE_SIZE;
	compressor_encode_scratch_t *cscratch = cscratchin;

	if (vm_compressor_current_codec == CMODE_WK) {
		dowk = TRUE;
	} else if (vm_compressor_current_codec == CMODE_LZ4) {
		dolz4 = TRUE;
	} else if (vm_compressor_current_codec == CMODE_HYB) {
		enum compressor_preselect_t presel = compressor_preselect();
		if (presel == CPRESELLZ4) {
			dolz4 = TRUE;
			goto lz4compress;
		} else if (presel == CSKIPLZ4) {
			dowk = TRUE;
			skiplz4 = TRUE;
		} else {
			assert(presel == CPRESELWK);
			dowk = TRUE;
		}
	}

	if (dowk) {
		*codec = CCWK;
		sz = WKdmC(in, cdst, &cscratch->wkscratch[0], outbufsz);
		VM_COMPRESSOR_STAT(compressor_stats.wk_compressions++);

		VERBOSE("WKDm Compress: %d\n", sz);
		if (sz == -1) {
			VM_COMPRESSOR_STAT(compressor_stats.wk_compressed_bytes_total+=PAGE_SIZE);
			VM_COMPRESSOR_STAT(compressor_stats.wk_compression_failures++);

			if (vm_compressor_current_codec == CMODE_HYB) {
				goto lz4eval;
			}
			goto cexit;
		} else if (sz == 0) {
			VM_COMPRESSOR_STAT(compressor_stats.wk_sv_compressions++);
			VM_COMPRESSOR_STAT(compressor_stats.wk_compressed_bytes_total+=8);
		} else {
			VM_COMPRESSOR_STAT(compressor_stats.wk_compressed_bytes_total+=sz);
		}
	}
lz4eval:
	if (vm_compressor_current_codec == CMODE_HYB) {
		if (((sz == -1) || (sz >= vmctune.lz4_threshold)) && (skiplz4 == FALSE)) {
			dolz4 = TRUE;
		} else {
			__unused int wkc = (sz == -1) ? PAGE_SIZE : sz;
			VM_COMPRESSOR_STAT(compressor_stats.wk_compressions_exclusive++);
			VM_COMPRESSOR_STAT(compressor_stats.wk_compressed_bytes_exclusive+=wkc);
			goto cexit;
		}
	}

lz4compress:

	if (dolz4) {
		if (sz == -1) {
			sz = PAGE_SIZE;
		}
		int wksz = sz;
		*codec = CCLZ4;

		sz = (int) lz4raw_encode_buffer(cdst, outbufsz, in, insize, &cscratch->lz4state[0]);

		VERBOSE("LZ4 Compress: %d\n", sz);
		compressor_selector_update(sz, dowk, wksz);
		if (sz == 0) {
			sz = -1;
			goto cexit;
		}
	}
cexit:
	return sz;
}

void metadecompressor(const uint8_t *source, uint8_t *dest, uint32_t csize, uint16_t ccodec, void *compressor_dscratchin) {
	int dolz4 = (ccodec == CCLZ4);
	int rval;
	compressor_decode_scratch_t *compressor_dscratch = compressor_dscratchin;
	
	if (dolz4) {
		rval = (int)lz4raw_decode_buffer(dest, PAGE_SIZE, source, csize, &compressor_dscratch->lz4decodestate[0]);
		VM_DECOMPRESSOR_STAT(compressor_stats.lz4_decompressions+=1);
		VM_DECOMPRESSOR_STAT(compressor_stats.lz4_decompressed_bytes+=csize);

		assertf(rval == PAGE_SIZE, "LZ4 decode: size != pgsize %d", rval);

	} else {
		assert(ccodec == CCWK);
		WKdmD(source, dest, &compressor_dscratch->wkdecompscratch[0], csize);
		VM_DECOMPRESSOR_STAT(compressor_stats.wk_decompressions+=1);
		VM_DECOMPRESSOR_STAT(compressor_stats.wk_decompressed_bytes+=csize);
	}
}
#pragma clang diagnostic pop

uint32_t vm_compressor_get_encode_scratch_size(void) {
	if (vm_compressor_current_codec != VM_COMPRESSOR_DEFAULT_CODEC) {
		return MAX(sizeof(compressor_encode_scratch_t), WKdm_SCRATCH_BUF_SIZE_INTERNAL);
	} else {
		return WKdm_SCRATCH_BUF_SIZE_INTERNAL;
	}
}

uint32_t vm_compressor_get_decode_scratch_size(void) {
	if (vm_compressor_current_codec != VM_COMPRESSOR_DEFAULT_CODEC) {
		return MAX(sizeof(compressor_decode_scratch_t), WKdm_SCRATCH_BUF_SIZE_INTERNAL);
	} else {
		return WKdm_SCRATCH_BUF_SIZE_INTERNAL;
	}
}


int vm_compressor_algorithm(void) {
	return vm_compressor_current_codec;
}

void vm_compressor_algorithm_init(void) {
	vm_compressor_mode_t new_codec = VM_COMPRESSOR_DEFAULT_CODEC;


	PE_parse_boot_argn("vm_compressor_codec", &new_codec, sizeof(new_codec));
	assertf(((new_codec == VM_COMPRESSOR_DEFAULT_CODEC) || (new_codec == CMODE_WK) ||
		(new_codec == CMODE_LZ4) || (new_codec = CMODE_HYB)),
	    "Invalid VM compression codec: %u", new_codec);


	if (PE_parse_boot_argn("-vm_compressor_wk", &new_codec, sizeof(new_codec))) {
		new_codec = VM_COMPRESSOR_DEFAULT_CODEC;
	} else if (PE_parse_boot_argn("-vm_compressor_hybrid", &new_codec, sizeof(new_codec))) {
		new_codec = CMODE_HYB;
	}

}
//TODO check open-sourceability of lz4
