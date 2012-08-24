/*
 *  ccdigest.h
 *  corecrypto
 *
 *  Created by Michael Brouwer on 11/30/10.
 *  Copyright 2010,2011 Apple Inc. All rights reserved.
 *
 */

#ifndef _CORECRYPTO_CCDIGEST_H_
#define _CORECRYPTO_CCDIGEST_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccn.h>

/* To malloc a digest context for a given di, use malloc(ccdigest_di_size(di))
   and assign the result to a pointer to a struct ccdigest_ctx. */
struct ccdigest_ctx {
    union {
        uint8_t u8;
        uint32_t u32;
        uint64_t u64;
        cc_unit ccn;
    } state;
} __attribute((aligned(8)));

typedef union {
    struct ccdigest_ctx *hdr;
} ccdigest_ctx_t __attribute__((transparent_union));

struct ccdigest_state {
    union {
        uint8_t u8;
        uint32_t u32;
        uint64_t u64;
        cc_unit ccn;
    } state;
} __attribute((aligned(8)));

typedef union {
    struct ccdigest_state *hdr;
    struct ccdigest_ctx *_ctx;
    ccdigest_ctx_t _ctxt;
} ccdigest_state_t __attribute__((transparent_union));

struct ccdigest_info {
    unsigned long output_size;
    unsigned long state_size;
    unsigned long block_size;
    unsigned long oid_size;
    unsigned char *oid;
    const void *initial_state;
    void(*compress)(ccdigest_state_t state, unsigned long nblocks,
                    const void *data);
    void(*final)(const struct ccdigest_info *di, ccdigest_ctx_t ctx,
                 unsigned char *digest);
};

/* Return sizeof a ccdigest_ctx for a given size_t _state_size_ and
   size_t _block_size_. */
#define ccdigest_ctx_size(_state_size_, _block_size_)  ((_state_size_) + sizeof(uint64_t) + (_block_size_) + sizeof(unsigned int))
/* Return sizeof a ccdigest_ctx for a given struct ccdigest_info *_di_. */
#define ccdigest_di_size(_di_)  (ccdigest_ctx_size((_di_)->state_size, (_di_)->block_size))

/* Declare a ccdigest_ctx for a given size_t _state_size_ and
   size_t _block_size_, named _name_.  Can be used in structs or on the
   stack. */
#define ccdigest_ctx_decl(_state_size_, _block_size_, _name_)  cc_ctx_decl(struct ccdigest_ctx, ccdigest_ctx_size(_state_size_, _block_size_), _name_)
#define ccdigest_ctx_clear(_state_size_, _block_size_, _name_) cc_ctx_clear(struct ccdigest_ctx, ccdigest_ctx_size(_state_size_, _block_size_), _name_)
/* Declare a ccdigest_ctx for a given size_t _state_size_ and
   size_t _block_size_, named _name_.  Can be used on the stack. */
#define ccdigest_di_decl(_di_, _name_)  cc_ctx_decl(struct ccdigest_ctx, ccdigest_di_size(_di_), _name_)
#define ccdigest_di_clear(_di_, _name_) cc_ctx_clear(struct ccdigest_ctx, ccdigest_di_size(_di_), _name_)

/* Digest context field accessors.  Consider the implementation private. */
#define ccdigest_state(_di_, _ctx_)      ((ccdigest_state_t)(_ctx_))
#define ccdigest_state_u8(_di_, _ctx_)   (&((ccdigest_ctx_t)(_ctx_)).hdr->state.u8)
#define ccdigest_state_u32(_di_, _ctx_)  (&((ccdigest_ctx_t)(_ctx_)).hdr->state.u32)
#define ccdigest_state_u64(_di_, _ctx_)  (&((ccdigest_ctx_t)(_ctx_)).hdr->state.u64)
#define ccdigest_state_ccn(_di_, _ctx_)  (&((ccdigest_ctx_t)(_ctx_)).hdr->state.ccn)
#define ccdigest_nbits(_di_, _ctx_)      (((uint64_t *)(&((ccdigest_ctx_t)(_ctx_)).hdr->state.u8 + (_di_)->state_size))[0])
#define ccdigest_data(_di_, _ctx_)       (&((ccdigest_ctx_t)(_ctx_)).hdr->state.u8 + (_di_)->state_size + sizeof(uint64_t))
#define ccdigest_num(_di_, _ctx_)        (((unsigned int *)(&((ccdigest_ctx_t)(_ctx_)).hdr->state.u8 + (_di_)->state_size + sizeof(uint64_t) + (_di_)->block_size))[0])

/* Digest state field accessors.  Consider the implementation private. */
#define ccdigest_u8(_state_)             (&((ccdigest_state_t)(_state_)).hdr->state.u8)
#define ccdigest_u32(_state_)            (&((ccdigest_state_t)(_state_)).hdr->state.u32)
#define ccdigest_u64(_state_)            (&((ccdigest_state_t)(_state_)).hdr->state.u64)
#define ccdigest_ccn(_state_)            (&((ccdigest_state_t)(_state_)).hdr->state.ccn)

/* We could just use memcpy instead of this special macro, but this allows us
   to use the optimized ccn_set() assembly routine if we have one, which for
   32 bit arm is about 200% quicker than generic memcpy(). */
#if CCN_SET_ASM && CCN_UNIT_SIZE <= 4
#define ccdigest_copy_state(_di_, _dst_, _src_) ccn_set((_di_)->state_size / CCN_UNIT_SIZE, _dst_, _src_)
#else
#define ccdigest_copy_state(_di_, _dst_, _src_) CC_MEMCPY(_dst_, _src_, (_di_)->state_size)
#endif

void ccdigest_init(const struct ccdigest_info *di, ccdigest_ctx_t ctx);
void ccdigest_update(const struct ccdigest_info *di, ccdigest_ctx_t ctx,
                     unsigned long len, const void *data);

CC_INLINE
void ccdigest_final(const struct ccdigest_info *di, ccdigest_ctx_t ctx, unsigned char *digest)
{
    di->final(di,ctx,digest);
}

void ccdigest(const struct ccdigest_info *di, unsigned long len,
              const void *data, void *digest);

/* test functions */
int ccdigest_test(const struct ccdigest_info *di, unsigned long len,
              const void *data, const void *digest);

int ccdigest_test_chunk(const struct ccdigest_info *di, unsigned long len,
                        const void *data, const void *digest, unsigned long chunk);

struct ccdigest_vector {
    unsigned long len;
    const void *message;
    const void *digest;
};

int ccdigest_test_vector(const struct ccdigest_info *di, const struct ccdigest_vector *v);
int ccdigest_test_chunk_vector(const struct ccdigest_info *di, const struct ccdigest_vector *v, unsigned long chunk);

#endif /* _CORECRYPTO_CCDIGEST_H_ */
