/*
 * Copyright (c) 2016-2016 Apple Inc. All rights reserved.
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

#include <vm/lz4_assembly_select.h>
#include <vm/lz4_constants.h>
#include <arm64/asm.h>

#if LZ4_ENABLE_ASSEMBLY_ENCODE_ARM64

/* void lz4_encode_2gb(uint8_t ** dst_ptr,
                       size_t dst_size,
                       const uint8_t ** src_ptr,
                       const uint8_t * src_begin,
                       size_t src_size,
                       lz4_hash_entry_t hash_table[LZ4_COMPRESS_HASH_ENTRIES],
                       int skip_final_literals)                               */

.globl _lz4_encode_2gb

#define dst_ptr             x0
#define dst_size            x1
#define src_ptr             x2
#define src_begin           x3
#define src_size            x4
#define hash_table          x5
#define skip_final_literals x6

.text
.p2align 4
_lz4_encode_2gb:

    // esteblish frame
    ARM64_STACK_PROLOG
    stp     fp, lr,    [sp, #-16]!
    mov     fp, sp

    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x27, x28, [sp, #-16]!

    // constant registers
    adr x7, L_constant
    ldr w28, [x7, #4]                        // x28 = 0x80808081 (magic number to cmopute 1/255)
    ldr w7, [x7]                             //  x7 = LZ4_COMPRESS_HASH_MULTIPLY
    mov x27, #-1                             // x27 = 0xffffffffffffffff
    dup.4s v1, w27                           //  q1 = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff}


    //  x9 - is current dst
    // x10 - dst_end - safety_margin
    ldr x9, [x0]                             // dst
    add x10, x9, x1                          // dst_end
    sub x10, x10, #LZ4_GOFAST_SAFETY_MARGIN  // dst_end - safety_margin
    cmp x10, x9                              // if dst_size < safety_margin abort
    b.lt L_done

    // x11 - is current src
    // x12 - is src_end - safety margin
    ldr x11, [x2]                            // src
    add x12, x11, x4                         // src_end
    sub x12, x12, #LZ4_GOFAST_SAFETY_MARGIN  // src_end - safety_margin
    cmp x12, x11                             // if src_size < safety_margin skip to trailing_literals
    b.lt L_trailing_literals


    // this block search for the next available match
    // set match_begin to current src (which is also where last match ended)
L_search_next_available_match:
    mov x13, x11                            // match_begin   = src
    sub x14, x13, x3                        // match_postion = match_begin - src_begin

    // compute hash value for the next 5 "quads"
    // hash distance need to be 0 < D < 0x10000

L_hash_match:
    ldr x15, [x13]                          // match_first_4_bytes
    umull x20, w7, w15                      // match_bytes * LZ4_COMPRESS_HASH_MULTIPLY
    lsr w20, w20, #LZ4_COMPRESS_HASH_SHIFT  // use LZ4_COMPRESS_HASH_BITS MSbits as index
    add x20, x5, x20, lsl #3                // hash_table_entry ptr (hash + 8*index)

    ldp w19, w22, [x20]                     //  read entry values (w19 - pos, w22 - 4 bytes at pos)
    stp w14, w15, [x20]                     // write entry values (w14 - current pos, w15 - current 4 bytes)

    add x26, x14, #1                        // next_match pos
    lsr x25, x15, #8                        // next_match_first_4_bytes
    umull x21, w7, w25                      // match_bytes * LZ4_COMPRESS_HASH_MULTIPLY
    lsr w21, w21, #LZ4_COMPRESS_HASH_SHIFT  // use LZ4_COMPRESS_HASH_BITS MSbits as index
    add x21, x5, x21, lsl #3                // hash_table_entry ptr (hash + 8*index)

    ldp w23, w24, [x21]                     //  read entry values (w23 - pos, w24 - 4 bytes at pos)
    stp w26, w25, [x21]                     // write entry values (w26 - next pos, w25 - next 4 bytes)

    cmp w15, w22
    b.ne L_try_next_match_0                 // compare the 4 bytes to see if there is a match
    sub w19, w14, w19                       // x19 - match_dist (current_pos - match_pos)
    cmp w19, #0x10000
    ccmp w19, #0, #0xf, lo
    b.eq L_try_next_match_0                 // verify the 0 < dist < 0x10000
    b L_found_valid_match

L_try_next_match_0:
    add x13, x13, #1
    add x14, x14, #1

    add x26, x14, #1                        // next_match pos
    lsr x15, x15, #16                       // next_match_first_4_bytes
    umull x20, w7, w15                      // match_bytes * LZ4_COMPRESS_HASH_MULTIPLY
    lsr w20, w20, #LZ4_COMPRESS_HASH_SHIFT  // use LZ4_COMPRESS_HASH_BITS MSbits as index
    add x20, x5, x20, lsl #3                // hash_table_entry ptr (hash + 8*index)

    ldp w21, w22, [x20]                     //  read entry values (w19 - pos, w22 - 4 bytes at pos)
    stp w26, w15, [x20]                     // write entry values (w14 - current pos, w15 - current 4 bytes)

    cmp w25, w24
    b.ne L_try_next_match_1                 // compare the 4 bytes to see if there is a match
    sub w19, w14, w23                       // x19 - match_dist (current_pos - match_pos)
    cmp w19, #0x10000
    ccmp w19, #0, #0xf, lo
    b.eq L_try_next_match_1                 // verify the 0 < dist < 0x10000
    b L_found_valid_match

L_try_next_match_1:
    add x13, x13, #1
    add x14, x14, #1

    add x26, x14, #1                        // next_match pos
    lsr x25, x15, #8                        // next_match_first_4_bytes
    umull x20, w7, w25                      // match_bytes * LZ4_COMPRESS_HASH_MULTIPLY
    lsr w20, w20, #LZ4_COMPRESS_HASH_SHIFT  // use LZ4_COMPRESS_HASH_BITS MSbits as index
    add x20, x5, x20, lsl #3                // hash_table_entry ptr (hash + 8*index)

    ldp w23, w24, [x20]                     //  read entry values (w23 - pos, w24 - 4 bytes at pos)
    stp w26, w25, [x20]                     // write entry values (w26 - next pos, w25 - next 4 bytes)

    cmp w15, w22
    b.ne L_try_next_match_2                 // compare the 4 bytes to see if there is a match
    sub w19, w14, w21                       // x19 - match_dist (current_pos - match_pos)
    cmp w19, #0x10000
    ccmp w19, #0, #0xf, lo
    b.eq L_try_next_match_2                 // verify the 0 < dist < 0x10000
    b L_found_valid_match

L_try_next_match_2:
    add x13, x13, #1
    add x14, x14, #1

    add x26, x14, #1                        // next_match pos
    lsr x15, x15, #16                       // next_match_first_4_bytes
    umull x20, w7, w15                      // match_bytes * LZ4_COMPRESS_HASH_MULTIPLY
    lsr w20, w20, #LZ4_COMPRESS_HASH_SHIFT  // use LZ4_COMPRESS_HASH_BITS MSbits as index
    add x20, x5, x20, lsl #3                // hash_table_entry ptr (hash + 8*index)

    ldp w21, w22, [x20]                     //  read entry values (w19 - pos, w22 - 4 bytes at pos)
    stp w26, w15, [x20]                     // write entry values (w14 - current pos, w15 - current 4 bytes)

    cmp w25, w24
    b.ne L_try_next_match_3                 // compare the 4 bytes to see if there is a match
    sub w19, w14, w23                       // x19 - match_dist (current_pos - match_pos)
    cmp w19, #0x10000
    ccmp w19, #0, #0xf, lo
    b.eq L_try_next_match_3                 // verify the 0 < dist < 0x10000
    b L_found_valid_match

L_try_next_match_3:
    add x13, x13, #1
    add x14, x14, #1

    cmp w15, w22
    b.ne L_try_next_matchs                 // compare the 4 bytes to see if there is a match
    sub w19, w14, w21                       // x19 - match_dist (current_pos - match_pos)
    cmp w19, #0x10000
    ccmp w19, #0, #0xf, lo
    b.eq L_try_next_matchs                 // verify the 0 < dist < 0x10000
    b L_found_valid_match

    // this block exapnd the valid match as much as possible
    // first it try to expand the match forward
    // next  it try to expand the match backword
L_found_valid_match:
    add x20, x13, #4                        // match_end = match_begin+4 (already confirmd the first 4 bytes)
    sub x21, x20, x19                       //   ref_end = match_end - dist
L_found_valid_match_expand_forward_loop:
    ldr x22, [x20], #8                      // load match_current_8_bytes (safe to load becasue of safety margin)
    ldr x23, [x21], #8                      // load   ref_current_8_bytes
    cmp x22, x23
    b.ne L_found_valid_match_expand_forward_partial
    cmp x20, x12                            // check if match_end reached src_end
    b.lo L_found_valid_match_expand_forward_loop
    b L_found_valid_match_expand_backward
L_found_valid_match_expand_forward_partial:
    sub  x20, x20, #8                       // revert match_end by 8 and compute actual match of current 8 bytes
    eor  x22, x22, x23                      // compare the bits using xor
    rbit x22, x22                           // revert the bits to use clz (the none equivalent bytes would have at least 1 set bit)
    clz  x22, x22                           // after the revrse for every equal prefix byte clz would count 8
    add  x20, x20, x22, lsr #3              // add the actual number of matching bytes is (clz result)>>3
L_found_valid_match_expand_backward:
    sub  x15, x13, x19                      // ref_begin = match_begin - dist
L_found_valid_match_expand_backward_loop:
    cmp  x13, x11                           // check if match_begin reached src (previous match end)
    ccmp x15, x3, #0xd, gt                  // check if   ref_begin reached src_begin
    b.le L_found_valid_match_emit_match
    ldrb w22, [x13, #-1]!                   // load match_current_8_bytes (safe to load becasue of safety margin)
    ldrb w23, [x15, #-1]!                   // load   ref_current_8_bytes
    cmp w22, w23
    b.eq L_found_valid_match_expand_backward_loop
    add x13, x13, #1                        // revert x13, last compare didn't match

    // this block write the match into dst
    // it write the ML token [extra L tokens] [literals] <2byte dist> [extar M tokens]
    // it update src & dst positions and progress to L_search_next_available_match
L_found_valid_match_emit_match:
    sub  x21, x20, x13                       // match_length - match_end - match_begin
    sub  x21, x21, #4                        // match_length - 4 (first 4 bytes are guaranteed)
    sub  x22, x13, x11                       // literals_length = match_begin - src    // compute
    sub  x26, x10, x9                        // dst_remaining_space = dst_end - dst
    sub  x26, x26, x22                       // dst_remaining_space -= literals_length
    subs x26, x26, #3                        // dst_remaining_space -= 2_dist_bytes + L/M_token
    b.lo L_done                              // exit if dst isn't sufficent

    and x23, x21, #0xf                       // store M 4 LSbits
    add x23, x23, x22, lsl #4                // add L 4 LSbits
    add x15, x9, #1                          // tmp_dst = dst + 1
    cmp x22, #15                             // if L >= 15 need to write more L tokens
    b.lo L_found_valid_match_copy_literals
    orr x23, x23, #0xf0                      // update L/M token to be 0xfM
    sub x24, x22, #15                        // reduce 15 from number_of_literals
    sub x26, x26, #1                         // check if there is space for the extra L token
    b.lo L_done
    cmp x24, #255                            // check if need to compute number of 255 tokens
    b.lo L_found_valid_match_skip_L_255_tokens
    umull x25, w24, w28                      // x25 - (literals_to_token * 1_DIV_255_magic_number)
    lsr   x25, x25, #39                      // x25 - number_of_255_tokens = (literals_to_token * 1_DIV_255_magic_number)>>39
    subs  x26, x26, x25                      // check if there is sufficent space for the 255_tokens
    b.lo L_done
    mov x13, #255
    umsubl x24, w25, w13, x24                // x24 - value_of_remainder_token = literals_to_token - (number_of_255_tokens*255)
L_found_valid_match_L_255_tokens_loop:
    str q1, [x15], #16                       // store 16 255 tokens into dst_tmp. safe to store because dst has safety_margin
    subs x25, x25, #16                       // check if there are any 255 token left after current 16
    b.hi L_found_valid_match_L_255_tokens_loop
    add x15, x15, x25                        // revert tmp_dst if written too many 255 tokens.
L_found_valid_match_skip_L_255_tokens:
    strb w24, [x15], #1                      // write last L token
L_found_valid_match_copy_literals:
    ldr q0, [x11], #16                       // load  current 16 literals. (safe becasue src_end has safety margin)
    str q0, [x15], #16                       // store current 16 literals. (safe becasue dst_end has safety margin)
    subs x22, x22, #16
    b.gt L_found_valid_match_copy_literals
    add x15, x15, x22                        // revert tmp_dst if written too many literals
    strh w19, [x15], #2                      // store dist bytes
    cmp x21, #15                             // if M >= 15 need to write more M tokens
    b.lo L_found_valid_match_finish_writing_match
    orr x23, x23, #0xf                       // update L/M token to be 0xLf
    sub x24, x21, #15                        // reduce 15 from match_length
    sub x26, x26, #1                         // check if there is space for the extra M token
    b.lo L_done
    cmp x24, #255                            // check if need to compute number of 255 tokens
    b.lo L_found_valid_match_skip_M_255_tokens
    umull x25, w24, w28                      // x25 - (match_length * 1_DIV_255_magic_number)
    lsr   x25, x25, #39                      // x25 - number_of_255_tokens = (match_length * 1_DIV_255_magic_number)>>39
    subs  x26, x26, x25                      // check if there is sufficent space for the 255_tokens
    b.lo L_done
    mov x13, #255
    umsubl x24, w25, w13, x24                // x24 - value_of_remainder_token = literals_to_token - (match_length*255)
L_found_valid_match_M_255_tokens_loop:
    str q1, [x15], #16                       // store 16 255 tokens into dst_tmp. safe to store because dst has safety_margin
    subs x25, x25, #16                       // check if there are any 255 token left after current 16
    b.hi L_found_valid_match_M_255_tokens_loop
    add x15, x15, x25                        // revert tmp_dst if written too many 255 tokens.
L_found_valid_match_skip_M_255_tokens:
    strb w24, [x15], #1                      // write last M token
L_found_valid_match_finish_writing_match:
    strb w23, [x9]                           // store first token of match in dst
    mov  x9, x15                             // update dst to last postion written
    mov x11, x20                             // update src to match_end (last byte that was encoded)
    cmp x11, x12                             // check if src reached src_end
    ccmp x9, x10, #9, lt                     // check if dst reached dst_end
    b.ge L_trailing_literals
    b L_search_next_available_match
    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    // attempted to hash three quad values from the end of each emited match
    // this eneded up being slower and less compression (???)
    // this block set match_begin and pos for next hash search and
    // compute the hash values for the last 3 bytes of currently emited match
    // only need to comute these hash becasue other "quads" were hashed when the original
    // data was read.

L_try_next_matchs:
    add x13, x13, #1                         // move to next match
    add x14, x14, #1                         // update next match pos
    cmp x13, x12                             // check match_begin didn't reach src_end
    b.lo L_hash_match

L_trailing_literals:
    // unless skip_final_literals is set
    // write the trailing bytes as literals
    // traliing bytes include the whole src (with the safty margin)
    // need to verify whole dst (withthe safty margin) has sufficent space

    tst x6, x6
    b.ne L_done                              // if skip_final_literals is set skip writing them

    add  x12, x12, #LZ4_GOFAST_SAFETY_MARGIN // add safety_margin
    subs x13, x12, x11                       // remaining_src
    b.eq L_done                              // finish if there are 0 trailing literals

    add x10, x10, #LZ4_GOFAST_SAFETY_MARGIN  // add safety_margin
    sub x14, x10, x9                         // remaining dst (dst_end - dst)
    sub x14, x14, #1                         // 1 byte is needed at least to write literals token
    subs x14, x14, x13                       // finish if dst can't contain all remaining literals + 1 literals token
    b.le L_done                              // (need to verify that it has room for literals tokens

    cmp  x13, #15
    b.lt L_trailing_literals_store_less_than_15_literals
    subs x14, x14, #1                        // 1-extra byte is needed for literals tokens
    b.mi L_done
    mov w15, #0xf0
    strb w15, [x9], #1                       // write literals first token (Important !!! if 255 tokens exist but dst isn't sufficent need to revert dst by 1)
    sub  x15, x13, #15
    cmp  x15, #255
    b.lo L_trailing_literals_no_255_tokens
    umull x19, w15, w28                      // x19 - (literals_to_token * 1_DIV_255_magic_number)
    lsr   x19, x19, #39                      // x19 - number_of_255_tokens = (literals_to_token * 1_DIV_255_magic_number)>>39
    subs  x14, x14, x19
    b.mi L_revert_x9_and_done
    mov x26, #255
    umsubl x15, w26, w19, x15                // x15 - value_of_remainder_token = literals_to_token - (number_of_255_tokens*255)
L_tariling_literals_write_16_255_tokens:
    str q1, [x9], #16                        // store 16 255 tokens each iteration (this is safe becasue there is space for 15 or more literals + remainder token)
    subs x19, x19, #16
    b.gt L_tariling_literals_write_16_255_tokens
    add x9, x9, x19                          // fixes dst to actual number of tokens (x19 might not be a mulitple of 16)
L_trailing_literals_no_255_tokens:
    strb w15, [x9], #1                       // store remainder_token
    lsr  x14, x13, #4                        // check if there are more than 16 literals left to be written
    tst  x14, x14
    b.eq L_trailing_literals_copy_less_than_16_literals
L_trailing_literals_copy_16_literals:
    ldr q0, [x11], #16                       // load current_16_literals
    str q0, [ x9], #16                       // *dst16++ = current_16_literals
    subs x14, x14, #1
    b.gt L_trailing_literals_copy_16_literals
    cmp x11, x12
    b.lo L_trailing_literals_copy_less_than_16_literals
    b L_done

L_trailing_literals_store_less_than_15_literals:
    lsl x14, x13, #4                         // literals_only_token is 0xL0 (where L is 4 bits)
    strb w14, [x9], #1                       // *dst++ = literals_only_token
L_trailing_literals_copy_less_than_16_literals:
    ldrb w13, [x11], #1                      // load current_literal
    strb w13, [ x9], #1                      // *dst++ = current_literal
    cmp x11, x12
    b.lo L_trailing_literals_copy_less_than_16_literals

    // this block upadte dst & src pointers and remove frame
L_done:
    str  x9, [x0]
    str x11, [x2]

    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16

    // clear frame
    ldp     fp, lr,    [sp], #16
    ARM64_STACK_EPILOG

L_revert_x9_and_done:
    sub x9, x9, #1
    b L_done

.p2align 2
L_constant:
.long LZ4_COMPRESS_HASH_MULTIPLY
.long 0x80808081

#endif

