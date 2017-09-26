/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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
#if LZ4_ENABLE_ASSEMBLY_DECODE_ARMV7

/*

  int64_t lz4_decode_asm(
    uint8_t ** dst_ptr,                     *dst_ptr points to next output byte to write
    uint8_t * dst_begin,                    points to first valid output byte we can access, dst_begin <= dst
    uint8_t * dst_end,                      "relaxed" end of output buffer (see below)
    const uint8_t ** src_ptr,               *src_ptr points to next input byte to read
    const uint8_t * src_end)                "relaxed" end of input buffer (see below)
 
  We test the position of the pointers only to ensure we don't access past src_end/dst_end + some fixed constant.
  We never read before dst_begin.
 
  Return 0 on success, -1 on failure
  On output, (*src_ptr,*dst_ptr) receives the last position in both buffers corresponding to the beginning of a LZ4 instruction.
 
*/

.globl _lz4_decode_asm

#define dst                r0   // arg0
#define dst_begin          r1   // arg1
#define dst_end            r2   // arg2
#define src                r3   // arg3

#define src_end            r4   // arg4

#define n_matches          r5
#define n_literals         r10
#define copy_src           r11   // match/literal copy source
#define copy_dst           r8   // match/literal copy destination

#define aux1               r9

#define match_distance    r6

#define match_permtable   r12
#define match_disttable   lr

#define dst_good          [sp, #0]
#define src_good          [sp, #4]

.macro establish_frame
    ldr     ip, [sp, #0]        // read src_end
    push    {r4-r7, lr}         //  Save registers
    add     r7, sp, #12         //  Establish stack frame
    push    {r8-r11}
    mov     src_end, ip   
    push    {r0, r3}                // save dst/src
    sub     sp, sp, #4+16           // 4 for 16-byte stack alignment, extra 16-bytes for local
.endm

.macro clear_frame_and_return
    add     sp, sp, #12+16          // skip r0/r3
    pop     {r8-r11}
    pop     {r4-r7,pc}
.endm

// copy_1x16 SOURCE_ADDR DESTINATION_ADDR
// Copy 16 bytes, clobber: q0
.macro copy_1x16
    vld1.8  {q0}, [$0]
    vst1.8  {q0}, [$1]
.endm

// copy_1x16_and_increment SOURCE_ADDR DESTINATION_ADDR
// Copy 16 bytes, and increment both addresses by 16, clobber: q0
.macro copy_1x16_and_increment
    vld1.8  {q0}, [$0]!
    vst1.8  {q0}, [$1]!
.endm

// copy_2x16_and_increment SOURCE_ADDR DESTINATION_ADDR
// Copy 2 times 16 bytes, and increment both addresses by 32, clobber: q0
.macro copy_2x16_and_increment
    vld1.8  {q0}, [$0]!
    vst1.8  {q0}, [$1]!
    vld1.8  {q0}, [$0]!
    vst1.8  {q0}, [$1]!
.endm

// copy_1x32_and_increment SOURCE_ADDR DESTINATION_ADDR
// Copy 32 bytes, and increment both addresses by 32, clobber: q0,q1
.macro copy_1x32_and_increment
    vld1.8  {q0,q1}, [$0]!
    vst1.8  {q0,q1}, [$1]!
.endm

// If we don't branch, src < src_end after this
.macro check_src_end
    cmp     src,src_end
    bhs     L_done                            // extremely unlikely, DONE when src >= src_end
.endm

// If we don't branch, dst < dst_end after this
.macro check_dst_end
    cmp     dst,dst_end
    bhs     L_done                            // extremely unlikely, DONE when dst >= dst_end
.endm

.text
.syntax unified
.thumb
.thumb_func _lz4_decode_asm
.p2align 1
_lz4_decode_asm:
    establish_frame
    ldr     src,[src]                         // src = *src_ptr
    ldr     dst,[dst]                         // dst = *dst_ptr

    adr     match_permtable,L_match_permtable
    adr     match_disttable,L_match_disttable

L_decode_command:
    // Keep last known good positions in both streams
    str     dst, dst_good
    str     src, src_good

    // Check limits
    check_src_end
    check_dst_end

    // Decode 1-byte command
    ldrb    aux1,[src],#1                     // read command byte LLLLMMMM
    lsr     n_literals,aux1,#4                // 0000LLLL. n_literals is now 0..15
    and     n_matches,aux1,#0xf               // 0000MMMM. n_matches is now 0..15
    add     n_matches,n_matches,#4            // n_matches is now 4..19

    // Test number of literals (do not test if n_literals==0, because branch prediction fails on it)
    cmp     n_literals,#14
    bls     L_copy_short_literal              // 96% likely: n_literals in 0..14
    // continue to decode_long_literal

    // the number of literals is encoded on more bytes, we need to decode them
L_decode_long_literal:
    check_src_end                             // required here, since we may loop an arbitrarily high number of times
    ldrb    aux1,[src],#1
    add     n_literals,n_literals,aux1
    cmp     aux1,#255
    beq     L_decode_long_literal             // extremely unlikely
    // continue to copy_long_literal

    // Copy literals, n_literals >= 15
L_copy_long_literal:
    mov     copy_src,src                      // literal copy origin
    mov     copy_dst,dst                      // literal copy destination
    add     src,src,n_literals
    add     dst,dst,n_literals
    check_src_end                             // required here, since n_literals can be arbitrarily high
    check_dst_end

    // fixed + loop
    copy_1x32_and_increment copy_src,copy_dst
L_copy_long_literal_loop:
    copy_1x32_and_increment copy_src,copy_dst
    cmp     dst,copy_dst
    bhi     L_copy_long_literal_loop          // first test occurs after 64 bytes have been copied, and is unlikely to loop back
    b       L_expand_match

    // Copy literals, n_literals <= 14: copy 16 bytes
L_copy_short_literal:
    copy_1x16 src,dst
    add     src,src,n_literals
    add     dst,dst,n_literals
    // continue to expand match

L_expand_match:

    // Decode match distance
    ldrh    match_distance,[src],#2           // 16-bit distance
    cbz     match_distance,L_fail             // distance == 0 is invalid
    sub     copy_src,dst,match_distance       // copy_src is the match copy source
    cmp     copy_src,dst_begin
    blo     L_fail                            // copy_src < dst_begin: FAIL
    mov     copy_dst,dst                      // copy_dst is the match copy destination
    add     dst,dst,n_matches                 // dst is updated to be the byte after the match; n_matches <= 19 here

    // Do we need to decode a long match?
    cmp     n_matches,#19
    beq     L_decode_long_match               // unlikely, n_matches >= 19 encoded on more bytes
    cmp     n_matches,#16
    bhi     L_long_match                      // unlikely, n_matches == 17 or 18
    // continue to short match (most probable case)

    // Copy match, n_matches <= 16
L_short_match:
    cmp     match_distance,#15
    bls     L_copy_short_match_small_distance

    // Copy match, n_matches <= 16, match_distance >= 16: copy 16 bytes
    copy_1x16 copy_src,copy_dst
    b       L_decode_command

L_fail:
mov     aux1,#-1                          // FAIL
b       L_exit

L_done:
mov     aux1,#0                           // OK
// continue to L_exit

L_exit:

ldr     dst,[sp, #20]                     // get back src_ptr,dst_ptr from stack
ldr     src,[sp, #24]                     // get back src_ptr,dst_ptr from stack
ldr     ip, src_good
ldr     lr, dst_good
str     ip,[src]                    // *src_ptr = src_good
str     lr,[dst]                    // *dst_ptr = dst_good

mov     r0,aux1                           // x0 = return value
clear_frame_and_return

    // Copy match, n_matches <= 16, match_distance < 16:
    // load shuffle table, and permute to replicate the pattern on 16 bytes
L_copy_short_match_small_distance:
    vld1.8  {q0},[copy_src]
    add     aux1,match_permtable,match_distance,lsl #5   // index in table
    vld1.8  {q1},[aux1]                       // load only permutation for the low 16 bytes
    vtbl.8  d4, {q0}, d2                      // low 16 bytes of pattern
    vtbl.8  d5, {q0}, d3                      // low 16 bytes of pattern
    vst1.8  {q2},[copy_dst]
    b       L_decode_command

    // n_matches == 19: the number of matches in encoded on more bytes, we need to decode them
L_decode_long_match:
    check_src_end                             // required here, since we may loop an arbitrarily high number of times
    ldrb    aux1,[src],#1
    add     dst,dst,aux1
    cmp     aux1,#255
    beq     L_decode_long_match               // very unlikely
    check_dst_end                             // required here, since dst was incremented by a arbitrarily high value
    // continue to long_match

    // n_matches > 16
L_long_match:
    cmp     match_distance,#31
    bhi     L_copy_long_match_32
    cmp     match_distance,#15
    bhi     L_copy_long_match_16

    // Copy match, n_matches >= 16, match_distance < 16:
    // load shuffle table, and permute to replicate the pattern on 32 bytes
L_copy_long_match_small_distance:
    vld1.8  {q1}, [copy_src]                  // 16 pattern bytes
    add     aux1,match_permtable,match_distance,lsl #5   // index in table
    vld1.8  {q2-q3}, [aux1]                   // load 32-byte permutation

    vtbl.8  d4, {q1}, d4                      // low 16 bytes of pattern
    vtbl.8  d5, {q1}, d5                      // low 16 bytes of pattern
    vtbl.8  d6, {q1}, d6                      // low 16 bytes of pattern
    vtbl.8  d7, {q1}, d7                      // low 16 bytes of pattern

    ldrb    aux1,[match_disttable,match_distance]  // valid pattern length in aux1
    // fixed
    vst1.8  {q2-q3},[copy_dst]
    add     copy_dst,copy_dst,aux1
L_copy_long_match_small_distance_loop:
    // loop
    vst1.8  {q2-q3},[copy_dst]
    add     copy_dst,copy_dst,aux1
    vst1.8  {q2-q3},[copy_dst]
    add     copy_dst,copy_dst,aux1
    cmp     dst,copy_dst
    bhi     L_copy_long_match_small_distance_loop
    b       L_decode_command

    // Copy match, n_matches >= 16, match_distance >= 32
L_copy_long_match_32:
    // fixed + loop
    copy_1x16_and_increment copy_src,copy_dst
L_copy_long_match_32_loop:
    copy_1x32_and_increment copy_src,copy_dst
    cmp     dst,copy_dst
    bhi     L_copy_long_match_32_loop
    b       L_decode_command

    // Copy match, n_matches >= 16, match_distance >= 16
L_copy_long_match_16:
    // fixed + loop
    copy_1x16_and_increment copy_src,copy_dst
L_copy_long_match_16_loop:
    copy_2x16_and_increment copy_src,copy_dst
    cmp     dst,copy_dst
    bhi     L_copy_long_match_16_loop
    b       L_decode_command


// permutation tables for short distance matches, 32 byte result, for match_distance = 0 to 15
// value(d)[i] = i%d for i = 0..31
.p2align 6
L_match_permtable:
.byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  // 0
.byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  // 1
.byte 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,    0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1  // 2
.byte 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0,    1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1  // 3
.byte 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3,    0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3  // 4
.byte 0, 1, 2, 3, 4, 0, 1, 2, 3, 4, 0, 1, 2, 3, 4, 0,    1, 2, 3, 4, 0, 1, 2, 3, 4, 0, 1, 2, 3, 4, 0, 1  // 5
.byte 0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 5, 0, 1, 2, 3,    4, 5, 0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 5, 0, 1  // 6
.byte 0, 1, 2, 3, 4, 5, 6, 0, 1, 2, 3, 4, 5, 6, 0, 1,    2, 3, 4, 5, 6, 0, 1, 2, 3, 4, 5, 6, 0, 1, 2, 3  // 7
.byte 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7,    0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7  // 8
.byte 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 1, 2, 3, 4, 5, 6,    7, 8, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 1, 2, 3, 4  // 9
.byte 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5,    6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1  // 10
.byte 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10, 0, 1, 2, 3, 4,    5, 6, 7, 8, 9,10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9  // 11
.byte 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11, 0, 1, 2, 3,    4, 5, 6, 7, 8, 9,10,11, 0, 1, 2, 3, 4, 5, 6, 7  // 12
.byte 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12, 0, 1, 2,    3, 4, 5, 6, 7, 8, 9,10,11,12, 0, 1, 2, 3, 4, 5  // 13
.byte 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13, 0, 1,    2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13, 0, 1, 2, 3  // 14
.byte 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14, 0,    1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14, 0, 1  // 15

// valid repeating pattern size, for each match_distance = 0 to 15
// value(d) = 32 - (32%d), is the largest a multiple of d <= 32
.p2align 6
L_match_disttable:
.byte 32,32,32,30  //  0 ..  3
.byte 16,30,30,28  //  4 ..  7
.byte 16,27,30,22  //  8 .. 11
.byte 24,26,28,30  // 12 .. 15

#endif // LZ4_ENABLE_ASSEMBLY_DECODE_ARMV7
