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
#if LZ4_ENABLE_ASSEMBLY_ENCODE_ARMV7

/* void lz4_encode_2gb(uint8_t ** dst_ptr,
                       size_t dst_size,
                       const uint8_t ** src_ptr,
                       const uint8_t * src_begin,
                       size_t src_size,
                       lz4_hash_entry_t hash_table[LZ4_COMPRESS_HASH_ENTRIES],
                       int skip_final_literals)                               */

.globl _lz4_encode_2gb
.syntax unified

#define dst_ptr r0
#define dst_end r1
#define src_ptr r2
#define src_beg r3
#define src_end r4
#define table   r5
#define mch_ptr r6
#define mch_dis r8
#define mch_len r9
#define mch_ref r10

#define margin  128

.macro establish_frame
  push   {r4-r7, lr}
  add     r7,       sp, #12
  push   {r8-r11}
  ldrd    r4, r5,  [sp, #36]
  push   {r0, r2}
  ldr     dst_ptr, [r0]
  ldr     src_ptr, [r2]
  subs    r1,       r1,  margin // subtract safety margin from dst_size
  bls     L_done
  add     dst_end,  dst_ptr, r1 // dst end - margin
  sub     r4,       r4,  margin // subtract safety margin from src_size (src_size < margin is detected by check on mch_ptr in match_candidate_loop).
  add     src_end,  src_ptr, r4 // src end - margin.
  vmov.i8 q1,       #255        // vector of all 1s used to emit
.endm

.macro clear_frame_and_return
  pop    {r1, r3}
  str     dst_ptr, [r1]
  str     src_ptr, [r3]
  pop    {r8-r11}
  pop    {r4-r7, pc}
.endm

.p2align 4
_lz4_encode_2gb:
  establish_frame
L_next_match:
  //  Start searching for the next match, starting at the end of the last one.
  //  [We begin with mch_ptr = src_ptr - 1 because we pre-increment mch_ptr
  //  within the search loop itself].  Load the hash magic number in lr, and
  //  zero out mch_len (when we find a match, its length will initially be
  //  four, but we actually work with the match length minus four at all times).
  ldr     lr,       L_hash
  sub     mch_ptr,  src_ptr, #1

L_match_candidate_loop:
  //  If mch_ptr >= src_end, we are near the end of the source buffer (remember
  //  that we subtracted margin from src_end, so we are *not* actually past the
  //  end just yet).
  cmp     mch_ptr,  src_end
  bhs     L_trailing_literal

  //  Load the four-byte word starting at mch_ptr, and get the address of the
  //  corresponding row of the hash table.
  ldr     r9,      [mch_ptr, #1]!
  sub     r8,       mch_ptr, src_beg
  mul     r12,      r9, lr
  mvn     r10,      #0x7
  and     r12,      r10, r12, lsr #17 // byte offset of table entry.

  //  Load offset and word from hash table row, then update with the new offset
  //  and word that we just computed.
  ldrd    r10,r11, [table, r12]
  strd    r8, r9,  [table, r12]

  //  At this point, we only know that the hashes of the words match; check to
  //  see if the words themselves match.  If not, move on to the next candidate.
  cmp     r9,       r11
  bne     L_match_candidate_loop

  //  It's not enough for the words to match; the match distance must also be
  //  in the representable range (i.e. less than 0x10000).
  sub     mch_dis,  r8, r10
  add     mch_ref,  src_beg, r10
  cmp     mch_dis,  #0x10000
  bhs     L_match_candidate_loop

  //  We have found a match; registers at this point are as follows:
  //
  //   register   symbolic name   meaning
  //      r0         dst_ptr      pointer into destination buffer where the
  //                              match information will be stored.
  //      r1         dst_end      pointer to the end of the destination buffer,
  //                              less margin.
  //      r2         src_ptr      pointer to the byte after the last match that
  //                              we found, or to the point from which we
  //                              started searching if this is the first match.
  //      r3         src_beg      pointer to the actual start of the buffer.
  //      r4         src_end      pointer to the end of the source buffer, less
  //                              margin.
  //      r5         table        address of hash table.
  //      r6         mch_ptr      pointer to match.
  //      r8         mch_dis      match distance ("D")
  //      r9         mch_len      length of match less four ("M")
  //      r10        mch_ref      pointer to match reference.
  //      r11        -
  //      r12        -
  //      lr         -
  //
  //  Attempt to grow the match backwards (typically we only grow backwards by
  //  a byte or two, if at all, so we use a byte-by-byte scan).
  eor     mch_len,  mch_len
0:cmp     mch_ref,  src_beg
  cmpne   mch_ptr,  src_ptr
  beq     1f
  ldrb    r11,     [mch_ref, #-1]
  ldrb    r12,     [mch_ptr, #-1]
  cmp     r11,      r12
  bne     1f
  sub     mch_ref,  #1
  sub     mch_ptr,  #1
  add     mch_len,  #1
  b       0b

  //  Now that we have the start of the match, we can compute the literal
  //  length.  Then advance the mch and ref pointers to the end of the match
  //  and its reference.  Because mch_len is the real match length minus four,
  //  we actually advance to four before the end of the match, but our loop
  //  to grow the matches uses pre-incremented loads with writeback, so this
  //  works out correctly.
#define lit_len lr
1:sub     lit_len,  mch_ptr, src_ptr
  add     mch_ptr,  mch_len
  add     mch_ref,  mch_len

  //  Now attempt to grow the match forwards.  This is much more common, and
  //  there is a safety margin at the end of the buffer, so we grow forwards
  //  in four-byte chunks.
0:ldr     r11,     [mch_ptr, #4]!
  ldr     r12,     [mch_ref, #4]!
  eors    r11,      r12
  bne     1f
  add     mch_len,  #4
  cmp     mch_ptr,  src_end
  blo     0b
  b       L_emit_match
  //  At least one of the bytes in the last comparison did not match.  Identify
  //  which byte had the mismatch and compute the final length (less four).
1:rev     r11,      r11
  clz     r11,      r11
  add     mch_len,  r11, lsr #3

L_emit_match:
  //  Time to emit what we've found!
  //
  //   register   symbolic name   meaning
  //      r0         dst_ptr      pointer into destination buffer where the
  //                              match information will be stored.
  //      r1         dst_end      pointer to the end of the destination buffer,
  //                              less margin.
  //      r2         src_ptr      pointer to the byte after the last match that
  //                              we found, or to the point from which we
  //                              started searching if this is the first match.
  //      r3         src_beg      pointer to the actual start of the buffer.
  //      r4         src_end      pointer to the end of the source buffer, less
  //                              margin.
  //      r5         table        address of hash table.
  //      r6         -
  //      r8         mch_dis      match distance ("D")
  //      r9         mch_len      length of match ("M")
  //      r10        -
  //      r11        -
  //      r12        -
  //      lr         lit_len      literal length ("L")
  //      q1                      vector of all ones
  //
  //  Synthesize control byte under the assumption that L and M are both less
  //  than 15, jumping out of the fast path if one of them is not.
  cmp     lit_len,  #15
  orr     r10,      mch_len, lit_len, lsl #4
  cmplo   mch_len,  #15
  bhs     L_emit_careful
  //  L and M are both less than 15, which means (a) we use the most compact
  //  encoding for the match and (b) we do not need to do a bounds check on
  //  the destination buffer before writing, only before continuing our search.
  //  Store the command byte.
  strb    r10,     [dst_ptr], #1
  //  Copy literal.
  vld1.8  q0,      [src_ptr]
  add     src_ptr,  lit_len
  vst1.8  q0,      [dst_ptr]
  add     dst_ptr,  lit_len
  //  Restore "true" match length before updating src_ptr.
  add     mch_len,  #4
  //  Store match distance (D) and update the source pointer.
  strh    r8,      [dst_ptr], #2
  add     src_ptr,  mch_len
  //  If we're not into the safety margin of the destination buffer, look for
  //  another match.
  cmp     dst_ptr,  dst_end
  blo     L_next_match
  //  If we *are* into the safety margin of the destination buffer, we're done
  //  encoding this block; update the source and destination pointers and
  //  return.
L_done:
  clear_frame_and_return

//  Constant island
L_hash: .long 2654435761
L_magic: .long 0x80808081

L_emit_careful:
  //  Either L or M is >= 15, which means that we don't get to use the compact
  //  encoding, and that we need to do extra bounds checks while writing.
  //
  //   register   symbolic name   meaning
  //      r0         dst_ptr      pointer into destination buffer where the
  //                              match information will be stored.
  //      r1         dst_end      pointer to the end of the destination buffer,
  //                              less margin.
  //      r2         src_ptr      pointer to the byte after the last match that
  //                              we found, or to the point from which we
  //                              started searching if this is the first match.
  //      r3         src_beg      pointer to the actual start of the buffer.
  //      r4         src_end      pointer to the end of the source buffer, less
  //                              margin.
  //      r5         table        address of hash table.
  //      r6         -
  //      r8         mch_dis      match distance ("D")
  //      r9         mch_len      length of match ("M") less four
  //      r10        -
  //      r11        -
  //      r12        -
  //      lr         lit_len      literal length ("L")
  //      q1                      vector of all ones
  //
  //  Start by creating the low 4 bits of the control word; M if M < 15, 0xf
  //  otherwise.  We also load 0x80808081, which is the magic number for
  //  division by 255; this will be required later on.
  ldr     r12,      L_magic
  cmp     mch_len,  #15
  mov     r10,      mch_len
  movhs   r10,      #0x0f
  subs    r6,       lit_len, #15
  bhs     L_large_L
  //  M is large, but L is < 15.  This means we can use the simple approach
  //  for copying the literal with no bounds checks.
  orr     r10,      lit_len, lsl #4
  strb    r10,     [dst_ptr], #1
  //  Copy literal.
  vld1.8  q0,      [src_ptr]
  add     src_ptr,  lit_len
  vst1.8  q0,      [dst_ptr]
  add     dst_ptr,  lit_len
  //  Store match distance (D).
  strh    r8,      [dst_ptr], #2
  sub     r6,       mch_len, #15
  b       L_large_M

L_large_L:
  //  L is large, M may or may not be.  We need to encode extra literal length
  //  bytes and we need to do bounds checks while store both those byte and the
  //  literal itself.
  orr     r10,      #0xf0
  strb    r10,     [dst_ptr], #1
  //  How many extra literal bytes do we need to store?  We need to store
  //  (L - 15)/255 extra literal bytes of 0xff, plus one more byte that is
  //  (L - 15)%255.  Get these quantities via magic number multiplication:
  //  (L - 15)*0x80808081 >> (32 + 7)
  umull   r10, r11, r6, r12
  mov     r12,      #255
  lsr     r10,      r11, #7       // (L - 15) / 255
  mls     r11,      r10, r12, r6  // (L - 15) % 255
  ldr     r12,      L_magic       // may need magic number again for M.
  //  Compute address dst_ptr will have after storing all 0xff bytes, and
  //  check that we won't exceed dst_end in doing so.
  add     r10,      dst_ptr, r10
  cmp     r10,      dst_end
  bhs     L_done
  //  There's enough space for all the 0xff bytes, so go ahead and store them.
0:vst1.8  q1,      [dst_ptr]!
  cmp     dst_ptr,  r10
  blo     0b
  //  Store the (L - 15) % 255 byte.
  strb    r11,     [r10], #1
  //  Compute the address we'll have reached after storing all literal bytes.
  //  If that passes dst_end, we're done.
  add     dst_ptr,  r10, lit_len
  cmp     dst_ptr,  dst_end
  bhs     L_done
  //  Copy the literal.
0:vld1.8  q0,      [src_ptr]!
  vst1.8  q0,      [r10]!
  subs    r6,       r10, dst_ptr
  blo     0b
  //  Fixup src_ptr, store match distance (D), and check whether or not M is
  //  bigger than 14.  If not, go find the next match.
  strh    r8,      [dst_ptr], #2
  sub     src_ptr,  r6
  subs    r6,       mch_len, #15
  bhs     L_large_M
  //  M is small, so we're all done; we just need to update the source pointer
  //  and we can go look for the next match.
  add     mch_len,  #4
  add     src_ptr,  mch_len
  b       L_next_match

L_large_M:
  //  Just like with large L, we split (M - 15) into (M - 15) / 255 and
  //  (M - 15) % 255 via magic number multiply.
  umull   r10, r11, r6, r12
  mov     r12,      #255
  lsr     r10,      r11, #7       // (M - 15) / 255
  mls     r11,      r10, r12, r6  // (M - 15) % 255
  //  Compute address dst_ptr will have after storing all 0xff bytes, and
  //  check that we won't exceed dst_end in doing so.
  add     r10,      dst_ptr, r10
  cmp     r10,      dst_end
  bhs     L_done
  //  There's enough space for all the 0xff bytes, so go ahead and store them.
0:vst1.8  q1,      [dst_ptr]!
  cmp     dst_ptr,  r10
  blo     0b
  //  Store final M % 255 byte, update dst_ptr and src_ptr, and look for next
  //  match.
  strb    r11,     [r10]
  add     mch_len,  #4
  add     dst_ptr,  r10, #1
  add     src_ptr,  mch_len
  b       L_next_match

L_trailing_literal:
  //  Check if skip_final_literals is set.
  ldr     r5,      [sp, #52]
  tst     r5,       r5
  bne     L_done
  //  Emit a trailing literal that covers the remainder of the source buffer,
  //  if we can do so without exceeding the bounds of the destination buffer.
  add     src_end,  margin
  sub     lit_len,  src_end, src_ptr
  subs    r6,       lit_len, #15
  bhs     L_trailing_literal_long
  lsl     r10,      lit_len, #4
  strb    r10,     [dst_ptr], #1
  vld1.8  q0,      [src_ptr]
  mov     src_ptr,  src_end
  vst1.8  q0,      [dst_ptr]
  add     dst_ptr,  lit_len
  b       L_done

L_trailing_literal_long:
  ldr     r12,      L_magic
  mov     r10,      #0xf0
  add     dst_end,  margin
  strb    r10,     [dst_ptr], #1
  umull   r10, r11, r6, r12
  mov     r12,      #255
  lsr     r10,      r11, #7       // (L - 15) / 255
  mls     r11,      r10, r12, r6  // (L - 15) % 255
  //  We want to write out lit_len + (L - 15)/255 + 1 bytes.  Check if we have
  //  space for all of them.
  add     r10,      dst_ptr
  add     r12,      r10, lit_len
  cmp     r12,      dst_end
  bhs     L_done
  //  We have enough space, so go ahead and write them all out.  Because we
  //  know that we have enough space, and that the literal is at least 15 bytes,
  //  we can write the block of 0xffs using vector stores, even without a
  //  safety margin.
0:vst1.8  q1,      [dst_ptr]!
  cmp     dst_ptr,  r10
  blo     0b
  //  Store the (L - 15) % 255 byte.
  strb    r11,     [r10], #1
  mov     dst_ptr,  r10
  //  Now store the literal itself; here we need to actually be somewhat
  //  careful to ensure that we don't write past the end of the destination
  //  buffer or read past the end of the source buffer.
  subs    lit_len,  #16
  blo     1f
0:vld1.8  q0,      [src_ptr]!
  subs    lit_len,  #16
  vst1.8  q0,      [dst_ptr]!
  bhs     0b
1:adds    lit_len,  #16
  beq     L_done
2:ldrb    r6,      [src_ptr], #1
  subs    lit_len,  #1
  strb    r6,      [dst_ptr], #1
  bne     2b
  b       L_done

#endif
