/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */

#define kShort  11
#define cr1_gt  5       // bit 1 of cr1

/*
 * short xsum_assym( short *p, int len, short xsum, boolean odd);
 *
 *  r3 - Pointer to data
 *  r4 - Length of data
 *  r5 - Accumulated sum value
 *  r6 -"Starting on odd address" flag (relative to byte 0 of the checksumed data)
 *
 * Note: If the "odd" flag is set, the address in r3 will be even.  Nonetheless, we
 *       correctly handle the case where the flag is set and the address is odd.
 *
 * This is the internet (IP, TCP) checksum algorithm, which is the 1s-complement sum
 * of the data, treated as an array of 16-bit integers.  1s-complement sums are done
 * via "add with carry" operations on a 2s-complement machine like PPC.  Note that
 * the adds can be done in parallel on 32-bit (or 64-bit) registers, as long as the
 * final sum is folded down to 16 bits.  On 32-bit machines we use "adde", which is
 * perfect except that it serializes the adds on the carry bit.  On 64-bit machines
 * we avoid this serialization by adding 32-bit words into 64-bit sums, then folding
 * all 64-bits into a 16-bit sum at the end.  We cannot use "adde" on 64-bit sums,
 * because the kernel runs in 32-bit mode even on 64-bit machines (so the carry bit
 * is set on the low 32-bits of the sum.)
 *
 * Using Altivec is tempting, but the performance impact of the greatly increased
 * number of exceptions and register save/restore traffic probably make it impractical
 * for now.
 */        
        .globl  _xsum_assym
        .globl  _xsum_nop_if_32bit
        .text
        .align  5
_xsum_assym:
        cmplwi  cr0,r4,kShort   ; too short to word align?
        rlwinm  r2,r3,0,0x3     ; get byte offset in word
        dcbt    0,r3            ; touch in 1st cache line
        cmpwi   cr6,r2,0        ; is address word aligned?
        ble     cr0,Lshort      ; skip if too short to bother aligning
        
        subfic  r0,r2,4         ; get #bytes in partial word
        cmplwi  cr1,r6,0        ; set cr1_gt if "starting on odd address" flag is set
        addic   r0,r0,0         ; turn off carry
        beq     cr6,Laligned    ; skip if already word aligned (r2==0 if aligned)
        
;       Partial word at start: zero filled on left, it becomes initial checksum.
        
        rlwinm  r3,r3,0,0,29    ; word align address
        mtcrf   0x01,r2         ; move byte offset to cr7
        lwz     r6,0(r3)        ; get partial word
        li      r7,-1           ; start of mask for partial fill
        slwi    r8,r2,3         ; multiply byte offset by 8
        sub     r4,r4,r0        ; adjust length for bytes in partial word
        crxor   cr1_gt,31,cr1_gt; set flag if byte-lane swap will be necessary
        srw     r7,r7,r8        ; get mask for bytes to keep in partial word
        addi    r3,r3,4         ; point to next word of input
        and     r2,r6,r7        ; zero fill on left
        
;       Address is now word aligned.  Prepare for inner loop over 32-byte chunks.
;           r2 = initial checksum
;           r3 = word aligned address
;           r4 = length remaining
;           r5 = accumulated sum parameter
;        carry = off
;       cr1_gt = "starting on odd address" flag

Laligned:
        srwi.   r0,r4,5         ; get count of 32-byte chunks
        mtcrf   0x02,r4         ; move residual length to cr6 and cr7
        mtcrf   0x01,r4
        beq     cr0,Lleftovers  ; no chunks
        
        mtctr   r0              ; set up loop count
        li      r4,32           ; offset to next chunk
_xsum_nop_if_32bit:
        b       L64BitPath      ; use the 64-bit path (patched to nop on 32-bit machine)
        dcbt    r4,r3           ; touch in 2nd cache line
        li      r0,96           ; get touch offset
        b       LInnerLoop32    ; enter 32-bit loop
        
;       Inner loop for 32-bit machines.

        .align  4
LInnerLoop32:
        lwz     r4,0(r3)
        lwz     r6,4(r3)
        lwz     r7,8(r3)
        lwz     r8,12(r3)
        adde    r2,r2,r4
        lwz     r9,16(r3)
        adde    r2,r2,r6
        lwz     r10,20(r3)
        adde    r2,r2,r7
        lwz     r11,24(r3)
        adde    r2,r2,r8
        lwz     r12,28(r3)
        adde    r2,r2,r9
        dcbt    r3,r0
        adde    r2,r2,r10
        addi    r3,r3,32
        adde    r2,r2,r11
        adde    r2,r2,r12
        bdnz+   LInnerLoop32

;       Handle leftover bytes.
;           r2 = checksum so far
;           r3 = word aligned address
;           r5 = accumulated sum parameter
;        carry = live
;       cr1_gt = "starting on odd address" flag
;      cr6,cr7 = residual length

Lleftovers:
        bf      27,Lleftover8   ; test 0x10 bit of residual length
        lwz     r4,0(r3)
        lwz     r6,4(r3)
        lwz     r7,8(r3)
        lwz     r8,12(r3)
        addi    r3,r3,16
        adde    r2,r2,r4
        adde    r2,r2,r6
        adde    r2,r2,r7
        adde    r2,r2,r8
Lleftover8:
        bf      28,Lleftover4
        lwz     r4,0(r3)
        lwz     r6,4(r3)
        addi    r3,r3,8
        adde    r2,r2,r4
        adde    r2,r2,r6
Lleftover4:
        bf      29,Lleftover2
        lwz     r4,0(r3)
        addi    r3,r3,4
        adde    r2,r2,r4
Lleftover2:
        bf      30,Lleftover1
        lhz     r4,0(r3)
        addi    r3,r3,2
        adde    r2,r2,r4
Lleftover1:
        bf      31,Lwrapup
        lbz     r4,0(r3)
        slwi    r4,r4,8         ; shift last byte into proper lane
        adde    r2,r2,r4

;       All data bytes checksummed.  Wrap up.
;           r2 = checksum so far (word parallel)
;           r5 = accumulated sum parameter
;        carry = live
;       cr1_gt = "starting on odd address" flag

Lwrapup:
        addze   r2,r2           ; add in last carry
        addze   r2,r2           ; in case the "addze" carries
Lwrapupx:                       ; here from short-operand case, with xer(ca) undefined
        srwi    r6,r2,16        ; top half of 32-bit checksum
        rlwinm  r7,r2,0,0xFFFF  ; lower half
        add     r2,r6,r7        ; add them together
        srwi    r6,r2,16        ; then do it again, in case first carried
        rlwinm  r7,r2,0,0xFFFF
        add     r2,r6,r7
        bf      cr1_gt,Lswapped ; test "starting on odd address" flag
        
;       The checksum began on an odd address, so swap bytes.

        rlwinm  r6,r2,24,0x00FF ; move top byte to bottom
        rlwinm  r7,r2,8,0xFF00  ; bottom to top
        or      r2,r6,r7        ; rejoin
        
;       Finally, add in checksum passed in as a parameter.

Lswapped:
        add     r2,r2,r5        ; add passed-in checksum
        srwi    r6,r2,16        ; top half of 32-bit checksum
        rlwinm  r7,r2,0,0xFFFF  ; lower half
        add     r2,r6,r7        ; add them together
        srwi    r6,r2,16        ; then do it again, in case first carried
        rlwinm  r7,r2,0,0xFFFF
        add     r3,r6,r7        ; steer result into r3
        blr

;       Handle short operands.  Do a halfword at a time.
;           r3 = address
;           r4 = length (<= kShort)
;           r5 = accumulated sum parameter
;           r6 = "starting on odd byte" flag

Lshort:
        cmpwi   cr6,r4,2        ; at least two bytes?
        andi.   r0,r4,1         ; odd length?
        li      r2,0            ; initialize checksum
        cmplwi  cr1,r6,0        ; set cr1_gt if "starting on odd address" flag is set
        blt     cr6,Lshort2     ; fewer than two bytes, so skip
Lshort1:
        cmpwi   cr6,r4,4        ; two more bytes (after we decrement)?
        lhz     r7,0(r3)
        subi    r4,r4,2
        addi    r3,r3,2
        add     r2,r2,r7        ; note no need for "adde"
        bge     cr6,Lshort1     ; loop for 2 more bytes
Lshort2:
        beq     Lwrapupx        ; no byte at end, proceed to checkout with carry undefined
        lbz     r7,0(r3)
        slwi    r7,r7,8         ; shift last byte into proper lane
        add     r2,r2,r7
        b       Lwrapupx
        
;       Handle 64-bit machine.  The major improvement over the 32-bit path is that we use
;       four parallel 32-bit accumulators, which carry into the upper half naturally so we
;       do not have to use "adde", which serializes on the carry bit.  Note that we cannot
;       do 64-bit "adde"s, because we run in 32-bit mode so carry would not be set correctly.
;           r2 = checksum so far (ie, the zero-filled partial first word)
;           r3 = word aligned address
;           r5 = accumulated sum parameter
;          ctr = number of 32-byte chunks of input
;        carry = unused in this code
;       cr1_gt = "starting on odd address" flag
;      cr6,cr7 = residual length

L64BitPath:
        stw     r13,-4(r1)      ; save a few nonvolatile regs in red zone so we can use them
        stw     r14,-8(r1)
        stw     r15,-12(r1)
        stw     r16,-16(r1)
        li      r0,128          ; to touch next line
        li      r13,0           ; r13-r15 are the accumulators, so initialize them
        dcbt    r3,r0           ; touch in next cache line, and keep loads away from the above stores
        lwz     r4,0(r3)        ; start pipeline by loading first 32 bytes into r4, r6-r12
        lwz     r6,4(r3)
        lwz     r7,8(r3)
        mr      r14,r2          ; just copy incoming partial word into one of the accumulators
        li      r15,0
        lwz     r8,12(r3)
        lwz     r9,16(r3)
        li      r16,0
        li      r0,256          ; get touch offset
        lwz     r10,20(r3)
        lwz     r11,24(r3)
        lwz     r12,28(r3)      ; load last word of previous chunk
        addi    r3,r3,32        ; skip past the chunk
        bdnz++  LInnerLoop64    ; enter loop if another chunk to go
        
        b       LAddLastChunk   ; only one chunk
        
;       Inner loop for 64-bit processors.  This loop is scheduled for the 970.
;       It is pipelined (loads are one iteration ahead of adds), and unrolled.
;       It should take 9-10 cycles per iteration, which consumes 64 bytes of input.

        .align  5
LInnerLoop64:                   ; 64 bytes/iteration
        add     r13,r13,r4      ; cycle 1
        add     r14,r14,r6
        dcbt    r3,r0           ; touch in 2 lines ahead
        lwz     r4,0(r3)
        
        add     r15,r15,r7      ; cycle 2, etc
        lwz     r6,4(r3)
        lwz     r7,8(r3)
        add     r16,r16,r8
        
        lwz     r8,12(r3)
        add     r13,r13,r9
        add     r14,r14,r10
        lwz     r9,16(r3)
        
        add     r15,r15,r11
        lwz     r10,20(r3)
        lwz     r11,24(r3)
        add     r16,r16,r12
        bdz--   LEarlyExit      ; early exit if no more chunks
        
        lwz     r12,28(r3)
        add     r13,r13,r4
        add     r14,r14,r6
        lwz     r4,32(r3)
        
        add     r15,r15,r7
        lwz     r6,36(r3)
        lwz     r7,40(r3)
        add     r16,r16,r8
        
        lwz     r8,44(r3)
        add     r13,r13,r9
        add     r14,r14,r10
        lwz     r9,48(r3)
        
        add     r15,r15,r11
        lwz     r10,52(r3)
        lwz     r11,56(r3)
        add     r16,r16,r12
        
        nop                     ; position last load in 2nd dispatch slot
        lwz     r12,60(r3)
        addi    r3,r3,64
        bdnz++  LInnerLoop64
        
        b       LAddLastChunk

;       Add in the last 32-byte chunk, and any leftover bytes.
;           r3 = word aligned address of next byte of data
;           r5 = accumulated sum parameter
;      r13-r16 = the four accumulators
;       cr1_gt = "starting on odd address" flag
;      cr6,cr7 = residual length

LEarlyExit:                     ; here from middle of inner loop
        lwz     r12,28(r3)      ; load last word of last chunk
        addi    r3,r3,32
LAddLastChunk:                  ; last 32-byte chunk of input is in r4,r6-r12
        add     r13,r13,r4      ; add in last chunk
        add     r14,r14,r6      ; these are 64-bit adds
        add     r15,r15,r7
        add     r16,r16,r8
        add     r13,r13,r9
        add     r14,r14,r10
        add     r15,r15,r11
        add     r16,r16,r12

;       Handle leftover bytes, if any.

        bf      27,Lleft1       ; test 0x10 bit of residual length
        lwz     r4,0(r3)
        lwz     r6,4(r3)
        lwz     r7,8(r3)
        lwz     r8,12(r3)
        addi    r3,r3,16
        add     r13,r13,r4
        add     r14,r14,r6
        add     r15,r15,r7
        add     r16,r16,r8
Lleft1:
        bf      28,Lleft2
        lwz     r4,0(r3)
        lwz     r6,4(r3)
        addi    r3,r3,8
        add     r13,r13,r4
        add     r14,r14,r6
Lleft2:
        bf      29,Lleft3
        lwz     r4,0(r3)
        addi    r3,r3,4
        add     r14,r14,r4
Lleft3:
        bf      30,Lleft4
        lhz     r4,0(r3)
        addi    r3,r3,2
        add     r15,r15,r4
Lleft4:
        bf      31,Lleft5
        lbz     r4,0(r3)
        slwi    r4,r4,8         ; shift last byte into proper lane
        add     r16,r16,r4

;       All data bytes have been checksummed.  Now we must add together the four
;       accumulators and restore the regs from the red zone.
;           r3 = word aligned address of next byte of data
;           r5 = accumulated sum parameter
;      r13-r16 = the four accumulators
;        carry = not used so far
;       cr1_gt = "starting on odd address" flag

Lleft5:
        add     r8,r13,r14      ; add the four accumulators together
        add     r9,r15,r16
        lwz     r13,-4(r1)      ; start to restore nonvolatiles from red zone
        lwz     r14,-8(r1)
        add     r8,r8,r9        ; now r8 is 64-bit sum of the four accumulators
        lwz     r15,-12(r1)
        lwz     r16,-16(r1)
        srdi    r7,r8,32        ; get upper half of 64-bit sum
        addc    r2,r7,r8        ; finally, do a 32-bit add of the two halves of r8 (setting carry)
        b       Lwrapup         ; merge r2, r5, and carry into a 16-bit checksum
