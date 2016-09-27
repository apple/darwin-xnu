#include <vm/lz4_assembly_select.h>
#if LZ4_ENABLE_ASSEMBLY_DECODE_X86_64

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

#if MSVC_CALLING_CONVENTIONS
#error TODO implement MSVC calling conventions for LZ4 x86_64 assembly
#endif

// %rax and %rbx are free to use

#define dst		%rdi    // arg0
#define dst_begin       %rsi    // arg1
#define dst_end		%rdx    // arg2
#define src		%rcx    // arg3
#define src_end		%r8     // arg4

#define n_literals	%r9
#define n_matches	%r10

#define copy_src	%r11    // match/literal copy source
#define copy_dst	%r12	// match/literal copy destination
#define match_distance	%r13	// match distance

#define src_good        %r14
#define dst_good        %r15

.globl _lz4_decode_asm

.macro establish_frame
    push	%rbp
    mov		%rsp,%rbp
    push	%rbx
    push	%r12
    push	%r13
    push	%r14
    push	%r15
.endm

.macro clear_frame_and_return
    pop		%r15
    pop		%r14
    pop		%r13
    pop		%r12
    pop		%rbx
    pop		%rbp
#ifdef __AVX2__
    vzeroupper
#endif
    ret
.endm

// copy_1x16 SOURCE_ADDR DESTINATION_ADDR
// Copy 16 bytes, clobber: xmm0
.macro copy_1x16
#ifdef __AVX2__
    vmovdqu	($0),%xmm0
    vmovdqu	%xmm0,($1)
#else
    movdqu	($0),%xmm0
    movdqu	%xmm0,($1)
#endif
.endm

// copy_1x16_and_increment SOURCE_ADDR DESTINATION_ADDR
// Copy 16 bytes, and increment both addresses by 16, clobber: xmm0
.macro copy_1x16_and_increment
#ifdef __AVX2__
    vmovdqu	($0),%xmm0
    vmovdqu	%xmm0,($1)
#else
    movdqu	($0),%xmm0
    movdqu	%xmm0,($1)
#endif
    add		$$16,$0
    add		$$16,$1
.endm

// copy_2x16_and_increment SOURCE_ADDR DESTINATION_ADDR
// Copy 2 times 16 bytes, and increment both addresses by 32, clobber: xmm0
.macro copy_2x16_and_increment
#ifdef __AVX2__
    vmovdqu	($0),%xmm0
    vmovdqu	%xmm0,($1)
    vmovdqu	16($0),%xmm0
    vmovdqu	%xmm0,16($1)
#else
    movdqu	($0),%xmm0
    movdqu	%xmm0,($1)
    movdqu	16($0),%xmm0
    movdqu	%xmm0,16($1)
#endif
    add		$$32,$0
    add		$$32,$1
.endm

// copy_1x32_and_increment SOURCE_ADDR DESTINATION_ADDR
// Copy 32 bytes, and increment both addresses by 32, clobber: xmm0,xmm1
.macro copy_1x32_and_increment
#ifdef __AVX2__
    vmovdqu	($0),%ymm0
    vmovdqu	%ymm0,($1)
#else
    movdqu	($0),%xmm0
    movdqu	16($0),%xmm1
    movdqu	%xmm0,($1)
    movdqu	%xmm1,16($1)
#endif
    add		$$32,$0
    add		$$32,$1
.endm

.macro check_src_end
    cmp		src,src_end
    jbe		L_done				// done if src >= src_end
.endm

.macro check_dst_end
    cmp		dst,dst_end
    jbe		L_done				// done if dst >= dst_end
.endm

.text
.p2align 6
_lz4_decode_asm:
    establish_frame
    push        dst                             // keep uint8_t ** dst on stack
    mov         (dst),dst                       // load current dst from *dst
    push        src                             // keep const uint8_t ** src on stack
    mov         (src),src                       // load current src from *src

L_decode_command:
    // Keep last known good command
    mov		dst,dst_good
    mov		src,src_good

    // Check limits
    check_src_end
    check_dst_end

    // Decode command
    movzb       (src),%rax			// read command byte LLLLMMMM
    add		$1,src
    mov		%rax,n_literals
    shr		$4,n_literals			// n_literals in 0..15
    mov		%rax,n_matches
    and		$0xf,n_matches
    add		$4,n_matches			// n_matches in 4..19

    // Short literal?
    cmp		$15,n_literals
    je		L_decode_long_literal

    // Copy literals, n_literals <= 14: copy 16 bytes
L_copy_short_literal:
    copy_1x16	src,dst
    add		n_literals,src			// src += n_literals
    add		n_literals,dst			// dst += n_literals
    jmp		L_expand_match				// continue to match

    // the number of literals is encoded on more bytes, we need to decode them
L_decode_long_literal:
    check_src_end				// required here, since we may loop an arbitrarily high number of times
    movzb	(src),%rax
    add		$1,src
    add		%rax,n_literals
    cmp		$255,%rax
    je		L_decode_long_literal

    // Copy literals, n_literals >= 15
L_copy_long_literal:
    mov		src,copy_src			// literal copy source
    mov		dst,copy_dst			// literal copy destination
    add		n_literals,src			// update src,dst for next step
    add		n_literals,dst
    check_src_end				// required here, since n_literals can be arbitrarily high
    check_dst_end

    // fixed + loop
    copy_1x32_and_increment copy_src,copy_dst
    copy_1x32_and_increment copy_src,copy_dst
L_copy_long_literal_loop:
    copy_1x32_and_increment copy_src,copy_dst
    cmp		copy_dst,dst
    ja		L_copy_long_literal_loop
    // continue to match

L_expand_match:
    // Load match distance, and get match copy source
    movzw	(src),match_distance
    add		$2,src
    test        match_distance,match_distance
    jz          L_fail                          // match_distance == 0: FAIL
    mov		dst,copy_src
    sub		match_distance,copy_src		// copy_src = match copy source
    cmp		copy_src,dst_begin
    ja		L_fail				// dst_begin > copy_src: FAIL

    // Long n_matches encoding?
    cmp		$19,n_matches
    je		L_decode_long_match		// unlikely
    // Long n_matches with short encoding (17 or 18)?
    cmp		$16,n_matches
    ja		L_long_match			// unlikely

    // Copy match, n_matches <= 16
L_copy_short_match:
    cmp		$16,match_distance
    jb		L_copy_short_match_overlap

    // Copy match, n_matches <= 16 and match_distance >= 16: copy 16 bytes
    copy_1x16	copy_src,dst
    add		n_matches,dst			// update dst
    jmp		L_decode_command		// to next command

    // Copy match, n_matches <= 16 and match_distance < 16: replicate pattern
L_copy_short_match_overlap:
    lea		L_match_permtable(%rip),%rax
    shl		$5,match_distance
#ifdef __AVX2__
    vmovdqa	(%rax,match_distance),%xmm2	// pattern address is match_permtable + 32 * match_distance
    vmovdqu	(copy_src),%xmm0		// read the bytes to replicate. exactly match_distance bytes are needed, but we load 16
    vpshufb	%xmm2,%xmm0,%xmm0		// replicate the pattern in xmm0
    vmovdqu	%xmm0,(dst)			// and store the result
#else
    movdqa	(%rax,match_distance),%xmm2	// pattern address is match_permtable + 32 * match_distance
    movdqu	(copy_src),%xmm0		// read the bytes to replicate. exactly match_distance bytes are needed, but we load 16
    pshufb	%xmm2,%xmm0			// replicate the pattern in xmm0
    movdqu	%xmm0,(dst)			// and store the result
#endif
    add		n_matches,dst			// update dst
    jmp		L_decode_command		// to next command

    // n_matches == 19: the number of matches in encoded on more bytes, we need to decode them
L_decode_long_match:
    mov		$255,%rbx
L_decode_long_match_loop:
    check_src_end				// required here, since we may loop an arbitrarily high number of times
    mov		(src),%rax
    add		$1,src
    and		%rbx,%rax
    add		%rax,n_matches
    cmp		%rbx,%rax
    je		L_decode_long_match_loop

    // n_matches > 16
L_long_match:
    mov		dst,copy_dst			// copy_dst = match copy destination
    add		n_matches,dst			// update dst
    check_dst_end				// n_matches may be arbitrarily high

    cmp		$16,match_distance
    jb		L_copy_long_match_overlap	// match_distance < 16: overlapping copy

    // Copy match, n_matches >= 16, match_distance >= 16
    // fixed + loop
    copy_1x16_and_increment copy_src,copy_dst
L_copy_long_match_loop:
    copy_2x16_and_increment copy_src,copy_dst
    cmp		copy_dst,dst
    ja		L_copy_long_match_loop
    jmp		L_decode_command		// to next command

    // Copy match, n_matches >= 16, match_distance < 16: replicate pattern
L_copy_long_match_overlap:
    lea		L_match_permtable(%rip),%rax
    mov		match_distance,%rbx
    shl		$5,%rbx
#ifdef __AVX2__
    vmovdqu	(copy_src),%xmm0		// read the bytes to replicate. exactly match_distance bytes are needed, but we load 16
    vmovdqa	%xmm0,%xmm1			// keep a copy for the high bytes
    vmovdqa	(%rax,%rbx),%xmm2		// pattern for low 16 bytes
    vpshufb	%xmm2,%xmm0,%xmm0		// replicate the pattern in xmm0
    vmovdqa	16(%rax,%rbx),%xmm2		// pattern for high 16 bytes
    vpshufb	%xmm2,%xmm1,%xmm1		// replicate the pattern in xmm1
    vinserti128	$1,%xmm1,%ymm0,%ymm0		// store all 32 bytes into a single register
#else
    movdqu	(copy_src),%xmm0		// read the bytes to replicate. exactly match_distance bytes are needed, but we load 16
    movdqa	%xmm0,%xmm1			// keep a copy for the high bytes
    movdqa	(%rax,%rbx),%xmm2		// pattern for low 16 bytes
    pshufb	%xmm2,%xmm0			// replicate the pattern in xmm0
    movdqa	16(%rax,%rbx),%xmm2		// pattern for high 16 bytes
    pshufb	%xmm2,%xmm1			// replicate the pattern in xmm1
#endif
    // Here, %xmm0:%xmm1 (or %ymm0 for AVX2) is a 32-byte pattern replicating the first match_distance bytes up to 32 bytes
    lea		L_match_disttable(%rip),%rax
    movzb	(%rax,match_distance),%rax	// and %rax is now the usable length of this pattern, the largest multiple of match_distance less than or equal to 32.

    // fixed
#ifdef __AVX2__
    vmovdqu	%ymm0,(copy_dst)
#else
    movdqu	%xmm0,(copy_dst)
    movdqu	%xmm1,16(copy_dst)
#endif
    add		%rax,copy_dst
L_copy_long_match_overlap_loop:
    // loop
#ifdef __AVX2__
    vmovdqu	%ymm0,(copy_dst)
#else
    movdqu	%xmm0,(copy_dst)
    movdqu	%xmm1,16(copy_dst)
#endif
    add		%rax,copy_dst
    cmp		copy_dst,dst
    ja		L_copy_long_match_overlap
    jmp		L_decode_command		// to next command

L_fail:
    xor		%rax,%rax
    dec		%rax				// -1
    jmp		L_exit

L_done:
    xor		%rax,%rax
    // continue to exit

L_exit:
    pop         src
    mov         src_good,(src)
    pop         dst
    mov         dst_good,(dst)
    clear_frame_and_return

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

#endif // LZ4_ENABLE_ASSEMBLY_DECODE_X86_64
