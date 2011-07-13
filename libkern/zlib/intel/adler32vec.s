/* Apple Copyright 2009
   CoreOS - vector & Numerics, cclee 10-22-09

	This following source code implements a vectorized version of adler32 computation that is defined in zlib.
	The target architectures are x86_64 and i386.

	Given 2 unsigned 32-bit alder and sum2 (both pre-modulo by BASE=65521) and a sequence of input bytes x[0],...x[N-1].
	The adler-sum2 pair is updated according to

		for (i=0;i<N;i++) {
			adler = (adler+x[i])%BASE;
			sum2 = (sum2+adler)%BASE;
		}

	To reduce/save the modulo operations, it can be shown that, if initial alder and sum2 are less than BASE(=65521),
	adler and sum2 (in 32-bit representation), will never overflow for the next NMAX=5552 bytes. This simplifies the
	algorithm to 

		for (i=0;i<N;i+=NMAX) {
			for (k=0;k<NMAX;k++) {
				adler+=x[i+k];
				sum2+=adler;
			}
			adler%=BASE;
			sum2%=BASE;
		}

	The hand optimization of this function is now reduced to 

			for (k=0;k<NMAX;k++) {
                adler+=x[k];
                sum2+=adler;
            }

	This subtask turns out to be very vecterizable. Suppose we perform the adler/sum2 update once per K bytes,

			for (k=0;k<K;k++) {
                adler+=x[k];
                sum2+=adler;
            }

	It can be shown that the sum2-adler pair can be updated according to

		sum2 += adler*K;
		adler += (x[0] + x[1] + ... + x[K-1]); 
		sum2 += (x[0]*K + x[1]*(K-1) + ... + x[K-1]*1);

	The last 2 equations obviously show that the adler-sum2 pair update can be speeded up using vector processor.
	The input vector [ x[0] x[1] ... x[K-1] ]. And we need two coefficient vectors
		[ 1 1 1 ... 1 ] for adler update.
		[ K K-1 ... 1 ] for sum2 update.

	The implementation below reads vector (K=16,32,48,64) into xmm registers, and sets up coefficient vectors in xmm
	registers. It then uses SSE instructions to perform the aforementioned vector computation.

	For i386, NMAX/16 = 347, whenever possible (NMAX-bytes block), it calls 173 times of macro code DO32 (K=32),
	followed by a single DO16 (K=16), before calling a modulo operation for adler and sum2.

	For x86_64 (where more xmm registers are available), NMAX/64 = 86, whenever possible (NMAX-bytes block), 
	it calls 86 times of macro code DO64 (K=64), followed by a single DO48 (K=48), 
	before calling a modulo operation for adler and sum2.

*/

/* added cpu_capability to detect kHasSupplementalSSE3 to branch into code w or wo SupplementalSSE3

	Previously, ssse3 code was intentionally turned off, because Yonah does not support ssse3
	add code here to probe cpu_capabilities for ssse3 support
		if ssse3 is supported, branch to ssse3-based code, otherwise use the original code

	cclee 5-3-10
*/

#define BASE 65521  /* largest prime smaller than 65536 */
#define NMAX 5552 	/* NMAX is the largest n such that 255n(n+1)/2 + (n+1)(BASE-1) <= 2^32-1 */

// uLong	adler32_vec(unsigned int adler, unsigned int sum2, const Bytef *buf, int len) {
//    unsigned n;
//    while (len >= NMAX) {
//        len -= NMAX;
//        n = NMAX / 16;          /* NMAX is divisible by 16 */
//        do {
//            DO16(buf);          /* 16 sums unrolled */
//            buf += 16;
//        } while (--n);
//        MOD(adler);
//        MOD(sum2);
//    }
//    if (len) {                  /* avoid modulos if none remaining */
//        while (len >= 16) {
//            len -= 16;
//            DO16(buf);
//            buf += 16;
//        }
//        while (len--) {
//            adler += *buf++;
//            sum2 += adler;
//        }
//        MOD(adler);
//        MOD(sum2);
//    }
//    return adler | (sum2 << 16);
// }

#if (defined __i386__ || defined __x86_64__)

#include <i386/cpu_capabilities.h>

	.text
	.align 4,0x90
.globl _adler32_vec
_adler32_vec:

#if (defined __i386__)

	pushl	%ebp
	movl	%esp, %ebp

	pushl	%ebx
	pushl	%edi
	pushl	%esi

#ifdef	KERNEL 						// if this is for kernel, need to save xmm registers
	subl	$140, %esp				// to save %xmm0-%xmm7 into stack, extra 12 to align %esp to 16-byte boundary
	movaps	%xmm0, 0(%esp)		// save xmm0, offset -12 for ebx/edi/esi
	movaps	%xmm1, 16(%esp)		// save xmm1
	movaps	%xmm2, 32(%esp)		// save xmm2
	movaps	%xmm3, 48(%esp)		// save xmm3
	movaps	%xmm4, 64(%esp)		// save xmm4
	movaps	%xmm5, 80(%esp)		// save xmm5
	movaps	%xmm6, 96(%esp)		// save xmm6
	movaps	%xmm7, 112(%esp)		// save xmm7, if this is for SSSE3 or above
#endif

	#define	adler	%edi				// 8(%ebp)
	#define	sum2	%esi				// 12(%ebp)
	#define	buf		%ecx				// 16(%ebp)
	#define	len		%ebx				// 20(%ebp)
	#define	zero	%xmm0
	#define ones	%xmm5

	movl	8(%ebp), adler
	movl	12(%ebp), sum2
	movl	16(%ebp), buf			// use ecx as buf pointer
	movl	20(%ebp), len

	.macro		modulo_BASE
	movl		$$-2146992015, %eax		// 1/BASE in Q47
	mull		adler					// edx:eax = adler divided by BASE in Q47
	shrl		$$15, %edx				// edx is now the floor integer of adler and BASE
	imull		$$BASE, %edx, %edx		// edx * BASE
	subl		%edx, adler				// adler -= edx*BASE
	movl		$$-2146992015, %eax		// 1/BASE in Q47
	mull		sum2					// edx:eax = sum2 divided by BASE in Q47
	shrl		$$15, %edx				// edx is now the floor integer of sum2 and BASE
	imull		$$BASE, %edx, %eax		// eax = edx * BASE
	subl		%eax, sum2				// sum2 -= sdx*BASE
	.endmacro

	// update adler/sum2 according to a new 16-byte vector
	.macro		DO16
	movaps		(buf), %xmm1			// 16 bytes vector, in xmm1
	movaps		%xmm1, %xmm3			// a copy of the vector, used for unsigned byte in the destination of pmaddubsw
	addl		$$16, buf				// buf -> next vector
	psadbw		zero, %xmm1				// 2 16-bit words to be added for adler in xmm1
	pmaddubsw	%xmm4, %xmm3			// 8 16-bit words to be added for sum2 in xmm3
	imull		$$16, adler, %edx		// edx = 16*adler;
	movhlps		%xmm1, %xmm2			// higher 16-bit word (for adler) in xmm2 	
	pmaddwd		ones, %xmm3				// 4 32-bit elements to be added for sum2 in xmm3
	paddq		%xmm2, %xmm1			// xmm1 lower 32-bit to be added to adler
	addl		%edx, sum2				// sum2 += adler*16;
	movhlps		%xmm3, %xmm2			// 2 higher 32-bit elements of xmm3 to be added to lower 2 32-bit elements
	movd		%xmm1, %edx				// to be added to adler
	paddd		%xmm2, %xmm3			// 2 32-bits elements in xmm3 to be added to sum2
	addl		%edx, adler				// update adler
	movd		%xmm3, %edx				// to be added to sum2
	psrlq		$$32, %xmm3				// another 32-bit to be added to sum2
	addl		%edx, sum2				// sum2 += 1st half of update
	movd		%xmm3, %edx				// to be added to sum2
	addl		%edx, sum2				// sum2 += 2nd half of update
	.endm

	// update adler/sum2 according to a new 32-byte vector
	.macro		DO32
	imull		$$32, adler, %edx		// edx = 32*adler
	movaps		(buf), %xmm1			// 1st 16 bytes vector
	movaps		16(buf), %xmm7			// 2nd 16 bytes vector
	movaps		%xmm1, %xmm3			// a copy of 1st vector, used for unsigned byte in the destination of pmaddubsw
	movaps		%xmm7, %xmm2			// a copy of 2nd vector, used for unsigned byte in the destination of pmaddubsw
	psadbw		zero, %xmm1				// 2 16-bit words to be added for adler in xmm1
	psadbw		zero, %xmm7				// 2 16-bit words to be added for adler in xmm7
	addl		%edx, sum2				// sum2 += adler*32;
	pmaddubsw	%xmm6, %xmm3			// 8 16-bit words to be added for sum2 in xmm3
	pmaddubsw	%xmm4, %xmm2			// 8 16-bit words to be added for sum2 in xmm2
	paddd		%xmm7, %xmm1			// 2 16-bit words to be added for adler in xmm1
	paddd		%xmm2, %xmm3			// 8 16-bit words to be added for sum2 in xmm3
	addl		$$32, buf				// buf -> vector for next iteration
	movhlps		%xmm1, %xmm2			// higher 16-bit word (for adler) in xmm2 	
	pmaddwd		ones, %xmm3				// 4 32-bit elements to be added for sum2 in xmm3
	paddq		%xmm2, %xmm1			// xmm1 lower 32-bit to be added to adler
	movhlps		%xmm3, %xmm2			// 2 higher 32-bit elements of xmm3 to be added to lower 2 32-bit elements
	movd		%xmm1, %edx				// to be added to adler
	paddd		%xmm2, %xmm3			// 2 32-bits elements in xmm3 to be added to sum2
	addl		%edx, adler				// update adler
	movd		%xmm3, %edx				// to be added to sum2
	psrlq		$$32, %xmm3				// another 32-bit to be added to sum2
	addl		%edx, sum2				// sum2 += 1st half of update
	movd		%xmm3, %edx				// to be added to sum2
	addl		%edx, sum2				// sum2 += 2nd half of update
	.endm

	// this defines the macro DO16 for SSSE3 not supported
    .macro      DO16_nossse3
    movaps      (buf), %xmm1            // 16 bytes vector
    movaps      %xmm1, %xmm3            // a copy of the vector, the lower 8 bytes to be shuffled into 8 words
    movaps      %xmm1, %xmm2            // a copy of the vector, the higher 8 bytes to be shuffled into 8 words
    psrldq      $$8, %xmm2              // shift down 8 bytes, to reuse the shuffle vector
    punpcklbw   zero, %xmm3             // convert lower 8 bytes into 8 words
    punpcklbw   zero, %xmm2             // convert higher 8 bytes into 8 words
    pmullw      %xmm6, %xmm3            // lower 8 words * 16:9
    pmullw      %xmm4, %xmm2            // higher 8 words * 8:1
    addl        $$16, buf               // buf -> next vector
    psadbw      zero, %xmm1             // 2 16-bit words to be added for adler in xmm1
    paddw       %xmm2, %xmm3            // 8 16-bit words to be added for sum2 in xmm3
    imull       $$16, adler, %edx       // edx = 16*adler;
    movhlps     %xmm1, %xmm2            // higher 16-bit word (for adler) in xmm2   
    pmaddwd     ones, %xmm3             // 4 32-bit elements to be added for sum2 in xmm3
    paddq       %xmm2, %xmm1            // xmm1 lower 32-bit to be added to adler
    addl        %edx, sum2              // sum2 += adler*16;
    movhlps     %xmm3, %xmm2            // 2 higher 32-bit elements of xmm3 to be added to lower 2 32-bit elements
    movd        %xmm1, %edx             // to be added to adler
    paddd       %xmm2, %xmm3            // 2 32-bits elements in xmm3 to be added to sum2
    addl        %edx, adler             // update adler
    movd        %xmm3, %edx             // to be added to sum2
    psrlq       $$32, %xmm3             // another 32-bit to be added to sum2
    addl        %edx, sum2              // sum2 += 1st half of update
    movd        %xmm3, %edx             // to be added to sum2
    addl        %edx, sum2              // sum2 += 2nd half of update
    .endm

#ifdef  KERNEL
    leal    __cpu_capabilities, %eax                        // %eax -> __cpu_capabilities
    mov     (%eax), %eax                                    // %eax = __cpu_capabilities
#else
    mov    _COMM_PAGE_CPU_CAPABILITIES, %eax
#endif
    test    $(kHasSupplementalSSE3), %eax 					// __cpu_capabilities & kHasAES
	je		L_no_ssse3

	// i386 adler32 with ssse3

	// need to fill up xmm4/xmm5/xmm6 only if len>=16
	cmpl	$16, len
	jl		L_skip_loading_tables

	// set up table starting address to %eax
	leal	sum2_coefficients, %eax

	// reading coefficients
	pxor	zero, zero
	movaps	(%eax), %xmm6			// coefficients for computing sum2 : pmaddubsw 32:17
	movaps	16(%eax), %xmm4			// coefficients for computing sum2 : pmaddubsw 16:1
	movaps	32(%eax), ones			// coefficients for computing sum2 : pmaddwd 1,1,...,1

L_skip_loading_tables:

	cmpl	$NMAX, len				// len vs NMAX
	jl		len_lessthan_NMAX		// if (len < NMAX), skip the following NMAX batches processing

len_ge_NMAX_loop:					// while (len>=NMAX) {

	subl	$NMAX, len				// 		len -= NMAX
	movl	$(NMAX/32), %eax		// 		n = NMAX/32

n_loop:								// 		do {
	DO32							// 			update adler/sum2 for a 32-byte input
	decl 	%eax					// 			n--;
	jg		n_loop					//  	} while (n);
	DO16							//  	update adler/sum2 for a 16-byte input
	modulo_BASE						// 		(adler/sum2) modulo BASE;
	cmpl	$NMAX, len				//  
	jge		len_ge_NMAX_loop		// }	/* len>=NMAX */

len_lessthan_NMAX:

	subl	$32, len				// pre-decrement len by 32
	jl		len_lessthan_32			// if len < 32, skip the 32-vector code
len32_loop:							// while (len>=32) {
	DO32							//   update adler/sum2 for a 32-byte input
	subl	$32, len				//   len -= 32;
	jge		len32_loop				// } 

len_lessthan_32:

	addl	$(32-16), len			// post-increment by 32 + pre-decrement by 16 on len
	jl		L_len_lessthan_16			// if len < 16, skip the 16-vector code
	DO16							// update adler/sum2 for a 16-byte input
	subl	$16, len				// len -= 16;

L_len_lessthan_16:
	addl	$16, len				// post-increment len by 16
	jz		len_is_zero				// if len==0, branch over scalar processing

0:									// while (len) {
	movzbl	(buf), %edx				// 	new input byte
	incl	buf						// 	buf++
	addl	%edx, adler				// 	adler += *buf
	addl	adler, sum2				// 	sum2 += adler
	subl	$1, len					// 	len--
	jg		0b						// }

len_is_zero:

	modulo_BASE						// (adler/sum2) modulo BASE;

	// construct 32-bit (sum2<<16 | adler) to be returned

	sall	$16, sum2				// sum2 <<16
	movl	adler, %eax				// adler		
	orl		sum2, %eax				// sum2<<16 | adler


#ifdef	KERNEL 					// if this is for kernel code, need to restore xmm registers
	movaps	(%esp), %xmm0		// restore xmm0, offset -12 for ebx/edi/esi
	movaps	16(%esp), %xmm1		// restore xmm1
	movaps	32(%esp), %xmm2		// restore xmm2
	movaps	48(%esp), %xmm3		// restore xmm3
	movaps	64(%esp), %xmm4		// restore xmm4
	movaps	80(%esp), %xmm5		// restore xmm5
	movaps	96(%esp), %xmm6		// restore xmm6
	movaps	112(%esp), %xmm7	// restore xmm7, if this is for SSSE3 or above
	addl	$140, %esp			// we've already restored %xmm0-%xmm7 from stack
#endif

    popl   %esi
    popl   %edi
	popl   %ebx
	leave						// pop ebp out from stack
	ret


L_no_ssse3:

	// i386 adler32 without ssse3

	// need to fill up xmm4/xmm5/xmm6 only if len>=16
	cmpl	$16, len
	jl		2f

	// set up table starting address to %eax
	leal	sum2_coefficients, %eax

	// reading coefficients
	pxor	zero, zero
	movaps  48(%eax), %xmm6         // coefficients for computing sum2 : pmaddubsw 16:9
    movaps  64(%eax), %xmm4         // coefficients for computing sum2 : pmaddubsw 8:1
    movaps  80(%eax), ones          // coefficients for computing sum2 : pmaddwd 1,1,...,1

2:

	cmpl	$NMAX, len				// len vs NMAX
	jl		3f						// if (len < NMAX), skip the following NMAX batches processing

0:									// while (len>=NMAX) {

	subl	$NMAX, len				// 		len -= NMAX
	movl	$(NMAX/16), %eax		// 		n = NMAX/16

1:									// 		do {
	DO16_nossse3					//			update adler/sum2 for a 16-byte input
	decl 	%eax					// 			n--;
	jg		1b						//  	} while (n);

	modulo_BASE						// 		(adler/sum2) modulo BASE;

	cmpl	$NMAX, len				//  
	jge		0b						// }	/* len>=NMAX */

3:

	subl	$16, len				// pre-decrement len by 16
	jl		L_len_lessthan_16		// if len < 16, skip the 16-vector code
	DO16_nossse3					// update adler/sum2 for a 16-byte input
	subl	$16, len				// len -= 16;
	jmp		L_len_lessthan_16


	.const
	.align	4
sum2_coefficients:	// used for vectorizing adler32 computation

	.byte	32
	.byte	31
	.byte	30
	.byte	29
	.byte	28
	.byte	27
	.byte	26
	.byte	25
	.byte	24
	.byte	23
	.byte	22
	.byte	21
	.byte	20
	.byte	19
	.byte	18
	.byte	17
	.byte	16
	.byte	15
	.byte	14
	.byte	13
	.byte	12
	.byte	11
	.byte	10
	.byte	9
	.byte	8
	.byte	7
	.byte	6
	.byte	5
	.byte	4
	.byte	3
	.byte	2
	.byte	1

	// coefficients for pmaddwd, to combine into 4 32-bit elements for sum2
	.word	1
	.word	1
	.word	1
	.word	1
	.word	1
	.word	1
	.word	1
	.word	1


	// data for without ssse3

	.word   16
    .word   15
    .word   14
    .word   13
    .word   12
    .word   11
    .word   10
    .word   9
    .word   8
    .word   7
    .word   6
    .word   5
    .word   4
    .word   3
    .word   2
    .word   1

	// coefficients for pmaddwd, to combine into 4 32-bit elements for sum2
	.word	1
	.word	1
	.word	1
	.word	1
	.word	1
	.word	1
	.word	1
	.word	1

#else	// (defined __x86_64__)

	movq    __cpu_capabilities@GOTPCREL(%rip), %rax         // %rax -> __cpu_capabilities
	mov     (%rax), %eax                                    // %eax = __cpu_capabilities
	test    $(kHasSupplementalSSE3), %eax                   // __cpu_capabilities & kHasSupplementalSSE3
    jne      L_has_ssse3

	// ----------------------------------------------------------------------------------
	// the following is added for x86_64 without SSSE3 support
	// it is essentially a translated copy of the i386 code without SSSE3 code
	// ----------------------------------------------------------------------------------

	// input :
	//		 adler : rdi
	//		 sum2  : rsi
	// 		 buf   : rdx
	//		 len   : rcx

	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%rbx

#ifdef	KERNEL			// if for kernel, save %xmm0-%xmm11
	subq	$200, %rsp	// allocate for %xmm0-%xmm11 (192 bytes), extra 8 to align %rsp to 16-byte boundary
	movaps	%xmm0, -32(%rbp)
	movaps	%xmm1, -48(%rbp)
	movaps	%xmm2, -64(%rbp)
	movaps	%xmm3, -80(%rbp)
	movaps	%xmm4, -96(%rbp)
	movaps	%xmm5, -112(%rbp)
	movaps	%xmm6, -128(%rbp)
#endif

	#define	adler	%rdi				// 16(%rbp)
	#define	sum2	%rsi				// 24(%ebp)
	#define	buf		%rcx				// 32(%ebp)
	#define	len		%rbx				// 40(%ebp)
	#define	zero	%xmm0
	#define ones	%xmm5

	movq	%rcx, len
	movq	%rdx, buf

	.macro		modulo_BASE
	movl		$$-2146992015, %eax		// 1/BASE in Q47
	mull		%edi					// edx:eax = adler divided by BASE in Q47
	shrl		$$15, %edx				// edx is now the floor integer of adler and BASE
	imull		$$BASE, %edx, %edx		// edx * BASE
	subq		%rdx, adler				// adler -= edx*BASE
	movl		$$-2146992015, %eax		// 1/BASE in Q47
	mull		%esi					// edx:eax = sum2 divided by BASE in Q47
	shrl		$$15, %edx				// edx is now the floor integer of sum2 and BASE
	imull		$$BASE, %edx, %eax		// eax = edx * BASE
	subq		%rax, sum2				// sum2 -= sdx*BASE
	.endmacro

	// update adler/sum2 according to a new 16-byte vector, no ssse3
	.macro		DO16_nossse3
    movaps      (buf), %xmm1            // 16 bytes vector
    movaps      %xmm1, %xmm3            // a copy of the vector, the lower 8 bytes to be shuffled into 8 words
    movaps      %xmm1, %xmm2            // a copy of the vector, the higher 8 bytes to be shuffled into 8 words
    psrldq      $$8, %xmm2              // shift down 8 bytes, to reuse the shuffle vector
    punpcklbw   zero, %xmm3             // convert lower 8 bytes into 8 words
    punpcklbw   zero, %xmm2             // convert higher 8 bytes into 8 words
    pmullw      %xmm6, %xmm3            // lower 8 words * 16:9
    pmullw      %xmm4, %xmm2            // higher 8 words * 8:1
    add	        $$16, buf               // buf -> next vector
    psadbw      zero, %xmm1             // 2 16-bit words to be added for adler in xmm1
    paddw       %xmm2, %xmm3            // 8 16-bit words to be added for sum2 in xmm3
    imulq       $$16, adler, %rdx       // edx = 16*adler;
    movhlps     %xmm1, %xmm2            // higher 16-bit word (for adler) in xmm2   
    pmaddwd     ones, %xmm3             // 4 32-bit elements to be added for sum2 in xmm3
    paddq       %xmm2, %xmm1            // xmm1 lower 32-bit to be added to adler
    add         %rdx, sum2              // sum2 += adler*16;
    movhlps     %xmm3, %xmm2            // 2 higher 32-bit elements of xmm3 to be added to lower 2 32-bit elements
    movd        %xmm1, %edx             // to be added to adler
    paddd       %xmm2, %xmm3            // 2 32-bits elements in xmm3 to be added to sum2
    addq        %rdx, adler             // update adler
    movd        %xmm3, %edx             // to be added to sum2
    psrlq       $$32, %xmm3             // another 32-bit to be added to sum2
    addq        %rdx, sum2              // sum2 += 1st half of update
    movd        %xmm3, %edx             // to be added to sum2
    addq        %rdx, sum2              // sum2 += 2nd half of update
	.endm

	// need to fill up xmm4/xmm5/xmm6 only if len>=16
	cmpq	$16, len
	jl		0f

	// set up table starting address to %eax
	leaq    sum2_coefficients_nossse3(%rip), %rax

	// reading coefficients
	pxor	zero, zero
	movaps  (%rax), %xmm6           // coefficients for computing sum2 : pmaddubsw 16:9
    movaps  16(%rax), %xmm4         // coefficients for computing sum2 : pmaddubsw 8:1
    movaps  32(%rax), ones          // coefficients for computing sum2 : pmaddwd 1,1,...,1
0:

	cmp		$NMAX, len				// len vs NMAX
	jl		3f						// if (len < NMAX), skip the following NMAX batches processing

0:									// while (len>=NMAX) {

	sub		$NMAX, len				// 		len -= NMAX
	mov		$(NMAX/16), %eax		// 		n = NMAX/16

1:									// 		do {
	DO16_nossse3					//			update adler/sum2 for a 16-byte input
	decl 	%eax					// 			n--;
	jg		1b						//  	} while (n);

	modulo_BASE						// 		(adler/sum2) modulo BASE;

	cmp		$NMAX, len				//  
	jge		0b						// }	/* len>=NMAX */

3:

	sub		$16, len				// pre-decrement len by 16
	jl		2f						// if len < 16, skip the 16-vector code
	DO16_nossse3					// update adler/sum2 for a 16-byte input
	sub		$16, len				// len -= 16;

2:
	add		$16, len				// post-increment len by 16
	jz		1f						// if len==0, branch over scalar processing

0:									// while (len) {
	movzbq	(buf), %rdx				// 	new input byte
	incq	buf						// 	buf++
	addq	%rdx, adler				// 	adler += *buf
	addq	adler, sum2				// 	sum2 += adler
	decq	len						// 	len--
	jg		0b						// }

1:

	modulo_BASE						// (adler/sum2) modulo BASE;

	// construct 32-bit (sum2<<16 | adler) to be returned

	salq	$16, sum2				// sum2 <<16
	movq	adler, %rax				// adler		
	orq		sum2, %rax				// sum2<<16 | adler

#ifdef	KERNEL 					// if this is for kernel code, need to restore xmm registers
	movaps	-32(%rbp), %xmm0
	movaps	-48(%rbp), %xmm1
	movaps	-64(%rbp), %xmm2
	movaps	-80(%rbp), %xmm3
	movaps	-96(%rbp), %xmm4
	movaps	-112(%rbp), %xmm5
	movaps	-128(%rbp), %xmm6
	addq	$200, %rsp	// we've already restored %xmm0-%xmm11 from stack
#endif

	popq   %rbx
	leave
	ret



	.const
	.align	4
sum2_coefficients_nossse3:	// used for vectorizing adler32 computation

	// data for without ssse3

	.word   16
    .word   15
    .word   14
    .word   13
    .word   12
    .word   11
    .word   10
    .word   9
    .word   8
    .word   7
    .word   6
    .word   5
    .word   4
    .word   3
    .word   2
    .word   1

	// coefficients for pmaddwd, to combine into 4 32-bit elements for sum2
	.word	1
	.word	1
	.word	1
	.word	1
	.word	1
	.word	1
	.word	1
	.word	1


	.text

	// ----------------------------------------------------------------------------------
	// the following is the original x86_64 adler32_vec code that uses SSSE3 instructions
	// ----------------------------------------------------------------------------------

L_has_ssse3:

	// input :
	//		 adler : rdi
	//		 sum2  : rsi
	// 		 buf   : rdx
	//		 len   : rcx

	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%rbx

#ifdef	KERNEL			// if for kernel, save %xmm0-%xmm11
	subq	$200, %rsp	// allocate for %xmm0-%xmm11 (192 bytes), extra 8 to align %rsp to 16-byte boundary
	movaps	%xmm0, -32(%rbp)
	movaps	%xmm1, -48(%rbp)
	movaps	%xmm2, -64(%rbp)
	movaps	%xmm3, -80(%rbp)
	movaps	%xmm4, -96(%rbp)
	movaps	%xmm5, -112(%rbp)
	movaps	%xmm6, -128(%rbp)
	movaps	%xmm7, -144(%rbp)
	movaps	%xmm8, -160(%rbp)
	movaps	%xmm9, -176(%rbp)
	movaps	%xmm10, -192(%rbp)
	movaps	%xmm11, -208(%rbp)
#endif

	#define	adler	%rdi				// 16(%rbp)
	#define	sum2	%rsi				// 24(%ebp)
	#define	buf		%rcx				// 32(%ebp)
	#define	len		%rbx				// 40(%ebp)
	#define	zero	%xmm0
	#define ones	%xmm5

	movq	%rcx, len
	movq	%rdx, buf

	// update adler/sum2 according to a new 16-byte vector
	.macro		DO16
	movaps		(buf), %xmm1			// 16 bytes vector
	movaps		%xmm1, %xmm3			// a copy of the vector, used for unsigned byte in the destination of pmaddubsw
	addq		$$16, buf				// buf -> next vector
	psadbw		zero, %xmm1				// 2 16-bit words to be added for adler in xmm1
	pmaddubsw	%xmm4, %xmm3			// 8 16-bit words to be added for sum2 in xmm3
	imulq		$$16, adler, %rdx		// edx = 16*adler;
	movhlps		%xmm1, %xmm2			// higher 16-bit word (for adler) in xmm2 	
	pmaddwd		ones, %xmm3				// 4 32-bit elements to be added for sum2 in xmm3
	paddq		%xmm2, %xmm1			// xmm1 lower 32-bit to be added to adler
	addq		%rdx, sum2				// sum2 += adler*16;
	movhlps		%xmm3, %xmm2			// 2 higher 32-bit elements of xmm3 to be added to lower 2 32-bit elements
	movd		%xmm1, %edx				// to be added to adler
	paddd		%xmm2, %xmm3			// 2 32-bits elements in xmm3 to be added to sum2
	addq		%rdx, adler				// update adler
	movd		%xmm3, %edx				// to be added to sum2
	psrlq		$$32, %xmm3				// another 32-bit to be added to sum2
	addq		%rdx, sum2				// sum2 += 1st half of update
	movd		%xmm3, %edx				// to be added to sum2
	addq		%rdx, sum2				// sum2 += 2nd half of update
	.endm

	// update adler/sum2 according to a new 32-byte vector
	.macro		DO32
	imulq		$$32, adler, %rdx		// edx = 32*adler
	movaps		(buf), %xmm1			// 1st 16 bytes vector
	movaps		16(buf), %xmm7			// 2nd 16 bytes vector
	movaps		%xmm1, %xmm3			// a copy of 1st vector, used for unsigned byte in the destination of pmaddubsw
	movaps		%xmm7, %xmm2			// a copy of 2nd vector, used for unsigned byte in the destination of pmaddubsw
	psadbw		zero, %xmm1				// 2 16-bit words to be added for adler in xmm1
	psadbw		zero, %xmm7				// 2 16-bit words to be added for adler in xmm7
	addq		%rdx, sum2				// sum2 += adler*32;
	pmaddubsw	%xmm6, %xmm3			// 8 16-bit words to be added for sum2 in xmm3
	pmaddubsw	%xmm4, %xmm2			// 8 16-bit words to be added for sum2 in xmm2
	paddd		%xmm7, %xmm1			// 2 16-bit words to be added for adler in xmm1
	paddw		%xmm2, %xmm3			// 8 16-bit words to be added for sum2 in xmm3
	addq		$$32, buf				// buf -> vector for next iteration
	movhlps		%xmm1, %xmm2			// higher 16-bit word (for adler) in xmm2 	
	pmaddwd		ones, %xmm3				// 4 32-bit elements to be added for sum2 in xmm3
	paddq		%xmm2, %xmm1			// xmm1 lower 32-bit to be added to adler
	movhlps		%xmm3, %xmm2			// 2 higher 32-bit elements of xmm3 to be added to lower 2 32-bit elements
	movd		%xmm1, %edx				// to be added to adler
	paddd		%xmm2, %xmm3			// 2 32-bits elements in xmm3 to be added to sum2
	addq		%rdx, adler				// update adler
	movd		%xmm3, %edx				// to be added to sum2
	psrlq		$$32, %xmm3				// another 32-bit to be added to sum2
	addq		%rdx, sum2				// sum2 += 1st half of update
	movd		%xmm3, %edx				// to be added to sum2
	addq		%rdx, sum2				// sum2 += 2nd half of update
	.endm

	// update adler/sum2 according to a new 48-byte vector

	.macro		DO48
	imulq		$$48, adler, %rdx		// edx = 48*adler

	movaps		(buf), %xmm7			// 1st 16 bytes vector
	movaps		16(buf), %xmm10			// 2nd 16 bytes vector
	movaps		32(buf), %xmm11			// 3rd 16 bytes vector

	movaps		%xmm7, %xmm1			// 1st vector
	movaps		%xmm10, %xmm2			// 2nd vector
	movaps		%xmm11, %xmm3			// 3rd vector

	psadbw		zero, %xmm7				// 1st vector for adler
	psadbw		zero, %xmm10			// 2nd vector for adler
	psadbw		zero, %xmm11			// 3rd vector for adler

	addq		%rdx, sum2				// sum2 += adler*48;

	pmaddubsw	%xmm9, %xmm1			// 8 16-bit words to be added for sum2 : 1st vector
	pmaddubsw	%xmm6, %xmm2			// 8 16-bit words to be added for sum2 : 2nd vector
	pmaddubsw	%xmm4, %xmm3			// 8 16-bit words to be added for sum2 : 3rd vector

	pmaddwd		ones, %xmm1				// 4 32-bit elements to be added for sum2 in xmm1
	pmaddwd		ones, %xmm2				// 4 32-bit elements to be added for sum2 in xmm2
	pmaddwd		ones, %xmm3				// 4 32-bit elements to be added for sum2 in xmm3

	paddd		%xmm10, %xmm7			// 2 16-bit words to be added for adler 
	paddd		%xmm11, %xmm7			// 2 16-bit words to be added for adler

	paddd		%xmm1, %xmm3			// 4 32-bit elements to be added for sum2
	paddd		%xmm2, %xmm3			// 4 32-bit elements to be added for sum2

	addq		$$48, buf				// buf -> vector for next iteration

	movhlps		%xmm7, %xmm2			// higher 16-bit word (for adler) in xmm2 	
	paddq		%xmm2, %xmm7			// xmm7 lower 32-bit to be added to adler

	movhlps		%xmm3, %xmm2			// 2 higher 32-bit elements of xmm3 to be added to lower 2 32-bit elements
	movd		%xmm7, %edx				// to be added to adler
	paddd		%xmm2, %xmm3			// 2 32-bits elements in xmm3 to be added to sum2
	addq		%rdx, adler				// update adler
	movd		%xmm3, %edx				// to be added to sum2
	psrlq		$$32, %xmm3				// another 32-bit to be added to sum2
	addq		%rdx, sum2				// sum2 += 1st half of update
	movd		%xmm3, %edx				// to be added to sum2
	addq		%rdx, sum2				// sum2 += 2nd half of update
	.endm

	// update adler/sum2 according to a new 64-byte vector
	.macro		DO64
	imulq		$$64, adler, %rdx		// edx = 64*adler

	movaps		(buf), %xmm1			// 1st 16 bytes vector
	movaps		16(buf), %xmm7			// 2nd 16 bytes vector
	movaps		32(buf), %xmm10			// 3rd 16 bytes vector
	movaps		48(buf), %xmm11			// 4th 16 bytes vector

	movaps		%xmm1, %xmm3			// 1st vector
	movaps		%xmm11, %xmm2			// 4th vector
	psadbw		zero, %xmm1				// 1st vector for adler
	psadbw		zero, %xmm11			// 4th vector for adler

	addq		%rdx, sum2				// sum2 += adler*64;

	pmaddubsw	%xmm8, %xmm3			// 8 16-bit words to be added for sum2 : 1st vector
	pmaddubsw	%xmm4, %xmm2			// 8 16-bit words to be added for sum2 : 4th vector
	pmaddwd		ones, %xmm3				// 4 32-bit elements to be added for sum2 in xmm3
	pmaddwd		ones, %xmm2				// 4 32-bit elements to be added for sum2 in xmm2

	paddd		%xmm11, %xmm1			// 2 16-bit words to be added for adler in xmm1
	paddd		%xmm2, %xmm3			// 4 32-bit elements to be added for sum2 in xmm3 

	movaps		%xmm7, %xmm2			// 2nd vector
	movaps		%xmm10, %xmm11			// 3rd vector

	psadbw		zero, %xmm7				// 2nd vector for adler
	psadbw		zero, %xmm10			// 3rd vector for adler

	pmaddubsw	%xmm9, %xmm2			// 8 16-bit words to be added for sum2 : 2nd vector
	pmaddubsw	%xmm6, %xmm11			// 8 16-bit words to be added for sum2 : 3rd vector 
	pmaddwd		ones, %xmm2				// 4 32-bit elements to be added for sum2 in xmm2
	pmaddwd		ones, %xmm11			// 4 32-bit elements to be added for sum2 in xmm11

	paddd		%xmm7, %xmm1			// 2 16-bit words to be added for adler in xmm1
	paddd		%xmm10, %xmm1			// 2 16-bit words to be added for adler in xmm1

	paddd		%xmm2, %xmm3			// 4 32-bit elements to be added for sum2 in xmm3
	paddd		%xmm11, %xmm3			// 4 32-bit elements to be added for sum2 in xmm3

	addq		$$64, buf				// buf -> vector for next iteration

	movhlps		%xmm1, %xmm2			// higher 16-bit word (for adler) in xmm2 	
	paddq		%xmm2, %xmm1			// xmm1 lower 32-bit to be added to adler
	movhlps		%xmm3, %xmm2			// 2 higher 32-bit elements of xmm3 to be added to lower 2 32-bit elements
	movd		%xmm1, %edx				// to be added to adler
	paddd		%xmm2, %xmm3			// 2 32-bits elements in xmm3 to be added to sum2
	addq		%rdx, adler				// update adler
	movd		%xmm3, %edx				// to be added to sum2
	psrlq		$$32, %xmm3				// another 32-bit to be added to sum2
	addq		%rdx, sum2				// sum2 += 1st half of update
	movd		%xmm3, %edx				// to be added to sum2
	addq		%rdx, sum2				// sum2 += 2nd half of update
	.endm

	// need to fill up xmm4/xmm5/xmm6 only if len>=16
	cmpq	$16, len
	jl		skip_loading_tables

	// set up table starting address to %eax
	leaq    sum2_coefficients(%rip), %rax

	// reading coefficients
	pxor	zero, zero
	movaps	(%rax), %xmm8			// coefficients for computing sum2 : pmaddubsw 64:49
	movaps	16(%rax), %xmm9			// coefficients for computing sum2 : pmaddubsw 48:33
	movaps	32(%rax), %xmm6			// coefficients for computing sum2 : pmaddubsw 32:17
	movaps	48(%rax), %xmm4			// coefficients for computing sum2 : pmaddubsw 16:1
	movaps	64(%rax), ones			// coefficients for computing sum2 : pmaddwd 1,1,...,1

skip_loading_tables:


	cmpq	$NMAX, len				// len vs NMAX
	jl		len_lessthan_NMAX		// if (len < NMAX), skip the following NMAX batches processing

len_ge_NMAX_loop:					// while (len>=NMAX) {

	subq	$NMAX, len				// 		len -= NMAX
	movq	$(NMAX/64), %rax		// 		n = NMAX/64

n_loop:								// 		do {
	DO64							// 			update adler/sum2 for a 64-byte input
	decq 	%rax					// 			n--;
	jg		n_loop					//  	} while (n);

	DO48							//		update adler/sum2 for a 48-byte input

	modulo_BASE						// 		(adler/sum2) modulo BASE;

	cmpq	$NMAX, len				//  
	jge		len_ge_NMAX_loop		// }	/* len>=NMAX */

len_lessthan_NMAX:

	subq	$64, len				// pre-decrement len by 64
	jl		len_lessthan_64			// if len < 64, skip the 64-vector code
len64_loop:							// while (len>=64) {
	DO64							//   update adler/sum2 for a 64-byte input
	subq	$64, len				//   len -= 64;
	jge		len64_loop				// } 

len_lessthan_64:
	addq	$(64-32), len			// post-increment 64 + pre-decrement 32 of len
	jl		len_lessthan_32			// if len < 32, skip the 32-vector code
	DO32							//   update adler/sum2 for a 32-byte input
	subq	$32, len				//   len -= 32;

len_lessthan_32:

	addq	$(32-16), len			// post-increment by 32 + pre-decrement by 16 on len
	jl		len_lessthan_16			// if len < 16, skip the 16-vector code
	DO16							// update adler/sum2 for a 16-byte input
	subq	$16, len				// len -= 16;

len_lessthan_16:
	addq	$16, len				// post-increment len by 16
	jz		len_is_zero				// if len==0, branch over scalar processing

scalar_loop:						// while (len) {
	movzbq	(buf), %rdx				// 	new input byte
	incq	buf						// 	buf++
	addq	%rdx, adler				// 	adler += *buf
	addq	adler, sum2				// 	sum2 += adler
	decq	len						// 	len--
	jg		scalar_loop				// }

len_is_zero:

	modulo_BASE						// (adler/sum2) modulo BASE;

	// construct 32-bit (sum2<<16 | adler) to be returned

	salq	$16, sum2				// sum2 <<16
	movq	adler, %rax				// adler		
	orq		sum2, %rax				// sum2<<16 | adler


#ifdef	KERNEL			// if for kernel, restore %xmm0-%xmm11
	movaps	-32(%rbp), %xmm0
	movaps	-48(%rbp), %xmm1
	movaps	-64(%rbp), %xmm2
	movaps	-80(%rbp), %xmm3
	movaps	-96(%rbp), %xmm4
	movaps	-112(%rbp), %xmm5
	movaps	-128(%rbp), %xmm6
	movaps	-144(%rbp), %xmm7
	movaps	-160(%rbp), %xmm8
	movaps	-176(%rbp), %xmm9
	movaps	-192(%rbp), %xmm10
	movaps	-208(%rbp), %xmm11
	addq	$200, %rsp	// we've already restored %xmm0-%xmm11 from stack
#endif

	popq   %rbx
	leave							// pop ebp out from stack
	ret


	.const
	.align	4
sum2_coefficients:	// used for vectorizing adler32 computation

	// coefficients for pmaddubsw instruction, used to generate 16-bit elements for sum2

	.byte	64
	.byte	63
	.byte	62
	.byte	61
	.byte	60
	.byte	59
	.byte	58
	.byte	57
	.byte	56
	.byte	55
	.byte	54
	.byte	53
	.byte	52
	.byte	51
	.byte	50
	.byte	49
	.byte	48
	.byte	47
	.byte	46
	.byte	45
	.byte	44
	.byte	43
	.byte	42
	.byte	41
	.byte	40
	.byte	39
	.byte	38
	.byte	37
	.byte	36
	.byte	35
	.byte	34
	.byte	33
	.byte	32
	.byte	31
	.byte	30
	.byte	29
	.byte	28
	.byte	27
	.byte	26
	.byte	25
	.byte	24
	.byte	23
	.byte	22
	.byte	21
	.byte	20
	.byte	19
	.byte	18
	.byte	17
	.byte	16
	.byte	15
	.byte	14
	.byte	13
	.byte	12
	.byte	11
	.byte	10
	.byte	9
	.byte	8
	.byte	7
	.byte	6
	.byte	5
	.byte	4
	.byte	3
	.byte	2
	.byte	1

	// coefficients for pmaddwd, to combine into 4 32-bit elements for sum2
	.word	1
	.word	1
	.word	1
	.word	1
	.word	1
	.word	1
	.word	1
	.word	1

#endif	// (defined __i386__)

#endif	// (defined __i386__ || defined __x86_64__)
