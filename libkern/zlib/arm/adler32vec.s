#include <arm/arch.h>

#define BASE 65521	    /* largest prime smaller than 65536 */
#define NMAX 5552 		/* NMAX is the largest n such that 255n(n+1)/2 + (n+1)(BASE-1) <= 2^32-1 */

// Note: buf should have been 16-byte aligned in the caller function,

// uLong adler32_vec(unsigned int adler, unsigned int sum2, const Bytef* buf, int len) {
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
//    return adler | (sum2 << 16); 		/* return recombined sums */
// }


/* 
	DO16 vectorization:
	given initial unsigned int sum2 and adler, and a new set of 16 input bytes (x[0:15]), it can be shown that
	sum2  += (16*adler + 16*x[0] + 15*x[1] + ... + 1*x[15]);
	adler += (x[0] + x[1] + ... + x[15]);

	therefore, this is what can be done to vectorize the above computation
	1. 16-byte aligned vector load into q2 (x[0:x15])
	2. sum2 += (adler<<4);
	3. vmull.u8 (q9,q8),q2,d2 where d2 = (1,1,1,1...,1), (q9,q8) + 16 16-bit elements x[0:15]
	4. vmull.u8 (q11,q10),q2,q0 where q0 = (1,2,3,4...,16), (q11,q10) + 16 16-bit elements (16:1)*x[0:15]
	5. parallel add (with once expansion to 32-bit) (q9,q8) and (q11,q10) all the way to accumulate to adler and sum2 

	In this revision, whenever possible, 2 DO16 loops are combined into a DO32 loop.
	1. 32-byte aligned vector load into q2,q14 (x[0:x31])
    2. sum2 += (adler<<5);
    3. vmull.u8 (4 q registers),(q2,q14),d2 where d2 = (1,1,1,1...,1), (4 q registers) : 32 16-bit elements x[0:31]
	4. vmull.u8 (4 q registers),(q2,q14),(q0,q15) where q0 = (1,...,32), (4 q regs) : 32 16-bit elements (32:1)*x[0:31]
    5. parallel add (with once expansion to 32-bit) the pair of (4 q regs) all the way to accumulate to adler and sum2 

	This change improves the performance by ~ 0.55 cycle/uncompress byte on ARM Cortex-A8.

*/

/*
	MOD implementation:
	adler%BASE = adler - floor(adler*(1/BASE))*BASE; where (1/BASE) = 0x80078071 in Q47
	1. vmull.u32   q2,(adler,sum2),(1/BASE)		// *(1/BASE) in Q47
    2. vshr.u64    q2,q2,#47					// floor function
    3. vpadd.u32   d4,d4,d5						// merge into a double word in d4
    4. vmls.u32    (adler,sum2),d4,d3[0]        // (adler,sum2) -= floor[(adler,sum2)/BASE]*BASE
	 
*/

#if defined _ARM_ARCH_6			// this file would be used only for armv6 or above


	.text
	.align 2
	.globl _adler32_vec
_adler32_vec:
 
#if (!KERNEL_SUPPORT_NEON) || (!defined _ARM_ARCH_7)	// for armv6 or armv7 without neon support


	#define	adler			r0
	#define	sum2			r1
	#define	buf				r2
	#define	len				r3	
	#define	one_by_base		r4
	#define	base			r5
	#define nmax			r6
	#define	t				r12
	#define	vecs			lr
	#define	x0				r8
	#define	x1				r10
	#define	x2				r11
	#define	x3				r12
	#define	zero			r9

	// this macro performs adler/sum2 update for 4 input bytes

	.macro DO4
	add		sum2, adler, lsl #2				// sum2 += 4*adler;
	ldr		x0,[buf]						// 4 bytes in 1 32-bit word
	usada8	adler, x0, zero, adler			// adler += sum(x0:x3)
	ldrb	x0,[buf], #4					// x0
	ldrb	x2,[buf,#-2]					// x2
	ldrb	x1,[buf,#-3]					// x1
	ldrb	x3,[buf,#-1]					// x3
	add		sum2, x0, lsl #2				// sum2 += 4*x0
	add		x3, x3, x1, lsl #1				// x3+2*x1
	add		sum2, x2, lsl #1				// sum2 += 2*x2
	add		x3, x1							// x3+3*x1
	add		sum2, x3						// sum2 += x3+3*x1
	.endm

	// the following macro cascades 4 DO4 into a adler/sum2 update for 16 bytes
	.macro DO16
	DO4										// adler/sum2 update for 4 input bytes
	DO4										// adler/sum2 update for 4 input bytes
	DO4										// adler/sum2 update for 4 input bytes
	DO4										// adler/sum2 update for 4 input bytes
	.endm

	// the following macro performs adler sum2 modulo BASE
	.macro	modulo_base
	umull	x0,x1,adler,one_by_base			// adler/BASE in Q47
	umull	x2,x3,sum2,one_by_base			// sum2/BASE in Q47
	lsr		x1, #15							// x1 >> 15 = floor(adler/BASE)
	lsr		x3, #15							// x3 >> 15 = floor(sum2/BASE)
	mla		adler, x1, base, adler			// adler %= base;
	mla		sum2, x3, base, sum2			// sum2 %= base;
	.endm

	adr		t, coeffs	
	push	{r4-r6, r8-r11, lr}
	ldmia	t, {one_by_base, base, nmax}	// load up coefficients

	subs        len, nmax                   // pre-subtract len by NMAX
	eor			zero, zero					// a dummy zero register to use usada8 instruction
    blt         len_lessthan_NMAX           // if (len < NMAX) skip the while loop     

while_lengenmax_loop:						// do {
    lsr         vecs, nmax, #4              // vecs = NMAX/16;

len16_loop:									// do {

	DO16

	subs	vecs, #1						// vecs--;
	bgt			len16_loop					// } while (vec>0);	

	modulo_base								// adler sum2 modulo BASE

	subs		len, nmax					// len -= NMAX
	bge			while_lengenmax_loop		// } while (len >= NMAX);

len_lessthan_NMAX:
	adds		len, nmax					// post-subtract len by NMAX

	subs		len, #16					// pre-decrement len by 16
	blt			len_lessthan_16

len16_loop2:

	DO16

	subs		len, #16
	bge			len16_loop2

len_lessthan_16:
	adds		len, #16					// post-increment len by 16
	beq			len_is_zero

remaining_buf:
	ldrb		x0, [buf], #1
	subs		len, #1
	add			adler, x0
	add			sum2, adler
	bgt			remaining_buf

len_is_zero:

	modulo_base 							// adler sum2 modulo BASE

	add		r0, adler, sum2, lsl #16		// to return sum2<<16 | adler 

	pop		{r4-r6, r8-r11, pc}

	.align 2
coeffs:
	.long	-2146992015
	.long	-BASE
	.long	NMAX

#else	// KERNEL_SUPPORT_NEON



	#define	adler	r0
	#define	sum2	r1
	#define	buf		r2
	#define	len		r3	
	#define	nmax	r4
	#define	vecs	lr				// vecs = NMAX/16
	#define	n		r5

	#define	t		r12

	#define	sum2_coeff		q0
	#define	sum2_coeff0		d0
	#define	sum2_coeff1		d1
	#define	alder_coeff		q1
	#define	ones			d2
	#define	x0_x15			q2
	#define	x0_x7			d4
	#define	x8_x15			d5
	#define	adlersum2		d6
	#define	adler16			d25

#if defined _ARM_ARCH_7 

	adr			t, vec_table				// address to vec_table[]
	stmfd		sp!, {r4, r5, lr}

	vld1.32		{q0-q1},[t,:128]!			// loading up coefficients for adler/sum2 computation
	vld1.32		{q15},[t,:128]!				// for sum2 computation
	ldr			nmax, [t]					// NMAX

	vmov		adlersum2, sum2, adler		// pack up adler/sum2 into a double register 

	cmp			len, nmax					// len vs NMAX
	lsr			vecs, nmax, #4				// vecs = NMAX/16;
	blt			len_lessthan_NMAX			// if (len < NMAX) skip the while loop		

	sub			len, nmax					// pre-decrement len by NMAX

while_len_ge_NMAX_loop: 					// while (len>=NMAX) {

	mov			n, vecs, lsr #1			// n = NMAX/16; 

do_loop:									// do {

	vshll.u32	q12, adlersum2, #5			// d25 = (0,32*adler) to be added into (adler,sum2)
	vld1.32		{x0_x15},[buf,:128]!		// 16-byte input x0:x15
	vmull.u8	q8, x0_x7, ones				// 16-bit x0-x7
	vld1.32		{q14}, [buf,:128]!			// x16:x31
	vmull.u8	q9, x8_x15, ones			// 16-bit x8-x15
	vadd.u32	adlersum2,adler16			// sum2 += old adler*32;
	vmull.u8	q12, d28, ones				// 16-bit x16-x23
	vmull.u8	q13, d29, ones				// 16-bit x24-x31
	vmull.u8	q10, d28, sum2_coeff0		// 16-bit x16*16, x17*15, ..., x23*9
	vmull.u8	q11, d29, sum2_coeff1		// 16-bit x24*8, x25*7, ..., x31*1	
	vadd.u16	q8, q8, q9					// q8 = (x0+x8):(x7+x15) 8 16-bit elements for adler
	vmull.u8	q9, x0_x7, d30				// 16-bit x0*32,...,x7*25
	vmull.u8	q14, x8_x15, d31			// 16-bit x8*24,...,x15*17
	vadd.u16	q12, q12, q13				// q12 = (x16+x24):(x23+x31) 8 16-bit elements for adler
	vadd.u16	q10, q11					// 8 16-bit elements for sum2
	vadd.u16	q8, q12						// 8 16-bit elements for adler
	vadd.u16	q9, q14						// 8 16-bit elements for sum2 
	vadd.u16	q10, q9						// 8 16-bit elements for sum2
	vpaddl.u16	q8, q8						// 4 32-bit elements for adler
	vpaddl.u16	q10, q10					// 4 32-bit elements for sum2
	vpadd.u32	d16,d16,d17					// 2 32-bit elements for adler
	vpadd.u32	d17,d20,d21					// 2 32-bit elements for sum2
	subs		n, #1						//  --n 
	vpadd.u32	d4,d17,d16					// s8 : 32-bit elements for sum2, s9 : 32-bit element for adler
	vadd.u32	adlersum2,d4				// update adler/sum2 with the new 16 bytes input

	bgt			do_loop						// } while (--n);

	vshll.u32	q12, adlersum2, #4			// d25 = (0,16*adler) to be added into (adler,sum2)

	vld1.32		{x0_x15},[buf,:128]!		// 	16-byte input

	vmull.u8	q8, x0_x7, ones				// 16-bit x0-x7
	vmull.u8	q9, x8_x15, ones			// 16-bit x8-x15
	vmull.u8	q10, x0_x7, sum2_coeff0		// 16-bit x0*16, x1*15, ..., x7*9
	vmull.u8	q11, x8_x15, sum2_coeff1	// 16-bit x8*8, x9*7, ..., x15*1	

	vadd.u16	q8, q8, q9					// 8 16-bit elements for adler
	vadd.u16	q10, q10, q11				// 8 16-bit elements for sum2
	vpaddl.u16	q8, q8						// 4 32-bit elements for adler
	vpaddl.u16	q10, q10					// 4 32-bit elements for sum2
	vpadd.u32	d16,d16,d17					// 2 32-bit elements for adler
	vpadd.u32	d17,d20,d21					// 2 32-bit elements for sum2
	vadd.u32	adlersum2,adler16			// sum2 += old adler;
	vpadd.u32	d4,d17,d16					// s8 : 32-bit elements for sum2, s9 : 32-bit element for adler
	vadd.u32	adlersum2,d4				// update adler/sum2 with the new 16 bytes input

	// mod(alder,BASE); mod(sum2,BASE);
	vmull.u32	q2,adlersum2,d3[1]			// alder/BASE, sum2/BASE in Q47
	vshr.u64	q2,q2,#47					// take the integer part
	vpadd.u32	d4,d4,d5					// merge into a double word in d4
	vmls.u32	adlersum2,d4,d3[0]			// (adler,sum2) -= floor[(adler,sum2)/BASE]*BASE

	subs		len, nmax					// len -= NMAX;
	bge			while_len_ge_NMAX_loop		// repeat while len >= NMAX

	add			len, nmax					// post-increment len by NMAX

len_lessthan_NMAX:

	cmp			len, #0
	beq			len_is_zero					// if len==0, branch to skip the following


	subs		len, #32					// pre-decrement len by 32
	blt			len_lessthan_32				// if len < 32, branch to len16_loop 

len32_loop:

	vshll.u32	q12, adlersum2, #5			// d25 = (0,32*adler) to be added into (adler,sum2)
	vld1.32		{x0_x15},[buf,:128]!		// 16-byte input x0:x15
	vmull.u8	q8, x0_x7, ones				// 16-bit x0-x7
	vld1.32		{q14}, [buf,:128]!			// x16:x31
	vmull.u8	q9, x8_x15, ones			// 16-bit x8-x15
	vadd.u32	adlersum2,adler16			// sum2 += old adler*32;
	vmull.u8	q12, d28, ones				// 16-bit x16-x23
	vmull.u8	q13, d29, ones				// 16-bit x24-x31
	vmull.u8	q10, d28, sum2_coeff0		// 16-bit x16*16, x17*15, ..., x23*9
	vmull.u8	q11, d29, sum2_coeff1		// 16-bit x24*8, x25*7, ..., x31*1	
	vadd.u16	q8, q8, q9					// q8 = (x0+x8):(x7+x15) 8 16-bit elements for adler
	vmull.u8	q9, x0_x7, d30				// 16-bit x0*32,...,x7*25
	vmull.u8	q14, x8_x15, d31			// 16-bit x8*24,...,x15*17
	vadd.u16	q12, q12, q13				// q12 = (x16+x24):(x23+x31) 8 16-bit elements for adler
	vadd.u16	q10, q11					// 8 16-bit elements for sum2
	vadd.u16	q8, q12						// 8 16-bit elements for adler
	vadd.u16	q9, q14						// 8 16-bit elements for sum2 
	vadd.u16	q10, q9						// 8 16-bit elements for sum2
	vpaddl.u16	q8, q8						// 4 32-bit elements for adler
	vpaddl.u16	q10, q10					// 4 32-bit elements for sum2
	vpadd.u32	d16,d16,d17					// 2 32-bit elements for adler
	vpadd.u32	d17,d20,d21					// 2 32-bit elements for sum2
	subs		len, #32					// len -= 32; 
	vpadd.u32	d4,d17,d16					// s8 : 32-bit elements for sum2, s9 : 32-bit element for adler
	vadd.u32	adlersum2,d4				// update adler/sum2 with the new 16 bytes input

	bge			len32_loop

len_lessthan_32:

	adds		len, #(32-16)				// post-increment len by 32, then pre-decrement by 16
	blt			len_lessthan_16				// if len < 16, branch to len_lessthan_16

	vshll.u32	q12, adlersum2, #4			// d25 = (0,16*adler) to be added into (adler,sum2)

	vld1.32		{x0_x15},[buf,:128]!		// 	16-byte input


	vmull.u8	q8, x0_x7, ones				// 16-bit x0-x7
	vmull.u8	q9, x8_x15, ones			// 16-bit x8-x15
	vmull.u8	q10, x0_x7, sum2_coeff0		// 16-bit x0*16, x1*15, ..., x7*9
	vmull.u8	q11, x8_x15, sum2_coeff1	// 16-bit x8*8, x9*7, ..., x15*1	

	vadd.u16	q8, q8, q9					// 8 16-bit elements for adler
	vadd.u16	q10, q10, q11				// 8 16-bit elements for sum2
	vpaddl.u16	q8, q8						// 4 32-bit elements for adler
	vpaddl.u16	q10, q10					// 4 32-bit elements for sum2
	vpadd.u32	d16,d16,d17					// 2 32-bit elements for adler
	vpadd.u32	d17,d20,d21					// 2 32-bit elements for sum2
	subs		len, #16					// decrement len by 16
	vadd.u32	adlersum2,adler16			// sum2 += old adler;
	vpadd.u32	d4,d17,d16					// s8 : 32-bit elements for sum2, s9 : 32-bit element for adler
	vadd.u32	adlersum2,d4				// update adler/sum2 with the new 16 bytes input

len_lessthan_16:
	adds		len, #16					// post-increment len by 16
	beq			len_is_zero_internal		// if len==0, branch to len_is_zero_internal

	// restore adler/sum2 into general registers for remaining (<16) bytes

	vmov		sum2, adler, adlersum2
remaining_len_loop:
	ldrb		t, [buf], #1				// *buf++;
	subs		len, #1						// len--;
	add			adler,t						// adler += *buf
	add			sum2,adler					// sum2 += adler
	bgt			remaining_len_loop			// break if len<=0

	vmov		adlersum2, sum2, adler		// move to double register for modulo operation

len_is_zero_internal:

	// mod(alder,BASE); mod(sum2,BASE);

	vmull.u32	q2,adlersum2,d3[1]			// alder/BASE, sum2/BASE in Q47
	vshr.u64	q2,q2,#47					// take the integer part
	vpadd.u32	d4,d4,d5					// merge into a double word in d4
	vmls.u32	adlersum2,d4,d3[0]			// (adler,sum2) -= floor[(adler,sum2)/BASE]*BASE

len_is_zero:

	vmov        sum2, adler, adlersum2		// restore adler/sum2 from (s12=sum2, s13=adler)
	add			r0, adler, sum2, lsl #16	// to return adler | (sum2 << 16);
	ldmfd       sp!, {r4, r5, pc}			// restore registers and return 


	// constants to be loaded into q registers
	.align	4		// 16 byte aligned

vec_table:

	// coefficients for computing sum2
	.long	0x0d0e0f10		// s0
	.long	0x090a0b0c		// s1
	.long	0x05060708		// s2
	.long	0x01020304		// s3

	// coefficients for computing adler
	.long	0x01010101		// s4/d2
	.long	0x01010101		// s5

	.long	BASE			// s6 : BASE 
	.long	0x80078071		// s7 : 1/BASE in Q47

	// q15 : d30.d31
	.long	0x1d1e1f20		// s0
	.long	0x191a1b1c		// s1
	.long	0x15161718		// s2
	.long	0x11121314		// s3

NMAX_loc:
	.long	NMAX			// NMAX
	
#endif		// _ARM_ARCH_7

#endif		//  (!KERNEL_SUPPORT_NEON) || (!defined _ARM_ARCH_7)

#endif		// _ARM_ARCH_6

