#include <arm/arch.h>

// the follow assembly code was hard wired to POSTINC not defined, 

#if 0			// #ifdef POSTINC
#  define OFF 0
#  define PUP(a) *(a)++
#else
#  define OFF 1
#  define PUP(a) *++(a)
#endif

// the code uses r9, therefore, it does not meet the register protocol for armv5 and below
// the code can only be used for armv6 and above

#if defined _ARM_ARCH_6 

	.cstring
	.align 2
LC0:
	.ascii "invalid distance too far back\0"
	.align 2
LC1:
	.ascii "invalid distance code\0"
	.align 2
LC2:
	.ascii "invalid literal/length code\0"

	// renaming the register and stack memory use

	#define		out			r0
	#define		strm		r10
	#define		state		r5
	#define		in			r11
	#define		write		r9
	#define		distcode	r8
	#define		bits		lr
	#define		hold		r4

	// stack memory allocation

	#define		window_loc	[sp,#0]
	#define		last_loc	[sp,#4]
	#define		beg_loc		[sp,#8]
	#define		end_loc		[sp,#12]
	#define		wsize_loc	[sp,#16]
	#define		whave_loc	[sp,#20]
	#define		windowm1_loc	[sp,#28]
	#define		lmask_loc	[sp,#32]
	#define		dmask_loc	[sp,#36]
	#define		op_loc		[sp,#44]
	#define		dist_loc	[sp,#48]

	#define		local_size	52

	// the following defines the variable offset in the inflate_state structure	(in inflate.h)

	#define		state_mode		[state, #0]
	#define		state_last		[state, #4]
	#define		state_wrap		[state, #8]
	#define		state_havedict	[state, #12]
	#define		state_flags		[state, #16]
	#define		state_dmax		[state, #20]
	#define		state_wbits		[state, #36]
	#define		state_wsize		[state, #40]
	#define		state_whave		[state, #44]
	#define		state_write		[state, #48]
	#define		state_window	[state, #52]
	#define		state_hold		[state, #56]
	#define		state_bits		[state, #60]
	#define		state_lencode	[state, #76]
	#define		state_distcode	[state, #80]
	#define		state_lenbits	[state, #84]
	#define		state_distbits	[state, #88]


// void inflate_fast(z_streamp strm, unsigned start)
// input : 	
//			r0 = strm, (move to r10) 
//			r1 = start	

	.text
	.align 2
	.globl _inflate_fast
_inflate_fast:

	stmfd	sp!, {r4-r6,r8-r11,lr}
	sub		sp, sp, #local_size

#if defined(_ARM_ARCH_5)
	ldrd	r2,r3,[r0, #0]			// r2 = strm->next_in, r3 = strm->avail_in
#else
	ldmia	r0, {r2-r3}
#endif

	sub		in, r2, #OFF			// in = strm->next_in - OFF; 
	sub		r2, #(OFF+5)			// next_in -= (OFF+5);
	ldr		state, [r0, #28]		// state = (struct inflate_state FAR *)strm->state;
	add		r3, r3, r2				// last = next_in - OFF + (avail_in - 5);	next_in already updated
	mov		strm, r0
	str		r3, last_loc			// store last to release r3

	ldr		r3, [r0, #12]			// next_out
	ldr		r2, [strm, #16]			// avail_out

	sub		out, r3, #OFF			// out = strm->next_out - OFF; r0 is used as out from this point on

	sub		r3, r3, #256			// next_out - 256
	rsb		r1, r2, r1				// start - avail_out
	sub		r3, r3, #(1+OFF)		// next_out-OFF-257 
	add		r3, r3, r2				// r3 = end = avail_out + (next_out-OFF) - 257 = avail_out + out - 257
	rsb		r2, r1, out				// r2 = beg = out - (start - avail_out);
#if defined(_ARM_ARCH_5)
	strd	r2,r3, beg_loc			// store beg/end
	ldrd	r2,r3, state_wsize		// wsize/whave
	strd	r2,r3, wsize_loc		// store wsize/whave
	//ldrd	r6,hold, state_window	// window/hold, hold use r7
	ldr		r6, state_window		// state->window
	ldr		hold, state_hold		// state->hold
	nop
#else
	// for architecture < armv5, ldrd/strd is not available
	str		r2, beg_loc				// store beg
	str		r3, end_loc				// store end
	ldr		r2, state_wsize			// state->wsize
	ldr		r3, state_whave			// state->whave
	str		r2, wsize_loc			// store wsize
	str		r3, whave_loc			// store whave
	ldr		r6, state_window		// state->window
	ldr		hold, state_hold		// state->hold
#endif

	ldr		ip, state_lencode		// lencode
	mov		r3, #1					// used to derive lmask and dmask
	ldr		write, state_write		// write (r9 from this point on) : window write index
	nop
	str		ip, [sp, #40]			// save lencode
	sub		ip, r6, #1				// window-1
	str		r6, window_loc			// store window
	str		ip, windowm1_loc		// store window-1
	ldr		r2, state_lenbits		// lenbits
	ldr		bits, state_bits		// bits, use lr from this point on
	ldr		distcode, state_distcode// distcode, use r8
	mov		r2, r3, asl r2			// (1<<lensbits)
	ldr		r12, state_distbits		// distbits
	sub		r2, r2, #1				// lmask = (1U << state->lenbits) - 1;
	mov		r3, r3, asl r12			// (1U << state->distbits)
	sub		r3, r3, #1				// dmask = (1U << state->distbits) - 1;

#if defined(_ARM_ARCH_5)
	strd	r2, r3, lmask_loc		// store lmask/dmask
#else
	str		r2, lmask_loc			// lmask
	str		r3, dmask_loc			// dmask
#endif

	// start the do loop decoding literals and length/distances 
	// until end-of-block or not enough input data or output space

do_loop:
	cmp		bits, #15				// bits vs 15
	ldr		r1, lmask_loc			// lmask
	bge		bitsge15				// if bits >= 15, skip loading new 16 bits	

	// this is a shortcut with the processor reads data in little-endian mode
	ldrh	r3, [in,#1]					// read 2 bytes 
	add		in, #2						// in pointer += 2
	add		hold, hold, r3, asl bits	// deposit the new 2 bytes into hold
	add		bits, #16					// bits count += 16

bitsge15:
	ldr		ip, [sp, #40]			// restore lencode
	and		r3, hold, r1				// r3 = hold & lmask
	b		dolen

op_not_zero:

	tst	r2, #16							// if (op&16)
	bne	length_base						// 		branch to length_base

	tst	r2, #64							// else if (op&64) 
	bne	end_of_block					// 		branch to end_of_block processing 

	// 2nd-level length code, this is the part where if ((op & 64) == 0) { ... }

	// this.val + (hold & ((1U << op) - 1)); 
	// r3 = r1 + hold & ((1<<r2)-1);

	rsb		r12, r2, #32				// r12 = (32-op)
	ror 	r3, hold, r2				// rotate the op least significant bits of hold to MSB
	add		r3, r1, r3, lsr r12			// r3 = r1 + (op LSBs in hold) = r1 + hold & ((1<<r2)-1); 

	ldr		ip, [sp, #40]			// restore lencode

dolen:

	// code -> 8-bit code, 8-bit bits, 16-bit val
	ldrb	r2, [ip,r3,asl #2]		// op = (unsigned)(this.bits);
	add		r3, ip, r3, asl #2		// r3 = this
	ldrb	ip, [r3, #1]				// ip = this.bits
	ldrh	r1, [r3, #2]				// r1 = this.value
	cmp		r2, #0						// op == 0 ?

	mov		hold, hold, lsr ip			// hold >>= this.bits
	rsb		bits, ip, bits				// bits -= this.bits
	bne		op_not_zero					// branch to op_not_zero if this.op != 0

	strb	r1, [out, #1]!				// PUP(out) = (unsigned char)(this.val);

do_loop_while:
	ldr		r1, last_loc				// last
	ldr		r2, end_loc					// end
	cmp		in, r1						// compare in vs last 
	cmpcc	out, r2						// if in < last, compare out vs end
	bcc		do_loop						// if (in < last && out < end) go back to do_loop

update_state_and_return:

	sub		r2, in, bits, lsr #3		// r2 = in - (bits>>3)

	add		r3, r2, #OFF				// r3 = (in - (bits>>3)) + OFF
	str		r3, [strm, #0]				// strm->next_in = in + OFF;

	add		r3, out, #OFF				// out + OFF
	str		r3, [strm, #12]				// strm->next_out = out + OFF;

	ldr		r3, last_loc				// r3 = last
	ldr		ip, end_loc					// ip = end

	cmp		r3, r2						// compare last vs in
	addhi	r3, r3, #5					// if last > in, last +=5
	movls	r6, r3						// o.w., r6 = last
	rsbls	r3, r6, r2					//       r3 = in-last
	rsbhi	r3, r2, r3					// r3 = (last+5) - in
	rsbls	r3, r3, #5					// r3 = 5 - (in-last);
	cmp		out, ip						// compare out vs end
	str		r3, [strm, #4]				// strm->avail_in = (unsigned)(in < last ? 5 + (last - in) : 5 - (in - last));
	movcs	r2, ip						// if out<end, r2=end
	addcc	r3, ip, #256				// if out>=end, r3 = end+256
	rsbcs	r3, r2, out					// if out<end, r3 = out-end
	addcc	r3, r3, #1					// if out>=end, r3 = end+257
	rsbcs	r3, r3, #256				// if out<end, r3 = 256-(out-end) = 256 + (end-out)
	and		bits, #7					// this is equivalent to bits -= (bits>>3) << 3;
	rsbcc	r3, out, r3					// if out<end, r3 = 257+end-out
	addcs	r3, r3, #1					// if out>=end, r3 = 257 + (end-out)
	str		r3, [strm, #16]				// strm->avail_out = (unsigned)(out < end ?  257 + (end - out) : 257 - (out - end)); 

	// hold &= (1U << bits) - 1;

	rsb		ip, bits, #32				// 32-bits
    ror 	hold, hold, bits			// this is equivalent to hold<<(32-bits)
    lsr 	hold, hold, ip				// logical shift right by (32-bits), hold now only keeps the bits LSBs

	str		bits, state_bits			// state->bits = bits;
	str		hold, state_hold			// state->hold = hold;

	add		sp, #local_size				// pop out stack memory
	ldmfd	sp!,{r4-r6,r8-r11,pc}				// restore registers and return

length_base:							// r2=op, r1=lmask
	ands	r2, r2, #15					// op&=15;
	mov		r6, r1						// len = (unsigned) this.val;
	beq		op_is_zero					// if op==0, branch to op_is_zero
	cmp		r2, bits					// op vs bits
	ldrhib	r3, [in, #1]!				// if (op>bits) r3 = (PUP(in));
	addhi	hold, hold, r3, asl bits	// if (op>bits) hold += (unsigned long)(PUP(in)) << bits;

	rsb		ip, r2, #32					// 32-op
    ror 	r3, hold, r2				// (hold<<(32-op))
	add		r6, r1, r3, lsr ip			// len += (unsigned)hold & ((1U << op) - 1);

	addhi	bits, bits, #8				// if (op>bits) bits += 8;

	mov		hold, hold, lsr r2			// hold >>= op;
	rsb		bits, r2, bits				// bits -= op;

op_is_zero:
	cmp		bits, #14
	ldrh    r3,[in,#1]                  // if (bits < 15) { 2 (PUP(in));  no condition code for better performance
    addls   in, #2                      // 	in+=2;
    addls   hold, hold, r3, asl bits    // 	twice hold += (unsigned long)(PUP(in)) << bits;
    addls   bits, #16                   // 	2 bits += 8; }

dodist:

	ldr		r2, dmask_loc				// r2 = dmask
	and		r3, hold, r2				// r3 = hold & dmask
	mov		r2, r3, asl #2
	add		r3, r2, distcode			// &dcode[hold&dmask];
	ldrb	ip, [r2, distcode]			// op
	ldrh	r1, [r3, #2]				// dist = (unsigned)(this.val);
	tst		ip, #16						// op vs 16
	ldrb	r3, [r3, #1]				// this.bits
	mov		hold, hold, lsr r3			// hold >>= this.bits;
	rsb		bits, r3, bits				// bits -= this.bits;
	bne		distance_base				// if (op&16) { distance base processing  }	
	tst		ip, #64						// 
	beq		second_distance_code		// else if ((op&64)==0) branch to 2nd level distance code

	b		invalide_distance_code

check_2nd_level_distance_code:

	tst		r2, #64						// check for esle if ((op & 64) == 0) for 2nd level distance code
	bne		invalide_distance_code

second_distance_code:

	rsb		r2, ip, #32					// 32-op
	ror		r3, hold, ip				// hold<<(32-op)
	add		r3, r1, r3, lsr r2			// this.val + (hold & ((1U << op) - 1))

	mov		r2, r3, asl #2
	add		r3, r2, distcode			// this = dcode[this.val + (hold & ((1U << op) - 1))];
	ldrb	r2, [r2, distcode]			// this.op
	ldrh	r1, [r3, #2]				// this.val

	tst		r2, #16						// op&16
	ldrb	r3, [r3, #1]				// this.bits
	mov		ip, r2						// op
	mov		hold, hold, lsr r3			// hold >> = this.bits
	rsb		bits, r3, bits				// bits -= this.bits
	beq		check_2nd_level_distance_code

distance_base:			// this is invoked from if ((op&16)!=0)

	and		r2, ip, #15					// op &= 15;
	cmp		r2, bits					// op vs bits
	ldrhib	r3, [in, #1]!				// if (op > bits) (PUP(in))
	addhi	hold, hold, r3, asl bits	// 		hold += (unsigned long)(PUP(in)) << bits;
	addhi	bits, bits, #8				//		bits += 8;	
	cmphi	r2, bits					// 		internel (bits < op)
	ldrhib	r3, [in, #1]!				//		if (op > bits) (PUP(in))
	addhi	hold, hold, r3, asl bits	//			hold += (unsigned long)(PUP(in)) << bits;
	addhi	bits, bits, #8				//			bits += 8

	rsb		ip, r2, #32					// (32-op)
	ror		r3, hold, r2				// hold<<(32-op)
	add		r3, r1, r3, lsr ip			// dist += (unsigned)hold & ((1U << op) - 1);
	str		r3, dist_loc				// save dist


#ifdef INFLATE_STRICT
	ldr     r1, state_dmax						// r1 = dmax
	cmp		r3, r1								// dist vs dmax	
	bgt		invalid_distance_too_far_back		// if dist > dmax, set up msg/mode = bad and break
#endif

	mov		hold, hold, lsr r2			// hold >>= op ;
	rsb		bits, r2, bits				// bits -= op;

	ldr		ip, beg_loc					// beg
	ldr		r1, dist_loc				// dist
	rsb		r3, ip, out					// (out - beg);

	cmp		r1, r3						// dist vs (out - beg) 

	rsbls	r2, r1, out					// if (dist<=op) r2 = from = out-dist
	bls		copy_direct_from_output		// if (dist<=op) branch to copy_direct_from_output

	ldr		r2, whave_loc					// whave
	rsb		r1, r3, r1						// op = dist-op
	cmp		r2, r1							// whave vs op
	str		r1, op_loc						// save a copy of op
	bcc		invalid_distance_too_far_back	// if whave < op,  message invalid distance too far back, and break

	cmp		write, #0						// write
	bne		non_very_common_case			// if (write ==0) non_very_common_case

	// the following : if (write == 0) { /* very common case */ }
	ldr		r1, op_loc						// restore op in r1
	ldr		ip, wsize_loc					// wsize
	cmp		r6, r1							// len vs op 
	rsb		r3, r1, ip						// wsize - op
	ldr		ip, windowm1_loc				// window - 1
	add		r2, ip, r3						// from = window - 1 + wsize - op : setup for using PUP(from)
	//movhi	r3, r1							// if len > op, r3 = op
	//movhi	r1, out							// if len > op, r1 = out
	bhi		some_from_window				// if (len > op), branch to some_from_window

finish_copy:

	//	while (len > 2) { 
	//		PUP(out) = PUP(from); 
	//		PUP(out) = PUP(from); 
	//		PUP(out) = PUP(from); 
	//		len -= 3; 
	//	} 
	//	if (len) { 
	//		PUP(out) = PUP(from); 
	//		if (len > 1) 
	//		PUP(out) = PUP(from); 
	//	}

	cmp		r6, #2							// len > 2 ?
	movls	r1, r6							// if (len<=2) r1 = len
	bls		lenle2							// if (len<=2) branch to lenle2
	mov		r1, r6
fcopy_per3bytes:
	ldrb	r3, [r2, #1]					// 1st PUP(from)
	sub		r1, r1, #3						// len-=3
	cmp		r1, #2							// len > 2 ?
	strb	r3, [out, #1]					// 1st PUP(out) = PUP(from);
	ldrb	r3, [r2, #2]					// 2nd PUP(from)
	add		r2, r2, #3						// from+=3
	strb	r3, [out, #2]					// 2nd PUP(out) = PUP(from);
	ldrb	r3, [r2, #0]					// 3rd PUP(from)
	add		out, out, #3					// out+=3
	strb	r3, [out, #0]					// 3rd PUP(out) = PUP(from);
	bgt		fcopy_per3bytes					// while (len>3) back to loop head	
lenle2:
	cmp		r1, #0							// len
	beq		do_loop_while					// back to while loop head if len==0	
	ldrb	r3, [r2, #1]					// PUP(from)
	cmp		r1, #2							// check whether len==2
	strb	r3, [out, #1]!					// PUP(out) = PUP(from);
	bne		do_loop_while					// back to while loop head if len==1 
	ldrb	r3, [r2, #2]					// 2nd PUP(from)
	strb	r3, [out, #1]!					// 2nd PUP(out) = PUP(from);
	b		do_loop_while					// back to while loop head

end_of_block:
	tst		r2, #32						// if (op&32)
	movne	r3, #11						//   TYPE?
	strne	r3, state_mode				// state-mode = TYPE
	bne		update_state_and_return		// break the do loop and branch to get ready to return
	ldr		r3, messages				// "invalid literal/length code" message
L75:
	add		r3, pc, r3
	str		r3, [strm, #24]				// strm->msg = (char *)"invalid literal/length code";
	mov		r3, #27						// BAD?
	str		r3, state_mode				// state->mode = BAD;
	b		update_state_and_return		// break the do loop and branch to get ready to return

//Read_2_bytes:
//	ldrh	r3,[in,#1]					// 2 (PUP(in)) together
//	add		in, #2						// 2 in++
//	add		hold, hold, r3, asl bits	// twice hold += (unsigned long)(PUP(in)) << bits;
//	add		bits, #16					// 2 bits += 8;
//	b		dodist						// branch to dodist 
	nop									// a pad dummy instruction to give better performance

copy_direct_from_output:				// r2 = from = out - dist ;

										// do {
	ldrb	r3, [r2, #1]				// 	1st PUP(from)
	sub		r6, r6, #3					// 	len-=3
	cmp		r6, #2						// 	len vs 2
	strb	r3, [out, #1]				// 	1st PUP(out) = PUP(from);
	ldrb	r3, [r2, #2]				// 	2nd PUP(from)
	add		r2, r2, #3					// 	update from+=3
	strb	r3, [out, #2]				// 	2nd PUP(out) = PUP(from);
	ldrb	r3, [r2, #0]				// 	3rd PUP(from);
	add		out, out, #3				// 	update out+=3
	strb	r3, [out, #0]				// 	3rd PUP(out) = PUP(from);
	bhi		copy_direct_from_output		// while (len>2);

	// len in r6 can now be 0 1 or 2

	subs    r6,#1						// len--;
    ldrb    r3, [r2, #1]				// PUP(from)
    blt     do_loop_while				// if len<0 back to while loop head
    strb    r3, [out, #1]!				// PUP(out) = PUP(from);
    subs    r6, #1						// len--;
    ldrb    r3, [r2, #2]				// 2nd PUP(from)
    blt     do_loop_while				// if len<0 back to while loop head
    strb    r3, [out, #1]!				// 2nd PUP(out) = PUP(from);
    b       do_loop_while				// back to while loop head


invalide_distance_code:
	ldr		r3, messages+4				// "invalid distance code"
L72:
	add		r3, pc, r3
	str		r3, [strm, #24]				// strm->msg = (char *)"invalid distance code";
	mov		r3, #27
	str		r3, state_mode				// state->mode = BAD;
	b		update_state_and_return		// break, restore registers, and return


some_from_window:
	ldr		r3, dist_loc				// dist
	rsb		r6, r1, r6					// len -= op 
some_from_window_loop:					// do {
	ldrb	ip, [r2, #1]!				// 		PUP(from);
	subs	r1, #1						//		--op	
	strb	ip, [out, #1]!				//		PUP(out) = PUP(from);
	bne		some_from_window_loop		// } while(op);
	rsb		r2, r3, out					// from = out - dist;
	b		finish_copy

non_very_common_case:
	ldr		r1, op_loc					// restore op in r1
	cmp		write, r1					// write vs op
	bcs		contiguous_in_window 		// if (write >= op) branch to contiguous_in_window

	/* wrap around window */

	ldr		r2, wsize_loc				// wsize
	ldr		ip, windowm1_loc			// window-1
	add		r3, write, r2				// r3 = wsize+write
	rsb		r3, r1, r3					// r3 = wsize+write-op
	add		r2, ip, r3					// r2 = from = wsize+write-op+window-1;
	rsb		r1, write, r1				// op -= write;

	cmp		r6, r1						// len vs op
	bls		finish_copy					// if (len <= op) branch to finish_copy
	rsb		r6, r1, r6					// len -= op
waw_loop:								// do {
	ldrb	r3, [r2, #1]!				// 	PUP(from)
	subs	r1, r1, #1					//  --op; 
	strb	r3, [out, #1]!				//  PUP(out) = PUP(from);
	bne		waw_loop					// } while (op); 

	cmp		write, r6					// write vs len
	ldr		r2, windowm1_loc			// if (write>=len) r2 = from = window-1;
	bcs		finish_copy					// if (write>=len) branch to finish_copy

	// some from start of window

	mov		r1, write				// op = write
	sub		r6, write				// len -= op
sow_loop:							// do { 
	ldrb	r3,[r2, #1]!			// 	PUP(from)
	subs	r1, #1					//  --op;
	strb	r3, [out,#1]!			//  PUP(out) = PUP(from);
	bne		sow_loop				// } while (op);

	ldr		r2, dist_loc			// dist
	rsb		r2, r2, out				// r2 = from = out-dist
	b		finish_copy				// continue to finish_copy


contiguous_in_window:
	ldr		ip, windowm1_loc		// window-1
	cmp		r6, r1					// len vs op
	rsb		r3, r1, write			// r3 = write-op
	add		r2, ip, r3				// r2 = from = window+write-op-1
	bls		finish_copy				// if (len <= op) branch to finish_copy
	rsb		r6, r1, r6				// len -= op 
	ldr		r3, dist_loc			// dist
ciw_loop:
	ldrb	ip, [r2, #1]!			// PUP(from)
	subs	r1, r1, #1				// op--
	strb	ip, [out, #1]!			// PUP(out) = PUP(from);
	bne		ciw_loop				// while (--op); 
	rsb		r2, r3, out				// from = out - dist;
	b		finish_copy

invalid_distance_too_far_back:
	ldr		r3, messages+8					// "invalid distance too far back"
L42:
	add		r3, pc, r3
	str		r3, [strm, #24]					// strm->msg = (char *)"invalid distance too far back";
	mov		r3, #27
	str		r3, state_mode					// state->mode = BAD;
	b		update_state_and_return			// break, restore registers, and return

	.align 2
messages:
	.long	LC2-8-(L75)
	.long	LC1-8-(L72)
	.long	LC0-8-(L42)

#endif // defined _ARM_ARCH_6
