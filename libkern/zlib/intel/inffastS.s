#if (defined __i386__)

/* this assembly was 1st compiled from inffast.c (assuming POSTINC defined, OFF=0) and then hand optimized */

	.cstring
LC0:
	.ascii "invalid distance too far back\0"
LC1:
	.ascii "invalid distance code\0"
LC2:
	.ascii "invalid literal/length code\0"
	.text
	.align 4,0x90


#ifdef  INFLATE_STRICT
	.byte 0
	.byte 0
	.byte 0
	.byte 0
	.byte 0
	.byte 0
	.byte 0
	.byte 0
	.byte 0
	.byte 0
#endif
.globl _inflate_fast
_inflate_fast:

	// set up ebp to refer to arguments strm and start
	pushl	%ebp
	movl	%esp, %ebp

	// push edi/esi/ebx into stack
	pushl	%edi
	pushl	%esi
	pushl	%ebx

	// allocate for local variables 92-12=80, + 12 to align %esp to 16-byte boundary
	subl	$92, %esp
	movl	8(%ebp), %ebx					

	/* definitions to help code readability */

	#define	bits	%edi
	#define	strm	%ebx
	#define	state	28(strm)		// state = (struct inflate_state FAR *)strm->state;	
	#define	in		-84(%ebp)		// in = strm->next_in - OFF; OFF=0
	#define	last	-80(%ebp)		// last = in + (strm->avail_in - 5);
	#define	out		-28(%ebp)		// out = strm->next_out - OFF;
	#define	beg		-76(%ebp)		// beg = out - (start - strm->avail_out);
	#define	end		-72(%ebp)		// end = out + (strm->avail_out - 257);
	#define	wsize	-68(%ebp)		// wsize = state->wsize;
	#define whave	-64(%ebp)		// whave = state->whave;
	#define write	-60(%ebp)		// write = state->write;
	#define window	-56(%ebp)		// window = state->window;
	#define	hold	-52(%ebp)		// hold = state->hold;
	#define	lcode	-48(%ebp)		// lcode = state->lencode;
	#define	dcode	-44(%ebp)		// dcode = state->distcode;
	#define	lmask	-40(%ebp)		// lmask = (1U << state->lenbits) - 1; 
	#define	dmask	-36(%ebp)		// dmask = (1U << state->distbits) - 1; 
	#define	len		-32(%ebp)
	#define dmax	-20(%ebp)		
	#define	dist	-16(%ebp)		// dist
	#define	write_wsize	-24(%ebp)	// write+wsize
	#define	write_1		-88(%ebp)	// write-1
	#define	op		-92(%ebp)		// op

	movl	(strm), %eax			// strm->next_in
	movl	%eax, in				// in = strm->next_in - OFF; OFF=0

	subl	$5, %eax				// in - 5;
	movl	4(strm), %ecx			// strm->avail_in
	addl	%ecx, %eax				// in + (strm->avail_in - 5);
	movl	%eax, last				// last = in + (strm->avail_in - 5);

	movl	12(strm), %esi			// strm->next_out
	movl	%esi, out				// out = strm->next_out - OFF;

	movl	16(strm), %ecx			// strm->avail_out
	movl	%esi, %eax				// out		
	subl	12(%ebp), %eax			// out - start
	addl	%ecx, %eax				// out - (start - strm->avail_out);
	movl	%eax, beg				// beg = out - (start - strm->avail_out);

	leal	-257(%esi,%ecx), %ecx	// out + (strm->avail_out - 257);
	movl	%ecx, end				// end = out + (strm->avail_out - 257);

	movl	state, %edx

#ifdef	INFLATE_STRICT
	movl	20(%edx), %ecx			// state->dmax
	movl	%ecx, dmax				// dmax = state->dmax;
#endif

	movl	40(%edx), %ecx			// state->wsize
	movl	%ecx, wsize				// wsize = state->wsize;

	movl	44(%edx), %ecx			// state->whave
	movl	%ecx, whave				// whave = state->whave;

	movl	48(%edx), %esi			// state->write
	movl	%esi, write				// write = state->write;

	movl	52(%edx), %eax			// state->window
	movl	%eax, window			// window = state->window;


	movl	56(%edx), %ecx			// state->hold
	movl	%ecx, hold				// hold = state->hold

	movl	60(%edx), bits			// bits = state->bits;

	movl	76(%edx), %esi			// state->lencode
	movl	%esi, lcode				// lcode = state->lencode;

	movl	80(%edx), %eax			// state->distcode
	movl	%eax, dcode				// dcode = state->distcode;

	movl	84(%edx), %ecx			// state->lenbits
	movl	$1, %eax
	movl	%eax, %esi				// a copy of 1
	sall	%cl, %esi				// 1 << state->lenbits
	decl	%esi					// (1U << state->lenbits) - 1;
	movl	%esi, lmask				// lmask = (1U << state->lenbits) - 1;

	movl	88(%edx), %ecx			// state->distbits
	sall	%cl, %eax				// 1 << state->distbits
	decl	%eax					// (1U << state->distbits) - 1;
	movl	%eax, dmask				// dmask = (1U << state->distbits) - 1;


	// these 2 might be used often, precomputed and saved in stack	
	movl	write, %eax
	addl	wsize, %eax
	movl	%eax, write_wsize		// write+wsize

	movl	write, %edx
	decl	%edx
	movl	%edx, write_1			// write-1


L_do_while_loop:						// do {

	cmpl	$15, bits
	jae		bits_ge_15					//		if (bits < 15) {
#if 0
	leal	8(bits), %esi				// esi = bits+8
	movl	in, %eax					// eax = in
	movzbl	(%eax), %edx				// edx = *in++
	movl	bits, %ecx					// cl = bits
	sall	%cl, %edx					// 1st *in << bits
	addl	hold, %edx					// hold += 1st *in << bits
	movzbl	1(%eax), %eax				// 2nd *in
	movl	%esi, %ecx					// cl = bits+8
	sall	%cl, %eax					// 2nd *in << (bits+8)
	addl	%eax, %edx					// hold += 2nd *in << (bits+8) 
	movl	%edx, hold					// update hold
	addl	$2, in						// in += 2
	addl	$16, bits					// bits += 16;
#else
	/* from simulation, this code segment performs better than the other case
		possibly, we are more often hit with aligned memory access */
	movl	in, %ecx					//			unsigned short *inp = (unsigned short *) (in+OFF);
	movzwl	(%ecx), %eax				// 			*((unsigned short *) in);
	movl	bits, %ecx					//			bits
	sall	%cl, %eax					// 			*((unsigned short *) in) << bits
	addl	%eax, hold					// 			hold += (unsigned long) *((unsigned short *) in) << bits;
	addl	$2, in						// 			in += 2;
	addl	$16, bits					// 			bits += 16;
#endif

bits_ge_15:								// 		}	/* bits < 15 */

	movl	hold, %eax					// 		hold
	andl	lmask, %eax					// 		hold & lmask;
	movl	lcode, %esi					// 		lcode[] : 4-byte aligned
	movl	(%esi,%eax,4), %eax			// 		this = lcode[hold&lmask];
	jmp		dolen
	.align 4,0x90
op_nonzero:
	movzbl	%al, %ecx					// a copy of op to cl
	testb	$16, %cl					// if op&16
	jne		Llength_base				// 		branch to length_base

	testb	$64, %cl					// elif op&64
	jne		length_2nd_level_else		//		branch to 2nd level length code else conditions

	// 2nd level length code

	movl	$1, %eax
	sall	%cl, %eax					// 1 << op
	decl	%eax						// ((1<<op) - 1)
	andl	hold, %eax					// hold & ((1U << op) - 1)
	movzwl	%si, %ecx					// this.val
	addl	%ecx, %eax					// this.val + (hold & ((1U << op) - 1))

	movl	lcode, %ecx					// lcode[] : 4-byte aligned
	movl	(%ecx,%eax,4), %eax			// this = lcode[this.val + (hold & ((1U << op) - 1))];
										// goto dolen (compiler rearranged the order of code)
dolen:
	movl	%eax, %esi					// make a copy of this (val 16-bit, bits 8-bit, op 8-bit)
	shrl	$16, %esi					// %esi = this.val;
	movzbl	%ah, %ecx					// op = (unsigned)(this.bits); 
	shrl	%cl, hold					// hold >>= op; 
	subl	%ecx, bits					// bits -= op;
	testb	%al, %al					// op = (unsigned)(this.op);
	jne		op_nonzero					// if op!=0, branch to op_nonzero 

	movl	%esi, %ecx					// this.val;
	movl	out, %eax					// out
	movb	%cl, (%eax)					// PUP(out) = (unsigned char)(this.val);
	incl	%eax						// out++;
	movl	%eax, out					// save out

L_tst_do_while_loop_end:
	movl	last, %eax					// last
	cmpl	%eax, in					// in vs last
	jae		return_unused_bytes 		// branch to return_unused_bytes if in >= last
	movl	end, %edx					// end
	cmpl	%edx, out					// out vs end
	jb		L_do_while_loop				// branch to do loop if out < end

return_unused_bytes:

	movl	bits, %eax					// bits
	shrl	$3, %eax					// len = bits >> 3
	movl	in, %edx					// in
	subl	%eax, %edx					// in -= len
	sall	$3, %eax					// len << 3
	movl	bits, %ecx					// bits
	subl	%eax, %ecx					// bits -= len << 3

	movl	%edx, (strm)				// strm->next_in = in + OFF;
	movl	out, %eax
	movl	%eax, 12(strm)				// strm->next_out = out + OFF;

	cmpl	%edx, last					// last vs in
	jbe		L67							// if (last <= in) branch to L67 and return to L69
	movl	last, %eax					// last
	addl	$5, %eax					// 5 + last
	subl	%edx, %eax					// 5 + last - in	
L69:
	movl	%eax, 4(strm)				// update strm->avail_in

	movl	end, %eax
	cmpl	%eax, out					// out vs end
	jae		L70							// if (out>=end) branch to L70, and return to L72
	addl	$257, %eax					// 257 + end
	subl	out, %eax					// 257 + end - out
L72:
	movl	%eax, 16(strm)				// update strm->avail_out

	movl	$1, %eax
	sall	%cl, %eax					// 1 << bits
	decl	%eax						// (1 << bits) -1
	andl	hold, %eax					// hold &= (1U << bits) - 1;
	movl	state, %esi
	movl	%eax, 56(%esi)				// state->hold = hold;
	movl	%ecx, 60(%esi)				// state->bits = bits;

	addl	$92, %esp					// pop out local from stack

	// restore saved registers and return
	popl	%ebx
	popl	%esi
	popl	%edi
	leave
	ret

	// this code segment is branched in from op_nonzero, with op in cl and this.value in esi
Llength_base:
	movzwl	%si, %esi			// this instruction might not be needed, pad here to give better performance
	movl	%esi, len			// len = (unsigned)(this.val);
 
	movl	%ecx, %esi			// leave a copy of op at ecx
	andl	$15, %esi			// op&=15;
	je		Lop_is_zero			// if (op) {
	cmpl	bits, %esi			//		op vs bits
	jbe		Lop_be_bits			//		if (bits < op) {
	movl	in, %edx			//			in
	movzbl	(%edx), %eax		//			*in
	movl	bits, %ecx			//			bits
	sall	%cl, %eax			//			*in << bits
	addl	%eax, hold			// 			hold += (unsigned long)(PUP(in)) << bits;
	incl	%edx				//			in++
	movl	%edx, in			//			update in
	addl	$8, bits			//			bits += 8
Lop_be_bits:					//		}
	movl	$1, %eax			//		1
	movl	%esi, %ecx			//		op
	sall	%cl, %eax			//		1 << op
	decl	%eax				// 		(1<<op)-1	
	andl	hold, %eax			//		hold & ((1U << op) - 1)
	addl	%eax, len			//		len += (unsigned)hold & ((1U << op) - 1);
	shrl	%cl, hold			//		hold >>= op;
	subl	%esi, bits			//		bits -= op;
Lop_is_zero:					// }
	cmpl	$14, bits			// if (bits < 15) {
	jbe		bits_le_14			//		branch to refill 16-bit into hold, and branch back to next
L19:							// }
	movl	hold, %eax			// hold
	andl	dmask, %eax			// hold&dmask
	movl	dcode, %esi			// dcode[] : 4-byte aligned
	movl	(%esi,%eax,4), %eax	// this = dcode[hold & dmask];
	jmp		dodist

Lop_16_zero:
	testb	$64, %cl					// op&64
	jne		Linvalid_distance_code		// if (op&64)!=0, branch to invalid distance code
	movl	$1, %eax					// 1
	sall	%cl, %eax					// (1<<op)
	decl	%eax						// (1<<op)-1 
	andl	hold, %eax					// (hold & ((1U << op) - 1))
	movzwl	%dx, %edx					// this.val
	addl	%edx, %eax					// this.val + (hold & ((1U << op) - 1))
	movl	dcode, %edx					// dcode[] : 4 byte aligned
	movl	(%edx,%eax,4), %eax			// this = dcode[this.val + (hold & ((1U << op) - 1))];
dodist:
	movl	%eax, %edx					// this : (val 16-bit, bits 8-bit, op 8-bit)
	shrl	$16, %edx					// edx = this.val
	movzbl	%ah, %ecx					// op = (unsigned)(this.bits); 
	shrl	%cl, hold					// hold >>= op;
	subl	%ecx, bits					// bits -= op;
	movzbl	%al, %ecx					// op = (unsigned)(this.op);
	testb	$16, %cl					// op & 16
	je		Lop_16_zero					// if (op&16)==0 goto test op&64

Ldistance_base:							// if (op&16) {		/* distance base */
	andl	$15, %ecx					//	  op &= 15; edx = dist = this.val;
	movl	%ecx, op					// 		save a copy of op
	cmpl	bits, %ecx					//		op vs bits
	jbe		0f							//		if (bits < op) {
	movl	in, %ecx					//			in
	movzbl	(%ecx), %eax				//			*in
	movl	bits, %ecx					//			bits
	sall	%cl, %eax					//			*in << bits
	addl	%eax, hold					//			hold += (unsigned long)(PUP(in)) << bits;
	incl	in							//			in++
	addl	$8, bits					//			bits += 8
	cmpl	bits, op					//			op vs bits
	jbe		0f							//			if (bits < op) {
	movl	in, %esi					//				i
	movzbl	(%esi), %eax				// 				*in
	movl	bits, %ecx					//				cl = bits
	sall	%cl, %eax					//				*in << bits
	addl	%eax, hold					//				hold += (unsigned long)(PUP(in)) << bits;
	incl	%esi						//				in++
	movl	%esi, in					//				update in
	addl	$8, bits					//				bits += 8
0:										// }		}

	movzwl	%dx, %edx					// dist = (unsigned)(this.val); 
	movl	$1, %eax					// 1
	movzbl	op, %ecx					// cl = op
	sall	%cl, %eax					// 1 << op
	decl	%eax						// ((1U << op) - 1)
	andl	hold, %eax					// (unsigned)hold & ((1U << op) - 1)
	addl	%edx, %eax					// dist += (unsigned)hold & ((1U << op) - 1);

#ifdef INFLATE_STRICT

	cmpl	dmax, %eax						// dist vs dmax
	ja		Linvalid_distance_too_far_back	// if (dist > dmax) break for invalid distance too far back	

#endif

	movl	%eax, dist						// save a copy of dist in stack
	shrl	%cl, hold						// hold >>= op; 
	subl	%ecx, bits						// bits -= op;

	movl	out, %eax
	subl	beg, %eax						// eax = op = out - beg
	cmpl	%eax, dist						// dist vs op
	jbe		Lcopy_direct_from_output		// if (dist <= op) branch to copy direct from output	

											// if (dist > op) {
	movl	dist, %ecx						//	dist
	subl	%eax, %ecx						//	esi = op = dist - op;
	cmpl	%ecx, whave						//  whave vs op
	jb		Linvalid_distance_too_far_back	//  if (op > whave) break for error;

	movl	write, %edx
	testl	%edx, %edx
	jne		Lwrite_non_zero					// if (write==0) {
	movl	wsize, %eax						//		wsize
	subl	%ecx, %eax						//		wsize-op
	movl	window, %esi					//		from=window-OFF
	addl	%eax, %esi						//		from += wsize-op
	movl	out, %edx						//		out
	cmpl	%ecx, len						//		len vs op
	jbe		L38								// 		if !(op < len) skip
    subl    %ecx, len						// len - op
0:											// do {
	movzbl  (%esi), %eax					//
    movb    %al, (%edx)						//	
    incl    %edx							//
    incl    %esi							//  	PUP(out) = PUP(from);
    decl    %ecx							//		--op;
    jne     0b								// } while (op);

    movl    %edx, out						// update out
    movl    %edx, %esi						// out 
    subl    dist, %esi						// esi = from = out - dist;

L38:			/* copy from output */

			//		while (len > 2) {
            //            PUP(out) = PUP(from);
            //            PUP(out) = PUP(from);
            //            PUP(out) = PUP(from);
            //            len -= 3;
            //        }
            //        if (len) {
            //            PUP(out) = PUP(from);
            //            if (len > 1)
            //                PUP(out) = PUP(from);
            //       }

	movl	len, %ecx						// len
	movl	out, %edx						// out
	subl	$3, %ecx						// pre-decrement len by 3
	jl		1f								// if len < 3, branch to 1f for remaining processing
0:											// while (len>2) {
	movzbl	(%esi), %eax
	movb	%al, (%edx)						// 		PUP(out) = PUP(from);
	movzbl	1(%esi), %eax
	movb	%al, 1(%edx)					//		PUP(out) = PUP(from);
	movzbl	2(%esi), %eax
	movb	%al, 2(%edx)					//		PUP(out) = PUP(from);
	addl	$3, %esi						//		from += 3;
	addl	$3, %edx						//		out += 3;
	subl	$3, %ecx						//		len -= 3;
	jge		0b								// }
	movl	%edx, out						// update out, in case len == 0
1:
	addl	$3, %ecx						// post-increment len by 3
	je		L_tst_do_while_loop_end			// if (len) {
	movzbl	(%esi), %eax					//
	movb	%al, (%edx)						//		PUP(out) = PUP(from);
	incl	%edx							//		out++
	movl	%edx, out						//		update out, in case len == 1
	cmpl	$2, %ecx						//
	jne		L_tst_do_while_loop_end			//		if len==1, break
	movzbl	1(%esi), %eax
	movb	%al, (%edx)						//		PUP(out) = PUP(from);
	incl	%edx							//		out++
	movl	%edx, out						//		update out
	jmp		L_tst_do_while_loop_end			//	}
	
	.align 4,0x90
length_2nd_level_else:
	andl	$32, %ecx						// test end-of-block
	je		invalid_literal_length_code		// if (op&32)==0, branch for invalid literal/length code break
	movl	state, %edx						// if (op&32), end-of-block is detected
	movl	$11, (%edx)						// state->mode = TYPE
	jmp		return_unused_bytes

L70:
	movl	out, %edx						// out
	subl	%edx, end						// (end-out)
	movl	end, %esi						// %esi = (end-out) = -(out - end);
	leal	257(%esi), %eax					// %eax = 257 + %esi = 257 - (out -end)
	jmp		L72								// return to update state and return

L67:										// %edx = in, to return 5 - (in - last) in %eax
	subl	%edx, last						// last - in 
	movl	last, %edx						// %edx = last - in = - (in - last);
	leal	5(%edx), %eax					// %eax = 5 + %edx = 5 - (in - last);
	jmp		L69								// return to update state and return

bits_le_14:
#if 1
	leal	8(bits), %esi				// esi = bits+8
	movl	in, %eax					// eax = in
	movzbl	(%eax), %edx				// edx = *in++
	movl	bits, %ecx					// cl = bits
	sall	%cl, %edx					// 1st *in << bits
	addl	hold, %edx					// hold += 1st *in << bits
	movzbl	1(%eax), %eax				// 2nd *in
	movl	%esi, %ecx					// cl = bits+8
	sall	%cl, %eax					// 2nd *in << (bits+8)
	addl	%eax, %edx					// hold += 2nd *in << (bits+8) 
	movl	%edx, hold					// update hold
	addl	$2, in						// in += 2
	addl	$16, bits					// bits += 16;
	jmp	L19
#else
	/* this code segment does not run as fast as the other original code segment, possibly the processor
		need extra time to handle unaligned short access */
	movl    in, %edx                    //          unsigned short *inp = (unsigned short *) (in+OFF);
    movzwl  (%edx), %eax                //          *((unsigned short *) in);
    movl    bits, %ecx                  //          bits
    sall    %cl, %eax                   //          *((unsigned short *) in) << bits
    addl    %eax, hold                  //          hold += (unsigned long) *((unsigned short *) in) << bits;
    addl    $2, %edx                    //          in += 2;
    addl    $16, %ecx                   //          bits += 16;
	movl	%edx, in
	movl	%ecx, bits
	jmp	L19
#endif
invalid_literal_length_code:
    call    0f
0:	popl    %eax
	leal	LC2-0b(%eax), %eax
	movl	%eax, 24(strm)
	movl	state, %esi
	movl	$27, (%esi)
	jmp		return_unused_bytes
Linvalid_distance_code:
    call    0f
0:	popl    %eax
	leal	LC1-0b(%eax), %eax
	movl	%eax, 24(strm)
	movl	state, %eax
	movl	$27, (%eax)
	jmp		return_unused_bytes

#ifdef	INFLATE_STRICT
	.align	4,0x90
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	0
#endif
Lcopy_direct_from_output:
	movl	out, %edx							// out
	subl	dist, %edx							// from = out - dist
	movl	out, %ecx							// out
	movl	len, %esi							// len
	subl	$3, %esi							// pre-decement len by 3
0:												// do {
	movzbl	(%edx), %eax
	movb	%al, (%ecx)							// 	PUP(out) = PUP(from);
	movzbl	1(%edx), %eax
	movb	%al, 1(%ecx)						// 	PUP(out) = PUP(from);
	movzbl	2(%edx), %eax
	movb	%al, 2(%ecx)						// 	PUP(out) = PUP(from);
	addl	$3, %edx							// 	from += 3
	addl	$3, %ecx							// 	out += 3	
	subl	$3, %esi							// 	len -= 3
	jge		0b									// } while (len > 2);
	movl	%ecx, out							// update out in case len == 0
	addl	$3, %esi							// post-increment len by 3
	je		L_tst_do_while_loop_end				// if (len) {
	movzbl	(%edx), %eax
	movb	%al, (%ecx)							//		PUP(out) = PUP(from);
	incl	%ecx
	movl	%ecx, out							//		out++
	cmpl	$2, %esi							//
	jne		L_tst_do_while_loop_end				//		if (len>2)
	movzbl	1(%edx), %eax
	movb	%al, (%ecx)							//			PUP(out) = PUP(from);
	incl	%ecx
	movl	%ecx, out							//			out++
	jmp		L_tst_do_while_loop_end				// }

	.align 4,0x90
Lwrite_non_zero:								// %edx = write, %ecx = op
	movl	window, %esi						// from = window - OFF;
	cmp		%ecx, %edx							// write vs op, test for wrap around window or contiguous in window
	jae		Lcontiguous_in_window				// if (write >= op) branch to contiguous in window 

Lwrap_around_window: 							// wrap around window
	addl	write_wsize, %esi					// from += write+wsize
	subl	%ecx, %esi							// from += wsize + write - op;		
	subl	%edx, %ecx							// op -= write
	cmpl	%ecx, len							// len vs op
	jbe		L38									// if (len <= op) break to copy from output
	subl	%ecx, len							// len -= op;
	movl	out, %edx							// out
0:												// do {
	movzbl	(%esi), %eax						// 	*from
	movb	%al, (%edx)							// 	*out
	incl	%esi								// 	from++
	incl	%edx								// 	out++	
	decl	%ecx								// 	--op
	jne		0b									// } while (op);

	movl	%edx, out							// save out in case we need to break to L38
	movl	window, %esi						// from = window - OFF;
	movl	len, %eax							// len
	cmpl	%eax, write							// write vs len
	jae		L38									// if (write >= len) break to L38 

	movl	write, %ecx							// op = write
	subl	%ecx, len							// len -= op;
0:												// do {
	movzbl	(%esi), %eax						//	*from
	movb	%al, (%edx)							//  *out
	incl	%esi								//  from++
	incl	%edx								//	out++
	decl	%ecx								//  --op
	jne		0b									// } while (op);

	movl	%edx, %esi							// from = out
	movl	%edx, out							// save a copy of out
	subl	dist, %esi							// from = out - dist;
	jmp		L38									// break to copy from output

Lcontiguous_in_window:								// contiguous in window, edx = write, %ecx = op
	subl	%ecx, %edx								// write - op
	addl	%edx, %esi								// from += write - op;
	cmpl	%ecx, len								// len vs op
	jbe		L38										// if (len <= op) break to copy from output 
	movl	out, %edx								// out
	subl	%ecx, len								// len -= op;

0:													// do {
	movzbl	(%esi), %eax							// 	*from
	movb	%al, (%edx)								// 	*out
	incl	%esi									// 	from++
	incl	%edx									// 	out++
	decl	%ecx									// 	op-- 
	jne		0b										// } while (op); 

	movl	%edx, out								// update out
	movl	%edx, %esi								// from = out
	subl	dist, %esi								// from = out - dist;
	jmp		L38

Linvalid_distance_too_far_back:
    call    0f
0:	popl    %eax
	leal	LC0-0b(%eax), %eax
	movl	%eax, 24(strm)
	movl	state, %ecx
	movl	$27, (%ecx)
	jmp		return_unused_bytes

#endif

#if (defined __x86_64__)
	.cstring
LC0:
	.ascii "invalid distance too far back\0"
LC1:
	.ascii "invalid distance code\0"
LC2:
	.ascii "invalid literal/length code\0"
	.text
	.align 4,0x90

#ifdef  INFLATE_STRICT
	.byte 0
	.byte 0
	.byte 0
	.byte 0
	.byte 0
	.byte 0
	.byte 0
	.byte 0
	.byte 0
	.byte 0
	.byte 0
	.byte 0
#endif

.globl _inflate_fast
_inflate_fast:

	// set up rbp
	pushq	%rbp
	movq	%rsp, %rbp

	// save registers in stack
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx

	#define	strm		%r13
	#define	state		%rdi
	#define	in			%r12
	#define	in_d		%r12d
	#define	out			%r10
	#define	out_d		%r10d
	#define	write		%r15d
	#define hold		%r9
	#define holdd		%r9d
	#define	bits		%r8d
	#define	lcode		%r14
	#define	len			%ebx
	#define from		%rcx
	#define	dmax		%r11d

	#define	last		-104(%rbp)
	#define	beg			-96(%rbp)
	#define	end			-88(%rbp)
	#define	wsize		-80(%rbp)
	#define	whave		-76(%rbp)
	#define	window		-72(%rbp)
	#define	dcode		-64(%rbp)
	#define	lmask		-56(%rbp)
	#define	dmask		-112(%rbp)
	#define	wsize_write	-116(%rbp)
	#define	write_1		-128(%rbp)
	#define	dist		-44(%rbp)

	// reserve stack memory for local variables 128-40=88
	subq	$88, %rsp

	movq	%rdi, strm
	movq	56(%rdi), state						// state = (struct inflate_state FAR *)strm->state;	
	movq	(strm), in							// in = strm->next_in - OFF;
	movl	8(strm), %eax						// strm->avail_in
	subl	$5, %eax							// (strm->avail_in - 5)
	addq	in, %rax							// in + (strm->avail_in - 5)
	movq	%rax, last							// last = in + (strm->avail_in - 5)
	movq	24(strm), out						// out = strm->next_out
	movl	32(strm), %eax						// strm->avail_out
	subl	%eax, %esi							// (start - strm->avail_out);
	movq	out, %rdx							// strm->next_out
	subq	%rsi, %rdx							// out - (start - strm->avail_out); 
	movq	%rdx, beg							// beg = out - (start - strm->avail_out);
	subl	$257, %eax							// (strm->avail_out - 257)
	addq	out, %rax							// out + (strm->avail_out - 257); 
	movq	%rax, end							// end = out + (strm->avail_out - 257);

#ifdef INFLATE_STRICT
	movl	20(state), dmax						// dmax = state->dmax;
#endif

	movl	52(state), %ecx						// state->wsize
	movl	%ecx, wsize							// wsize = state->wsize;
	movl	56(state), %ebx						// state->whave;
	movl	%ebx, whave							// whave = state->whave;
	movl	60(state), write					// write = state->write;
	movq	64(state), %rax						// state->window
	movq	%rax, window						// window = state->window;
	movq	72(state), hold						// hold = state->hold;
	movl	80(state), bits						// bits = state->bits;

	movq	96(state), lcode					// lcode = state->lencode;
	movq	104(state), %rdx					// state->distcode;
	movq	%rdx, dcode							// dcode = state->distcode;

	movl	116(state), %ecx					// state->distbits
	movl	$1, %eax
	movl	%eax, %edx							// 1
	sall	%cl, %edx							// (1U << state->distbits)
	movl	112(state), %ecx					// state->lenbits
	sall	%cl, %eax							// (1U << state->lenbits)
	decl	%eax								// (1U << state->lenbits) - 1
	movq	%rax, lmask							// lmask = (1U << state->lenbits) - 1
	decl	%edx								// (1U << state->distbits) - 1
	movq	%rdx, dmask							// dmask = (1U << state->distbits) - 1

	movl	wsize, %ecx							// wsize
	addl	write, %ecx							// wsize + write
	movl	%ecx, wsize_write					// wsize_write = wsize + write

	leal	-1(%r15), %ebx						// write - 1
	movq	%rbx, write_1						// write_1 = write - 1

L_do_while_loop:
	cmpl	$14, bits							// bits vs 14
	ja		0f									// if (bits < 15) {
	movzwl	(in), %eax							//		read 2 bytes from in
	movl	bits, %ecx							//		set up cl = bits
	salq	%cl, %rax							//		(*in) << bits	
	addq	%rax, hold							// 		hold += (*in) << bits
	addq	$2, in								//		in += 2
	addl	$16, bits							//		bits += 16
0:												// }
	movq	lmask, %rax							//	lmask
	andq	hold, %rax							//	hold & lmask
	jmp		1f
	.align 4,0x90
Lop_nonzero:
	movzbl	%al, %ecx							// op in al and cl 
	testb	$16, %cl							// check for length base processing (op&16)
	jne		L_length_base						// if (op&16) branch to length base processing	
	testb	$64, %cl							// check for 2nd level length code (op&64==0)
	jne		L_end_of_block						// if (op&64)!=0, branch for end-of-block processing

	/* 2nd level length code : (op&64) == 0*/
L_2nd_level_length_code:
	movl	$1, %eax							// 1
	sall	%cl, %eax							// 1 << op
	decl	%eax								// ((1U << op) - 1)
	andq	hold, %rax							// (hold & ((1U << op) - 1))
	movzwl	%dx, %edx
	addq	%rdx, %rax							// this = lcode[this.val + (hold & ((1U << op) - 1))];
1:	
	movl	(lcode,%rax,4), %eax				// this = lcode[hold & lmask];
Ldolen:
	movl	%eax, %edx							// a copy of this
	shrl	$16, %edx							// edx = this.val;
	movzbl	%ah, %ecx							// op = this.bits
	shrq	%cl, hold							// hold >>= op; 
	subl	%ecx, bits							// bits -= op;
	testb	%al, %al							// op = (unsigned)(this.op);
	jne		Lop_nonzero							// if (op!-0) branch for copy operation
L_literal:
	movb	%dl, (out)							// *out = this.val
	incq	out									// out ++
L_do_while_loop_check:
	cmpq	last, in							// in vs last
	jae		L_return_unused_byte				// if in >= last, break to return unused byte processing
	cmpq	end, out							// out vs end
	jb		L_do_while_loop						// back to do_while_loop if out < end

	/* return unused bytes (on entry, bits < 8, so in won't go too far back) */

L_return_unused_byte:
	movl	out_d, %esi
	jmp		L34

L_length_base:				/* al = cl = op, edx = this.val, op&16 = 16 */ 
	movzwl	%dx, len							// len = (unsigned)(this.val);
	movl	%ecx, %edx							// op
	andl	$15, %edx							// op &= 15;
	je		1f									// if (op) {
	cmpl	bits, %edx							//		op vs bits
	jbe		0f									//		if (bits < op) {
	movzbl	(in), %eax							//			*in
	movl	bits, %ecx							//			cl = bits
	salq	%cl, %rax							//			*in << bits
	addq	%rax, hold							//			hold += (unsigned long)(PUP(in)) << bits;
	incq	in									//			in++
	addl	$8, bits							//			bits += 8
0:												//		}
	movl	$1, %eax							//		1
	movl	%edx, %ecx							//		cl = op
	sall	%cl, %eax							//		1 << op
	decl	%eax								//		(1 << op) - 1
	andl	holdd, %eax							//		 (unsigned)hold & ((1U << op) - 1);
	addl	%eax, len							//		len += (unsigned)hold & ((1U << op) - 1);
	shrq	%cl, hold							//		hold >>= op;
	subl	%edx, bits							//		bits -= op;
1:												// }
	cmpl	$14, bits							// bits vs 14
	jbe		L99									// if (bits < 15) go to loading to hold and return to L19
L19:												// }
	movq	dmask, %rax							// dmask
	andq	hold, %rax							// hold & dmask
	movq	dcode, %rdx							// dcode[]
	movl	(%rdx,%rax,4), %eax					// this = dcode[hold & dmask];
	jmp		L_dodist
	.align 4,0x90
0:												// op&16 == 0, test (op&64)==0 for 2nd level distance code
	testb	$64, %cl							// op&64	
	jne		L_invalid_distance_code				// if ((op&64)==0) { /* 2nd level distance code */
	movl	$1, %eax							//	1
	sall	%cl, %eax							//  1 << op 
	decl	%eax								// (1 << op) - 1
	andq	hold, %rax							// (hold & ((1U << op) - 1))
	movzwl	%dx, %edx							// this.val	
	addq	%rdx, %rax							// this.val + (hold & ((1U << op) - 1))
	movq	dcode, %rcx							// dcode[]
	movl	(%rcx,%rax,4), %eax					// this = dcode[this.val + (hold & ((1U << op) - 1))];
L_dodist:
	movl	%eax, %edx							// this
	shrl	$16, %edx							// dist = (unsigned)(this.val);
	movzbl	%ah, %ecx							// cl = op = this.bits
	shrq	%cl, hold							// hold >>= op;
	subl	%ecx, bits							// bits -= op;
	movzbl	%al, %ecx							// op = (unsigned)(this.op);
	testb	$16, %cl							// (op & 16)	test for distance base
	je		0b									// if (op&16) == 0, branch to check for 2nd level distance code

L_distance_base:								/* distance base */

	movl	%ecx, %esi							// op
	andl	$15, %esi							// op&=15
	cmpl	bits, %esi							// op vs bits
	jbe		1f									// if (bits < op) {
	movzbl	(in), %eax							//		*in
	movl	bits, %ecx							//		cl = bits
	salq	%cl, %rax							//		*in << bits
	addq	%rax, hold							//		hold += (unsigned long)(PUP(in)) << bits;
	incq	in									//		in++
	addl	$8, bits							//		bits += 8
	cmpl	bits, %esi							//		op vs bits
	jbe		1f									//		if (bits < op) {
	movzbl	(in), %eax							//			*in
	movl	bits, %ecx							//			cl = bits
	salq	%cl, %rax							//			*in << bits
	addq	%rax, hold							//			hold += (unsigned long)(PUP(in)) << bits;
	incq	in									//			in++
	addl	$8, bits							//			bits += 8
1:												// }	}

	movzwl	%dx, %edx							// dist
	movl	$1, %eax							// 1
	movl	%esi, %ecx							// cl = op
	sall	%cl, %eax							// (1 << op)
	decl	%eax								// (1 << op) - 1
	andl	holdd, %eax							// (unsigned)hold & ((1U << op) - 1)
	addl	%edx, %eax							// dist += (unsigned)hold & ((1U << op) - 1);
	movl	%eax, dist							// save a copy of dist in stack

#ifdef INFLATE_STRICT
	cmp		%eax, dmax							// dmax vs dist 
	jb		L_invalid_distance_too_far_back		// if (dmax < dist) break for invalid distance too far back
#endif

	shrq	%cl, hold							// hold >>= op;
	subl	%esi, bits							// bits -= op;
	movl	out_d, %esi							// out
	movl	out_d, %eax							// out
	subl	beg, %eax							// op = out - beg
	cmpl	%eax, dist							// dist vs op,  /* see if copy from window */
	jbe		L_copy_direct_from_output			// if (dist <= op) branch to copy direct from output

L_distance_back_in_window:			

	movl	dist, %edx							// dist
	subl	%eax, %edx							// op = dist - op;	/* distance back in window */

	cmpl	%edx, whave							// whave vs op
	jb		L_invalid_distance_too_far_back		// if (op > whave), break for invalid distance too far back

	testl	write, write						// if (write!=0)
	jne		L_wrap_around_window				//		branch to wrap around window

L_very_common_case:

	movl	wsize, %eax							//	wsize
	subl	%edx, %eax							//	wsize - op
	movq	window, from						//	from = window - OFF;
	addq	%rax, from							//	from += wsize - op;

	movl	%edx, %esi							//  op
	cmpl	%edx, len							//  len vs op
	ja		L_some_from_window					//  if (len > op), branch for aligned code block L_some_from_window
L38:
	subl	$3, len								// pre-decrement len by 3
	jge		0f									// if len >= 3, branch to the aligned code block 
1:	addl	$3, len								// post-increment len by 3
	je		L_do_while_loop_check				// if (len==0) break to L_do_while_loop_check
	movzbl	(from), %eax						// *from
	movb	%al, (out)							// *out
	incq	out									// out++
	cmpl	$2, len								// len vs 2
	jne		L_do_while_loop_check				// if len!=2 break to L_do_while_loop_check
	movzbl	1(from), %eax						// *from
	movb	%al, (out)							// *out
	incq	out									// out++
	jmp		L_do_while_loop_check				// break to L_do_while_loop_check

	.align 4,0x90
0:												// do {				
	movzbl	(from), %eax						//		*from
	movb	%al, (out)							//		*out
	movzbl	1(from), %eax						//		*from
	movb	%al, 1(out)							//		*out
	movzbl	2(from), %eax						//		*from
	movb	%al, 2(out)							//		*out
	addq	$3, out								//		out += 3
	addq	$3, from							//		from += 3
	subl	$3, len								//		len -= 3
	jge		0b									// } while (len>=0);
	jmp		1b									// branch back to the possibly unaligned code

	.align 4,0x90
L_end_of_block:
	andl	$32, %ecx							// op & 32
	jne		L101								// if (op&32) branch to end-of-block break
	leaq	LC2(%rip), from
	movq	from, 48(strm)						// state->mode
	movl	$27, (state)						// state->mode = BAD;
	movl	out_d, %esi

L34:
	movl	bits, %eax							// bits
	shrl	$3, %eax							// len = bits >> 3;
	mov		%eax, %edx							// len
	subq	%rdx, in							// in -= len
	sall	$3, %eax							// len << 3
	movl	bits, %ecx							// bits
	subl	%eax, %ecx							// bits -= len << 3
	movq	in, (strm)							// strm->next_in = in + OFF;
	movq	out, 24(strm)						// strm->next_out = out + OFF;
	cmpq	in, last							// last vs in
	jbe		L67									// if (last <= in) branch to L67 and return to L69
	movl	last, %eax							// last
	addl	$5, %eax							// last + 5
	subl	in_d, %eax							// 5 + last - in
L69:
	movl	%eax, 8(strm)						// update strm->avail_in

	cmpq	end, out							// out vs end
	jae		L70									// if out<=end branch to L70 and return to L72
	movl	end, %eax							// end
	addl	$257, %eax							// 257 + end
	subl	%esi, %eax							// 257 + end - out;
L72:
	movl	%eax, 32(strm)						// update strm->avail_out

	movl	$1, %eax							// 1
	sall	%cl, %eax							// 1 << bits
	decl	%eax								// (1U << bits) - 1
	andq	hold, %rax							// hold &= (1U << bits) - 1;
	movq	%rax, 72(state)						// state->hold = hold;
	movl	%ecx, 80(state)						// state->bits = bits;

	// clear stack memory for local variables
	addq	$88, %rsp

	// restore registers from stack 
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15

	// return to caller
	leave
	ret

	.align 4,0x90
L99:
	leal	8(bits), %esi						//		esi = bits+8
	movzbl	(in), %edx							//		1st *in	
	movl	bits, %ecx							//		cl = bits
	salq	%cl, %rdx							//		1st *in << 8
	addq	%rdx, hold							// 		1st hold += (unsigned long)(PUP(in)) << bits;
	movzbl	1(in), %eax							//		2nd *in
	movl	%esi, %ecx							//		cl = bits + 8
	salq	%cl, %rax							//		2nd *in << bits+8	
	addq	%rax, hold							// 		2nd hold += (unsigned long)(PUP(in)) << bits;
	addq	$2, in								//		in += 2
	addl	$16, bits							//		bits += 16
	jmp		L19

L101:
	movl	$11, (state)
	movl	out_d, %esi
	jmp	L34
	.align 4,0x90
L70:
	movl	end, %eax							// end
	subl	%esi, %eax							// end - out
	addl	$257, %eax							// 257 + end - out
	jmp		L72
	.align 4,0x90
L67:
	movl	last, %eax							// last
	subl	in_d, %eax							// last - in
	addl	$5, %eax							// 5 + last - in
	jmp		L69


	.align 4,0x90

	// stuffing the following 4 bytes to align the major loop to a 16-byte boundary to give the better performance
	.byte 0
	.byte 0
	.byte 0
	.byte 0
L_copy_direct_from_output:
	mov		dist, %eax						// dist
	movq	out, %rdx						// out
	subq	%rax, %rdx						// from = out - dist;
	subl	$3, len							// pre-decrement len by 3
											// do {
0:	movzbl	(%rdx), %eax					// 	*from
	movb	%al, (out)						//	*out
	movzbl	1(%rdx), %eax					//	*from
	movb	%al, 1(out)						//	*out
	movzbl	2(%rdx), %eax					//	*from
	movb	%al, 2(out)						//	*out
	addq	$3, out							//	out+=3
	addq	$3, %rdx						//  from+=3
	subl	$3, len							//  len-=3
	jge		0b								// } while (len>=0);
1:	addl	$3, len							// post-increment len by 3
	je		L_do_while_loop_check			// if len==0, branch to do_while_loop_check

	movzbl	(%rdx), %eax					// *from
	movb	%al, (out)						// *out
	incq	out								// out++
	cmpl	$2, len							// len == 2 ?
	jne		L_do_while_loop_check			// if len==1, branch to do_while_loop_check

	movzbl	1(%rdx), %eax					// *from
	movb	%al, (out)						// *out
	incq	out								// out++
	jmp	L_do_while_loop_check				// branch to do_while_loop_check

	.align 4,0x90
L_some_from_window:		// from : from, out, %esi/%edx = op
									// do {
	movzbl	(from), %eax			// 	*from
	movb	%al, (out)				// 	*out
	incq	from					// 	from++
	incq	out						// 	out++
	decl	%esi					// 	--op
	jne		L_some_from_window		// } while (op);
	subl	%edx, len				// len -= op;
	mov		dist, %eax				// dist
	movq	out, from				// out
	subq	%rax, from				// from = out - dist;
	jmp		L38						// copy from output

	.align 4,0x90
L_wrap_around_window:
	cmpl	%edx, write					// write vs op
	jae		L_contiguous_in_window		// if (write >= op) branch to contiguous in window
	movl	wsize_write, %eax			// wsize+write
	subl	%edx, %eax					// wsize+write-op
	movq	window, from				// from = window - OFF
	addq	%rax, from					// from += wsize+write-op
	subl	write, %edx					// op -= write
	cmpl	%edx, len					// len vs op
	jbe		L38							// if (len<=op) branch to copy from output
 
	subl	%edx, len					// len -= op;
0:										// do {
	movzbl	(from), %eax				//		*from
	movb	%al, (out)					//		*out
	incq	from						//		from++
	incq	out							//		out++
	decl	%edx						//		op--
	jne		0b							// } while (op);
	movq	window, from

	cmpl	len, write					// write vs len
	jae		L38							// if (write >= len) branch to copy from output
	movl	write, %esi					// op = write
	subl	write, len					// len -= op
1:										// do {
	movzbl	(from), %eax				//		*from	
	movb	%al, (out)					//		*out
	incq	from						//		from++
	incq	out							//		out++
	decl	%esi						//		op--
	jne		1b							// } while (op);
	mov		dist, %eax					// dist
	movq	out, from					// out
	subq	%rax, from					// from = out - dist;
	jmp		L38

	.align 4,0x90
L_contiguous_in_window:
	movl	write, %eax					// write
	subl	%edx, %eax					// write - op
	movq	window, from				// from = window - OFF
	addq	%rax, from					// from += write - op
	cmpl	%edx, len					// len vs op
	jbe		L38							// if (len <= op) branch to copy from output
	subl    %edx, len					// len -= op;
2:										// do {
	movzbl	(from), %eax				// 	*from
	movb	%al, (out)					// 	*out
	incq	from						// 	from++
	incq	out							// 	out++
	decl	%edx						// 	op--
	jne		2b							// } while (op);

	mov		dist, %eax					// dist
	movq	out, from					// out
	subq	%rax, from					// from = out - dist;
	jmp		L38							// copy from output

	.align 4,0x90
L_invalid_distance_code:
	leaq	LC1(%rip), %rdx
	movq	%rdx, 48(strm)
	movl	$27, (state)
	movl	out_d, %esi
	jmp		L34

L_invalid_distance_too_far_back:
	leaq	LC0(%rip), %rbx
	movq	%rbx, 48(strm)				// error message
	movl	$27, (state)				// state->mode = BAD
	jmp		L34

#endif
