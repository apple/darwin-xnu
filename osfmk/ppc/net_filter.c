/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 * 
 */


#if NET_FILTER_COMPILER


#define USE_EXTRA_REGS 0

#define REG_ZERO	0	/* Register we keep equal to 0. */
#define REG_DATAADDR	3	/* Address of packet data, and filter return. */
#define REG_DATALEN	4	/* Length of packet data in two-byte units. */
#define REG_HDRADDR	5	/* Address of header data. */
#define REG_RET		3	/* Where to put return value. */

/* Originally we dealt in virtual register numbers which were essentially
   indexes into this array, and only converted to machine register numbers
   when emitting instructions.  But that meant a lot of conversions, so
   instead we deal with machine register numbers all along, even though this
   means wasting slots in the regs[] array.  */
const unsigned char scratchregs[] = {
    6, 7, 8, 9, 10, 11, 12,
#if USE_EXTRA_REGS	/* Callee-saves regs available if we save them. */
#define INITIAL_NSCRATCHREGS 8	/* Number of registers above. */
    #error not yet written
#endif
};
#define NSCRATCHREGS (sizeof scratchregs / sizeof scratchregs[0])
#define NREGS 32
#define NO_REG 1	/* This is the stack pointer!  Flag value.  */

#define MAX_LI		0x7fff	/* Max unsigned value in an LI. */

#define BCLR(cond)	((19 << 26) | (cond) | (16 << 1))
#define BLR()		BCLR(COND_ALWAYS)
#define BC(cond, off)	((16 << 26) | (cond) | ((off) << 2))
#define COND(BO, BI)	(((BO) << (16 + 5)) | ((BI) << 16))
#define COND_ALWAYS	COND(COND_IF_ALWAYS, 0)
#define COND_EQ		COND(COND_IF_TRUE, COND_BIT(0, BIT_EQ))
#define COND_NE		COND(COND_IF_FALSE, COND_BIT(0, BIT_EQ))
#define COND_LE		COND(COND_IF_FALSE, COND_BIT(0, BIT_GT))
#define COND_GE		COND(COND_IF_FALSE, COND_BIT(0, BIT_LT))
#define COND_BIT(crf, bit) \
			((crf) * 4 + (bit))
#define BIT_EQ		2
#define BIT_GT		1
#define BIT_LT		0
#define COND_IF_FALSE	0x04
#define COND_IF_TRUE	0x0c
#define COND_IF_ALWAYS	0x14

/* For arithmetical instructions, a is the dest and b is the source;
   for logical instructions, a is the source and b is the dest.  Ho hum.  */
#define IMMED(opcode, a, b, imm) \
			(((opcode) << 26) | ((a) << 21) | ((b) << 16) | \
			 ((imm) & 0xffff))
#define ADDI(dst, src, imm) \
			IMMED(14, dst, src, imm)
#define ADDIC(dst, src, imm) \
			IMMED(12, dst, src, imm)
#define SUBFIC(dst, src, imm) \
			IMMED(8, dst, src, imm)
#define LI(dst, imm)	ADDI(dst, 0, (imm))
#define ANDI(dst, src, imm) \
			IMMED(28, src, dst, imm)
#define ORI(dst, src, imm) \
			IMMED(24, src, dst, imm)
#define XORI(dst, src, imm) \
			IMMED(26, src, dst, imm)

#define CMPL(lhs, rhs)	((31 << 26) | ((lhs) << 16) | ((rhs) << 11) | (32 << 1))
#define CMPLI(lhs, imm)	((10 << 26) | ((lhs) << 16) | ((imm) & 0xffff))

#define INTEGER_OP(opcode, a, b, c) \
			((31 << 26) | ((a) << 21) | ((b) << 16) | \
			 ((c) << 11) | ((opcode) << 1))
#define ARITH_OP(opcode, dst, lhs, rhs) \
			INTEGER_OP(opcode, dst, lhs, rhs)
#define ADD(dst, lhs, rhs) \
			ARITH_OP(OP_ADD, dst, lhs, rhs)
#define ADDE(dst, lhs, rhs) \
			ARITH_OP(OP_ADDE, dst, lhs, rhs)
#define SUBF(dst, lhs, rhs) \
			ARITH_OP(OP_SUBF, dst, lhs, rhs)
#define SUBFC(dst, lhs, rhs) \
			ARITH_OP(OP_SUBFC, dst, lhs, rhs)
#define SUBFE(dst, lhs, rhs) \
			ARITH_OP(OP_SUBFE, dst, lhs, rhs)
#define LOGIC_OP(opcode, dst, lhs, rhs) \
			INTEGER_OP(opcode, lhs, dst, rhs)
#define OR(dst, lhs, rhs) \
			LOGIC_OP(OP_OR, dst, lhs, rhs)
#define XOR(dst, lhs, rhs) \
			LOGIC_OP(OP_XOR, dst, lhs, rhs)
#define OP_ADD 		266
#define OP_ADDE		138
#define OP_AND		28
#define OP_OR		444
#define OP_SRW		536
#define OP_SUBF		40
#define OP_SUBFC	8
#define OP_SUBFE	136
#define OP_XOR		316
#define MR(dst, src)	OR(dst, src, src)

#define LHZ(dst, base, offset) \
			((40 << 26) | ((dst) << 21) | ((base) << 16) | \
			 ((offset) & 0xffff))
#define LHZX(dst, base, index) \
			INTEGER_OP(279, dst, base, index)
#define MFCR(dst)	INTEGER_OP(19, dst, 0, 0)

#define RLWINM(dst, src, shiftimm, mbegin, mend) \
			((21 << 26) | ((src) << 21) | ((dst) << 16) | \
			 ((shiftimm) << 11) | ((mbegin) << 6) | ((mend) << 1))
#define RLWNM(dst, src, shiftreg, mbegin, mend) \
			((23 << 26) | ((src) << 21) | ((dst) << 16) | \
			 ((shiftreg) << 11) | ((mbegin) << 6) | ((mend) << 1))

/* Every NETF_arg generates at most four instructions (4 for PUSHIND).
   Every NETF_op generates at most 3 instructions (3 for EQ and NEQ).  */
#define MAX_INSTR_PER_ARG 4
#define MAX_INSTR_PER_OP  3
#define MAX_INSTR_PER_ITEM (MAX_INSTR_PER_ARG + MAX_INSTR_PER_OP)
int junk_filter[MAX_INSTR_PER_ITEM];

enum {NF_LITERAL, NF_HEADER, NF_DATA};
struct common {	/* Keeps track of values we might want to avoid reloading. */
    char type;	/* NF_LITERAL: immediate; NF_HEADER: header word;
		   NF_DATA: data word. */
    char nuses;	/* Number of remaining uses for this value. */
    unsigned char reg;
		/* Register this value is currently in, or NO_REG if none. */
    unsigned short value;
		/* Immediate value or header or data offset. */
};
struct reg {	/* Keeps track of the current contents of registers. */
    unsigned char commoni;
			/* Index in common[] of the contained value. */
#define NOT_COMMON_VALUE NET_MAX_FILTER	/* When not a common[] value. */
    unsigned char stacktimes;
			/* Number of times register appears in stack. */
};
struct local {	/* Gather local arrays so we could kalloc() if needed.  */
    struct common common[NET_MAX_FILTER];	/* Potentially common values. */
    struct reg regs[NREGS];			/* Register statuses. */
    unsigned char commonpos[NET_MAX_FILTER];	/* Index in common[] for the
						   value loaded in each filter
						   command. */
    unsigned char stackregs[NET_FILTER_STACK_DEPTH];
						/* Registers making up the
						   stack. */
#if USE_EXTRA_REGS
    unsigned char maxreg;
#endif
};

int allocate_register(struct local *s, int commoni);
int compile_preamble(int *instructions, struct local *s);

/* Compile a packet filter into POWERPC machine code.  We do everything in
   the 7 caller-saves registers listed in scratchregs[], except when
   USE_EXTRA_REGS is defined, in which case we may also allocate callee-
   saves registers if needed.  (Not yet implemented on PPC.)

   Rather than maintaining an explicit stack in memory, we allocate registers
   dynamically to correspond to stack elements -- we can do this because we
   know the state of the stack at every point in the filter program.  We also
   attempt to keep around in registers values (immediates, or header or data
   words) that are used later on, to avoid having to load them again.
   Since there are only 7 registers being used, we might be forced to reload
   a value that we could have kept if we had more.  We might even be unable
   to contain the stack in the registers, in which case we return failure and
   cause the filter to be interpreted by net_do_filter().  But for all current
   filters I looked at, 7 registers is enough even to avoid reloads.  When
   USE_EXTRA_REGS is defined there are about 28 available registers, which is
   plenty.

   We depend heavily on NET_MAX_FILTER and NET_FILTER_STACK_DEPTH being
   small.  We keep indexes to arrays sized by them in char-sized fields,
   originally because we tried allocating these arrays on the stack.
   Even then we overflowed the small (4K) kernel stack, so we were forced
   to allocate the arrays dynamically, which is the reason for the existence
   of `struct local'.

   We also depend on the filter being logically correct, for instance not
   being longer than NET_MAX_FILTER or underflowing its stack.  This is
   supposed to have been checked by parse_net_filter() before the filter
   is compiled.

   We are supposed to return 1 (TRUE) if the filter accepts the packet
   and 0 (FALSE) otherwise.  In fact, we may return any non-zero value
   for true, which is sufficient for our caller and convenient for us.

   There are lots and lots of optimisations that we could do but don't.
   This is supposedly a *micro*-kernel, after all.  Here are some things
   that could be added without too much headache:
   - Using the condition register.  We go to a lot of trouble to generate
     integer truth values for EQ etc, but most of the time those values
     are just ANDed or ORed together or used as arguments to COR etc.  So
     we could compute the comparison values directly into CR bits and
     operate on them using the CR logical instructions without (most of
     the time) ever having to generate integer equivalents.
   - More registers.  We could note the last uses of r3, r4, and
     r5, and convert them to general registers after those uses.  But if
     register shortage turns out to be a problem it is probably best just
     to define USE_EXTRA_REGS and have done with it.
   - Minimising range checks.  Every time we refer to a word in the data
     part, we generate code to ensure that it is within bounds.  But often
     the truth of these tests is implied by earlier tests.  Instead, at the
     start of the filter and after every COR or CNAND we could insert
     a single check when that is necessary.  (After CAND and CNOR we don't
     need to check since if they terminate it will be to return FALSE
     anyway so all we'd do would be to return it prematurely.)
   - Remembering immediate values.  Instead of generating code as soon as we
     see a PUSHLIT, we could remember that value and only generate code when
     it is used.  This would enable us to generate certain shorter
     instructions (like addi) that incorporate the immediate value instead
     of ever putting it in a register.
 */

filter_fct_t
net_filter_alloc(filter_t *filter, unsigned int size, unsigned int *lenp)
{
    struct local *s;
    int len, oldi, i, j, t, ncommon, sp;
    int type, value, arg, op, reg, reg1, dst, commoni;
    int returnfalseoffset;
    int *instructions, *instp, *returnfalse;
#if USE_EXTRA_REGS
    int oldmaxreg;
#endif
    boolean_t compiling;

#define SCHAR_MAX 127	/* machine/machlimits->h, anyone? */
    assert(NET_MAX_FILTER <= SCHAR_MAX);
    assert(NET_FILTER_STACK_DEPTH <= SCHAR_MAX);
    assert(NREGS <= SCHAR_MAX);

    assert(size < NET_MAX_FILTER);

    s = (struct local *) kalloc(sizeof *s);

#if USE_EXTRA_REGS
    s->maxreg = INITIAL_NSCRATCHREGS;
#endif
    len = 0;
    compiling = FALSE;
    returnfalse = junk_filter;

    /* This loop runs at least twice, once with compiling==FALSE to determine
       the length of the instructions we will compile, and once with
       compiling==TRUE to compile them.  The code generated on the two passes
       must be the same.  In the USE_EXTRA_REGS case, the loop can be re-run
       an extra time while !compiling, if we decide to use the callee-saves
       registers.  This is because we may be able to generate better code with
       the help of these registers than before.  */
    while (1) {

	/* Identify values that we can potentially preserve in a register to
	   avoid having to reload them.  All immediate values and references to
	   known offsets in the header or data are candidates.  The results of
	   this loop are the same on every run, so with a bit of work we
	   could run it just once; but this is not a time-critical
	   application.  */
	ncommon = 0;
	for (i = 0; i < size; i++) {
	    oldi = i;
	    arg = NETF_ARG(filter[i]);
	    if (arg == NETF_PUSHLIT) {
		type = NF_LITERAL;
		value = filter[++i];
	    } else if (arg >= NETF_PUSHSTK) {
		continue;
	    } else if (arg >= NETF_PUSHHDR) {
		type = NF_HEADER;
		value = arg - NETF_PUSHHDR;
	    } else if (arg >= NETF_PUSHWORD) {
		type = NF_DATA;
		value = arg - NETF_PUSHWORD;
	    } else {
		continue;
	    }
	    for (j = 0; j < ncommon; j++) {
		if (s->common[j].type == type && s->common[j].value == value) {
		    s->common[j].nuses++;
		    break;
		}
	    }
	    if (j == ncommon) {
		s->common[j].type = type;
		s->common[j].value = value;
		s->common[j].nuses = 1;
		ncommon++;
	    }
	    s->commonpos[oldi] = j;
	}

#if USE_EXTRA_REGS
	oldmaxreg = s->maxreg;
#endif

	/* Initially, no registers hold common values or are on the stack.  */
	for (i = 0; i < ncommon; i++)
	    s->common[i].reg = NO_REG;
	for (i = 0; i < NSCRATCHREGS; i++) {
	    s->regs[scratchregs[i]].commoni = NOT_COMMON_VALUE;
	    s->regs[scratchregs[i]].stacktimes = 0;
	}

	/* Now read through the filter and generate code. */
	sp = -1;	/* sp points to top element */
	for (i = 0; i < size; i++) {
	    if (!compiling)
		instp = junk_filter;

	    assert(sp >= -1);
	    assert(sp < NET_FILTER_STACK_DEPTH - 1);
	    commoni = s->commonpos[i];
	    arg = NETF_ARG(filter[i]);
	    op = NETF_OP(filter[i]);

	    /* Generate code to get the required value into a register and
	       set `reg' to the number of this register. */
	    switch (arg) {
	    case NETF_PUSHLIT:
		value = filter[++i];
		reg = s->common[commoni].reg;
		if (reg == NO_REG) {
		    if ((reg = allocate_register(s, commoni)) == NO_REG)
			goto fail;
		    assert(value >= 0);	/* Comes from unsigned short. */
		    *instp++ = ORI(reg, REG_ZERO, value);
		}
		s->common[commoni].nuses--;
		break;
	    case NETF_NOPUSH:
		reg = s->stackregs[sp--];
		s->regs[reg].stacktimes--;
		break;
	    case NETF_PUSHZERO:
		reg = REG_ZERO;
		break;
	    case NETF_PUSHIND:
	    case NETF_PUSHHDRIND:
		reg1 = s->stackregs[sp--];
		s->regs[reg1].stacktimes--;
		if (arg == NETF_PUSHIND)
		    *instp++ = CMPL(reg1, REG_DATALEN);
		else
		    *instp++ = CMPLI(reg1,
				     NET_HDW_HDR_MAX/sizeof (unsigned short));
		*instp = BC(COND_GE, returnfalse - instp);
		instp++;
		if ((reg = allocate_register(s, -1)) == NO_REG)
		    goto fail;
		*instp++ = ADD(reg, reg1, reg1);
		*instp++ = LHZX(reg, (arg == NETF_PUSHIND) ?
					REG_DATAADDR : REG_HDRADDR, reg);
		break;
	    default:
		if (arg >= NETF_PUSHSTK)
		    reg = s->stackregs[sp - (arg - NETF_PUSHSTK)];
		else if (arg >= NETF_PUSHWORD) {
		    assert(2 * (NETF_PUSHHDR - NETF_PUSHWORD) <= MAX_LI);
		    assert(NETF_PUSHSTK - NETF_PUSHHDR <= MAX_LI);
		    reg = s->common[commoni].reg;
		    if (reg == NO_REG) {
			if ((reg = allocate_register(s, commoni)) == NO_REG)
			    goto fail;
			if (arg < NETF_PUSHHDR) {
			    value = arg - NETF_PUSHWORD;
			    *instp++ = CMPLI(REG_DATALEN, value);
			    *instp = BC(COND_LE, returnfalse - instp);
			    instp++;
			    reg1 = REG_DATAADDR;
			} else {
			    value = arg - NETF_PUSHHDR;
			    reg1 = REG_HDRADDR;
			}
			*instp++ = LHZ(reg, reg1, 2 * value);
		    }
		    s->common[commoni].nuses--;
		}
	    }

	    /* Now generate code to do `op' on `reg1' (lhs) and `reg' (rhs). */
	    if (op != NETF_NOP) {
		reg1 = s->stackregs[sp--];
		s->regs[reg1].stacktimes--;
	    }
	    switch (op) {
	    case NETF_OP(NETF_CAND):
	    case NETF_OP(NETF_COR):
	    case NETF_OP(NETF_CNAND):
	    case NETF_OP(NETF_CNOR):
		dst = -1;
	    case NETF_OP(NETF_NOP):
		break;
	    default:
		/* Allocate a register to put the result in. */
		if ((dst = allocate_register(s, -1)) == NO_REG)
		    goto fail;
	    }
	    switch (op) {
	    case NETF_OP(NETF_NOP):
		dst = reg;
		break;
	    case NETF_OP(NETF_EQ):
	    case NETF_OP(NETF_NEQ):
		/* We arrange for the truth value to end up in the carry
		   flag and then put it in the destination register by
		   adding-with-carry zero to itself.  To set the carry, we
		   first make a value `x' that is zero if the values are
		   equal; this is either their XOR, or, if we know the
		   rhs is 0, the lhs.  Then to set the carry only when
		   x==0 we do `subfic dst,x,0' (subtract x from 0, setting
		   carry as not-borrow, so set only if x==0); to set it when
		   x!=0 we do `addic dst,x,-1' (add -1 to x setting carry,
		   so set unless x==0).  We're only interested in the carry
		   from these operations, not dst.
		   We don't test if reg1==REG_ZERO since in practice you
		   write NETF_PUSHLIT|NETF_EQ; the other order is eccentric
		   so you get an extra instruction, tough.  */
		if (reg == REG_ZERO)
		    t = reg1;
		else {
		    *instp++ = XOR(dst, reg1, reg);
		    t = dst;
		}
		*instp++ = (op == NETF_OP(NETF_EQ)) ?
			    SUBFIC(dst, t, 0) : ADDIC(dst, t, -1);
		*instp++ = ADDE(dst, REG_ZERO, REG_ZERO);
		break;
	    case NETF_OP(NETF_LT):
		/* LT and GT take advantage of the fact that all numbers are
		   16-bit quantities, so the sign bit after a subtraction
		   is a reliable indication of the relative magnitudes of
		   the operands.  */
		*instp++ = SUBF(dst, reg, reg1);	/* dst = reg1 - reg */
		*instp++ = RLWINM(dst, dst, 1, 31, 31);	/* sign bit */
		break;
	    case NETF_OP(NETF_GT):
		*instp++ = SUBF(dst, reg1, reg);	/* dst = reg - reg1 */
		*instp++ = RLWINM(dst, dst, 1, 31, 31);	/* sign bit */
		break;
	    case NETF_OP(NETF_LE):
		/* LE and GE use the carry (= not-borrow) flag.  When doing
		   a - b, there is a borrow if b > a, so carry if b <= a. */
		*instp++ = SUBFC(dst, reg1, reg);	/* dst = reg - reg1 */
		*instp++ = ADDE(dst, REG_ZERO, REG_ZERO);/* ca if reg1 <= reg */
		break;
	    case NETF_OP(NETF_GE):
		*instp++ = SUBFC(dst, reg, reg1);	/* dst = reg1 - reg */
		*instp++ = ADDE(dst, REG_ZERO, REG_ZERO);/* ca if reg <= reg1 */
		break;
	    case NETF_OP(NETF_AND):
		j = OP_AND;
		goto logical;
	    case NETF_OP(NETF_OR):
		j = OP_OR;
		goto logical;
	    case NETF_OP(NETF_XOR):
		j = OP_XOR;
		goto logical;
	    case NETF_OP(NETF_RSH):
		j = OP_SRW;
logical:
		*instp++ = LOGIC_OP(j, dst, reg1, reg);
		break;
	    case NETF_OP(NETF_ADD):
		j = OP_ADD;
		goto arithmetical;
	    case NETF_OP(NETF_SUB):
		j = OP_SUBF;	/* First reg subtracted from second. */
arithmetical:
		*instp++ = ARITH_OP(j, dst, reg, reg1);
		*instp++ = ANDI(dst, dst, 0xffff);
		break;
	    case NETF_OP(NETF_LSH):
		*instp++ = RLWNM(dst, reg1, reg, 16, 31);
		break;
	    case NETF_OP(NETF_COR):
	    case NETF_OP(NETF_CNAND):
		*instp++ = CMPL(reg1, reg);
		*instp++ = BCLR((op == NETF_OP(NETF_COR)) ? COND_EQ : COND_NE);
		break;
	    case NETF_OP(NETF_CAND):
	    case NETF_OP(NETF_CNOR):
		*instp++ = CMPL(reg1, reg);
		*instp = BC((op == NETF_OP(NETF_CAND)) ? COND_NE : COND_EQ,
			    returnfalse - instp);
		instp++;
		break;
	    default:
		printf("op == 0x%x\n", op);
		panic("net_filter_alloc: bad op");
		/* Should have been caught by parse_net_filter(). */
	    }
	    /* If the op generated a result, push it on the stack. */
	    if (dst >= 0) {
		s->stackregs[++sp] = dst;
		s->regs[dst].stacktimes++;
	    }
	    if (!compiling) {
		assert(instp - junk_filter <= MAX_INSTR_PER_ITEM);
		len += instp - junk_filter;
	    }
	}
	if (compiling) {
	    /* If the stack contains any values, we are supposed to return 0 or
	       1 according as the top-of-stack is zero or not.  Since the only
	       place we are called requires just zero-false/nonzero-true, we
	       simply copy the value into r3.  If the stack is empty, we
	       leave the pointer value r3 intact to return TRUE.  */
	    if (sp >= 0)
		*instp++ = MR(REG_RET, s->stackregs[sp]);
	    *instp++ = BLR();
	    /* Branch here to return false.  We could avoid adding these
	       instructions if they are not used, but practically every
	       filter does use them (for failure values when trying to
	       access values beyond the header or data length) so it's
	       not worth the effort.  */
	    assert(instp == returnfalse);
	    *instp++ = LI(REG_RET, 0);
	    *instp++ = BLR();
	    break;
	} else {
	    len += 1 + (sp >= 0);
			/* For the reach-the-end return instruction(s).  */
#if USE_EXTRA_REGS
	    if (s->maxreg > oldmaxreg) {
		len = 0;
		continue;
	    }
#endif
	    len += compile_preamble(NULL, s);
	    returnfalseoffset = len;
	    len += 2;	/* For the return-false instructions.  */
	}
	if ((instructions = (int *) kalloc(len * sizeof (int))) == NULL)
	    return NULL;
	returnfalse = instructions + returnfalseoffset;
	instp = instructions;
	instp += compile_preamble(instp, s);
	compiling = TRUE;
    }

    assert(instp - instructions == len);
    *lenp = len * sizeof (int);
    {
	kern_return_t kr;
	vm_machine_attribute_val_t val = MATTR_VAL_CACHE_SYNC;

	kr = pmap_attribute(kernel_pmap, (vm_offset_t) instructions,
			    len * sizeof (int), MATTR_CACHE, &val);
	if (kr != KERN_SUCCESS) {
	    printf("net_filter_alloc: pmap_attribute -> 0x%x\n", kr);
	    return NULL;
	}
    }
    kfree((vm_offset_t) s, sizeof *s);
    return (filter_fct_t) instructions;
fail:
    assert(!compiling);
    kfree((vm_offset_t) s, sizeof *s);
    printf("net_filter_alloc: failed to compile (filter too complex)\n");
    printf("-- will work, but more slowly; consider enabling USE_EXTRA_REGS\n");
    return NULL;
}


/* Allocate a register.  Registers that are already being used to make up
   the virtual stack are ineligible.  Among the others, we choose the one
   whose value has the least number of subsequent uses (ideally, and
   usually, 0) of the common value it already holds.  If commoni is >=
   0, it is the index in common[] of the value we are going to put in
   the allocated register, so we can update the various data structures
   appropriately.  */
int
allocate_register(struct local *s, int commoni)
{
    int i, reg, bestreg, nuses, bestregnuses, maxreg;

    bestreg = NO_REG;
#if USE_EXTRA_REGS
    maxreg = s->maxreg;
#else
    maxreg = NSCRATCHREGS;
#endif
    while (1) {
	bestregnuses = NOT_COMMON_VALUE;
	for (i = 0; i < maxreg; i++) {
	    reg = scratchregs[i];
	    if (s->regs[reg].stacktimes == 0) {
		nuses = (s->regs[reg].commoni == NOT_COMMON_VALUE) ?
			0 : s->common[s->regs[reg].commoni].nuses;
		if (nuses < bestregnuses) {
		    bestreg = reg;
		    bestregnuses = nuses;
		}
	    }
	}
	if (bestreg != NO_REG)
	    break;
#if USE_EXTRA_REGS
	if (maxreg == NSCRATCHREGS)
	    return NO_REG;
	s->maxreg = ++maxreg;
#else
	return NO_REG;
#endif
    }
    if (bestregnuses > 0)
	printf("net_filter_alloc: forced to reallocate r%d\n", bestreg);
	/* With USE_EXTRA_REGS, we could push up the number of registers
	   here to have one extra available for common values, but it's usually
	   not worth the overhead of the extra save-and-restore in the preamble.
	   Anyway, this never happens with typical filters.  */
    if (s->regs[bestreg].commoni != NOT_COMMON_VALUE)
	s->common[s->regs[bestreg].commoni].reg = NO_REG;
    if (commoni >= 0) {
	s->regs[bestreg].commoni = commoni;
	s->common[commoni].reg = bestreg;
    } else
	s->regs[bestreg].commoni = NOT_COMMON_VALUE;
    return bestreg;
}


#define FIXED_PREAMBLE_INSTRUCTIONS 1

int
compile_preamble(int *instructions, struct local *s)
{
    int *instp;
    int len = FIXED_PREAMBLE_INSTRUCTIONS;
#if USE_EXTRA_REGS
#error this hp code must be ported to the ppc
    int extra_regs, i, j, t, disp;

    extra_regs = s->maxreg - INITIAL_NSCRATCHREGS;
    if (extra_regs > 0) {
	len = extra_regs * 2 + 4;
	/* stw rp | (n-1) * stw | bl | stw | ldw rp | (n-1) * ldw | bv | ldw */
    } else
	return 0;
#endif
    if (instructions == NULL)
	return len;
    instp = instructions;

    *instp++ = LI(REG_ZERO, 0);
    assert(instp - instructions == FIXED_PREAMBLE_INSTRUCTIONS);

#if USE_EXTRA_REGS
#error this hp code must be ported to the ppc
    /* Generate a wrapper function to save the callee-saves registers
       before invoking the filter code we have generated.  It would be
       marginally better to have the filter branch directly to the
       postamble code on return, but the difference is trivial and it
       is easier to have it always branch to (rp).  */
#define FRAME_SIZE 128	/* This is plenty without being excessive. */
    *instp++ = STW_NEG(REG_RTN, 20, REG_SP);		/* stw rp,-20(sp) */
    i = INITIAL_NSCRATCHREGS;
    t = STWM(scratchregs[i], FRAME_SIZE, REG_SP);	/* stwm r3,128(sp) */
    j = FRAME_SIZE;
    while (++i < s->maxreg) {
	*instp++ = t;
	j -= sizeof (int);
	t = STW_NEG(scratchregs[i], j, REG_SP);		/* stw r4,-124(sp) &c */
    }
    disp = extra_regs + 2;	/* n * ldw | bv | ldw rp */
    *instp++ = BL(disp, REG_RTN);			/* bl filter,rp */
    *instp++ = t;					/* stw in delay slot */
    *instp++ = LDW_NEG(FRAME_SIZE + 20, REG_SP, REG_RTN);
							/* ldw -148(sp),rp */
    while (--i > INITIAL_NSCRATCHREGS) {
	*instp++ = LDW_NEG(j, REG_SP, scratchregs[i]);	/* ldw -124(sp),r4 &c */
	j += sizeof (int);
    }
    *instp++ = BV(0, REG_RTN);				/* bv (rp) */
    *instp++ = LDWM_NEG(FRAME_SIZE, REG_SP, scratchregs[i]);
							/* ldwm -128(sp),r3
							   in delay slot */
#endif

    assert(instp - instructions == len);
    return len;
}

void
net_filter_free(filter_fct_t fp, unsigned int len)
{
    kfree((vm_offset_t) fp, len);
}

#else	/* NET_FILTER_COMPILER */

/*
 *	Compilation of a source network filter into ppc instructions
 *	- a small version that doesnt do anything, but doesn't take
 *	up any space either. Note that if using a single mklinux server
 *	with ethertalk enabled (standard situation), the filter passes
 *	everything through so no need to compile one. If running multi
 *      servers then there is more of a need. Ethertalk (in linux server)
 *      should really have a packet filter, but at time of writing
 *	it does not.
 */
filter_fct_t
net_filter_alloc(
	filter_t	*fpstart,
	unsigned int	fplen,
	unsigned int	*len)
{
	*len = 0;
	return ((filter_fct_t)0);
}

void
net_filter_free(
	filter_fct_t	fp,
	unsigned int	len)
{
	assert(fp == (filter_fct_t)0 && len == 0);
}
#endif	/* NET_FILTER_COMPILER */
