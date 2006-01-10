/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:36  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:37  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.2.8.3  1996/07/31  09:43:35  paire
 * 	Merged with nmk20b7_shared (1.2.11.1)
 * 	[96/06/10            paire]
 *
 * Revision 1.2.11.1  1996/05/14  13:49:36  paire
 * 	Added support for new cmpxchg8b, cpuid, rdtsc, rdwmr, rsm and wrmsr
 * 	Pentium instructions
 * 	[95/11/23            paire]
 * 
 * Revision 1.2.8.2  1994/09/23  01:50:45  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:21:17  ezf]
 * 
 * Revision 1.2.8.1  1994/09/16  15:26:28  emcmanus
 * 	Only skip over GAS-inserted NOPs after branches if they are really
 * 	NOPs; this depends at least on assembler options.
 * 	[1994/09/16  15:26:03  emcmanus]
 * 
 * Revision 1.2.6.3  1994/02/19  15:40:34  bolinger
 * 	For load/store counting, mark all varieties of "call" as writing
 * 	memory.
 * 	[1994/02/15  20:25:18  bolinger]
 * 
 * Revision 1.2.6.2  1994/02/14  21:46:49  dwm
 * 	Warning repair
 * 	[1994/02/14  21:46:14  dwm]
 * 
 * Revision 1.2.6.1  1994/02/12  23:26:05  bolinger
 * 	Implement load/store counting for ddb "until" command.
 * 	[1994/02/12  03:34:55  bolinger]
 * 
 * Revision 1.2.2.3  1993/08/09  19:39:21  dswartz
 * 	Add ANSI prototypes - CR#9523
 * 	[1993/08/06  17:44:13  dswartz]
 * 
 * Revision 1.2.2.2  1993/06/09  02:27:29  gm
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:03:54  jeffc]
 * 
 * Revision 1.2  1993/04/19  16:12:57  devrcs
 * 	Print file names and lineno on branch instructions.
 * 	[barbou@gr.osf.org]
 * 	[92/12/03            bernadat]
 * 
 * Revision 1.1  1992/09/30  02:02:19  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.5.3.1  92/03/03  16:14:27  jeffreyh
 * 	Pick up changes from TRUNK
 * 	[92/02/26  11:05:06  jeffreyh]
 * 
 * Revision 2.6  92/01/03  20:05:00  dbg
 * 	Add a switch to disassemble 16-bit code.
 * 	Fix spelling of 'lods' opcodes.
 * 	[91/10/30            dbg]
 * 
 * Revision 2.5  91/10/09  16:05:58  af
 * 	Supported disassemble of non current task by passing task parameter.
 * 	[91/08/29            tak]
 * 
 * Revision 2.4  91/05/14  16:05:04  mrt
 * 	Correcting copyright
 * 
 * Revision 2.3  91/02/05  17:11:03  mrt
 * 	Changed to new Mach copyright
 * 	[91/02/01  17:31:03  mrt]
 * 
 * Revision 2.2  90/08/27  21:55:56  dbg
 * 	Fix register operand for move to/from control/test/debug
 * 	register instructions.  Add i486 instructions.
 * 	[90/08/27            dbg]
 * 
 * 	Import db_sym.h.  Print instruction displacements in
 * 	current radix (signed).  Change calling sequence of
 * 	db_disasm.
 * 	[90/08/21            dbg]
 * 	Fix includes.
 * 	[90/08/08            dbg]
 * 	Created.
 * 	[90/07/25            dbg]
 * 
 */
/* CMU_ENDHIST */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */

/*
 * Instruction disassembler.
 */

#include <mach/boolean.h>
#include <machine/db_machdep.h>

#include <ddb/db_access.h>
#include <ddb/db_sym.h>
#include <ddb/db_output.h>

#include <kern/task.h>
#include <kern/misc_protos.h>

struct i_addr {
	int		is_reg;	/* if reg, reg number is in 'disp' */
	int		disp;
	char *		base;
	char *		index;
	int		ss;
};

/* Forward */

extern db_addr_t	db_read_address(
				db_addr_t	loc,
				int		short_addr,
				int		regmodrm,
				struct i_addr	* addrp,
				task_t		task);
extern void		db_print_address(
				char *		seg,
				int		size,
				struct i_addr	*addrp,
				task_t		task);
extern db_addr_t	db_disasm_esc(
				db_addr_t	loc,
				int		inst,
				int		short_addr,
				int		size,
				char *		seg,
				task_t		task);

/*
 * Switch to disassemble 16-bit code.
 */
boolean_t	db_disasm_16 = FALSE;

/*
 * Size attributes
 */
#define	BYTE	0
#define	WORD	1
#define	LONG	2
#define	QUAD	3
#define	SNGL	4
#define	DBLR	5
#define	EXTR	6
#define	SDEP	7
#define	NONE	8

/*
 * Addressing modes
 */
#define	E	1			/* general effective address */
#define	Eind	2			/* indirect address (jump, call) */
#define	Ew	3			/* address, word size */
#define	Eb	4			/* address, byte size */
#define	R	5			/* register, in 'reg' field */
#define	Rw	6			/* word register, in 'reg' field */
#define	Ri	7			/* register in instruction */
#define	S	8			/* segment reg, in 'reg' field */
#define	Si	9			/* segment reg, in instruction */
#define	A	10			/* accumulator */
#define	BX	11			/* (bx) */
#define	CL	12			/* cl, for shifts */
#define	DX	13			/* dx, for IO */
#define	SI	14			/* si */
#define	DI	15			/* di */
#define	CR	16			/* control register */
#define	DR	17			/* debug register */
#define	TR	18			/* test register */
#define	I	19			/* immediate, unsigned */
#define	Is	20			/* immediate, signed */
#define	Ib	21			/* byte immediate, unsigned */
#define	Ibs	22			/* byte immediate, signed */
#define	Iw	23			/* word immediate, unsigned */
#define	Il	24			/* long immediate */
#define	O	25			/* direct address */
#define	Db	26			/* byte displacement from EIP */
#define	Dl	27			/* long displacement from EIP */
#define	o1	28			/* constant 1 */
#define	o3	29			/* constant 3 */
#define	OS	30			/* immediate offset/segment */
#define	ST	31			/* FP stack top */
#define	STI	32			/* FP stack */
#define	X	33			/* extended FP op */
#define	XA	34			/* for 'fstcw %ax' */

struct inst {
	char *	i_name;			/* name */
	short	i_has_modrm;		/* has regmodrm byte */
	short	i_size;			/* operand size */
	int	i_mode;			/* addressing modes */
	char *	i_extra;		/* pointer to extra opcode table */
};

#define	op1(x)		(x)
#define	op2(x,y)	((x)|((y)<<8))
#define	op3(x,y,z)	((x)|((y)<<8)|((z)<<16))

struct finst {
	char *	f_name;			/* name for memory instruction */
	int	f_size;			/* size for memory instruction */
	int	f_rrmode;		/* mode for rr instruction */
	char *	f_rrname;		/* name for rr instruction
					   (or pointer to table) */
};

char *	db_Grp6[] = {
	"sldt",
	"str",
	"lldt",
	"ltr",
	"verr",
	"verw",
	"",
	""
};

char *	db_Grp7[] = {
	"sgdt",
	"sidt",
	"lgdt",
	"lidt",
	"smsw",
	"",
	"lmsw",
	"invlpg"
};

char *	db_Grp8[] = {
	"",
	"",
	"",
	"",
	"bt",
	"bts",
	"btr",
	"btc"
};

struct inst db_inst_0f0x[] = {
/*00*/	{ "",	   TRUE,  NONE,  op1(Ew),     (char *)db_Grp6 },
/*01*/	{ "",	   TRUE,  NONE,  op1(Ew),     (char *)db_Grp7 },
/*02*/	{ "lar",   TRUE,  LONG,  op2(E,R),    0 },
/*03*/	{ "lsl",   TRUE,  LONG,  op2(E,R),    0 },
/*04*/	{ "",      FALSE, NONE,  0,	      0 },
/*05*/	{ "",      FALSE, NONE,  0,	      0 },
/*06*/	{ "clts",  FALSE, NONE,  0,	      0 },
/*07*/	{ "",      FALSE, NONE,  0,	      0 },

/*08*/	{ "invd",  FALSE, NONE,  0,	      0 },
/*09*/	{ "wbinvd",FALSE, NONE,  0,	      0 },
/*0a*/	{ "",      FALSE, NONE,  0,	      0 },
/*0b*/	{ "",      FALSE, NONE,  0,	      0 },
/*0c*/	{ "",      FALSE, NONE,  0,	      0 },
/*0d*/	{ "",      FALSE, NONE,  0,	      0 },
/*0e*/	{ "",      FALSE, NONE,  0,	      0 },
/*0f*/	{ "",      FALSE, NONE,  0,	      0 },
};

struct inst	db_inst_0f2x[] = {
/*20*/	{ "mov",   TRUE,  LONG,  op2(CR,E),   0 }, /* use E for reg */
/*21*/	{ "mov",   TRUE,  LONG,  op2(DR,E),   0 }, /* since mod == 11 */
/*22*/	{ "mov",   TRUE,  LONG,  op2(E,CR),   0 },
/*23*/	{ "mov",   TRUE,  LONG,  op2(E,DR),   0 },
/*24*/	{ "mov",   TRUE,  LONG,  op2(TR,E),   0 },
/*25*/	{ "",      FALSE, NONE,  0,	      0 },
/*26*/	{ "mov",   TRUE,  LONG,  op2(E,TR),   0 },
/*27*/	{ "",      FALSE, NONE,  0,	      0 },

/*28*/	{ "",      FALSE, NONE,  0,	      0 },
/*29*/	{ "",      FALSE, NONE,  0,	      0 },
/*2a*/	{ "",      FALSE, NONE,  0,	      0 },
/*2b*/	{ "",      FALSE, NONE,  0,	      0 },
/*2c*/	{ "",      FALSE, NONE,  0,	      0 },
/*2d*/	{ "",      FALSE, NONE,  0,	      0 },
/*2e*/	{ "",      FALSE, NONE,  0,	      0 },
/*2f*/	{ "",      FALSE, NONE,  0,	      0 },
};
struct inst	db_inst_0f3x[] = {
/*30*/	{ "rdtsc", FALSE, NONE,  0,	      0 },
/*31*/	{ "rdmsr", FALSE, NONE,  0,	      0 },
/*32*/	{ "wrmsr", FALSE, NONE,  0,	      0 },
/*33*/	{ "",      FALSE, NONE,  0,	      0 },
/*34*/	{ "",      FALSE, NONE,  0,	      0 },
/*35*/	{ "",      FALSE, NONE,  0,	      0 },
/*36*/	{ "",      FALSE, NONE,  0,	      0 },
/*37*/	{ "",      FALSE, NONE,  0,	      0 },

/*38*/	{ "",      FALSE, NONE,  0,	      0 },
/*39*/	{ "",      FALSE, NONE,  0,	      0 },
/*3a*/	{ "",      FALSE, NONE,  0,	      0 },
/*3b*/	{ "",      FALSE, NONE,  0,	      0 },
/*3c*/	{ "",      FALSE, NONE,  0,	      0 },
/*3d*/	{ "",      FALSE, NONE,  0,	      0 },
/*3e*/	{ "",      FALSE, NONE,  0,	      0 },
/*3f*/	{ "",      FALSE, NONE,  0,	      0 },
};

struct inst	db_inst_0f8x[] = {
/*80*/	{ "jo",    FALSE, NONE,  op1(Dl),     0 },
/*81*/	{ "jno",   FALSE, NONE,  op1(Dl),     0 },
/*82*/	{ "jb",    FALSE, NONE,  op1(Dl),     0 },
/*83*/	{ "jnb",   FALSE, NONE,  op1(Dl),     0 },
/*84*/	{ "jz",    FALSE, NONE,  op1(Dl),     0 },
/*85*/	{ "jnz",   FALSE, NONE,  op1(Dl),     0 },
/*86*/	{ "jbe",   FALSE, NONE,  op1(Dl),     0 },
/*87*/	{ "jnbe",  FALSE, NONE,  op1(Dl),     0 },

/*88*/	{ "js",    FALSE, NONE,  op1(Dl),     0 },
/*89*/	{ "jns",   FALSE, NONE,  op1(Dl),     0 },
/*8a*/	{ "jp",    FALSE, NONE,  op1(Dl),     0 },
/*8b*/	{ "jnp",   FALSE, NONE,  op1(Dl),     0 },
/*8c*/	{ "jl",    FALSE, NONE,  op1(Dl),     0 },
/*8d*/	{ "jnl",   FALSE, NONE,  op1(Dl),     0 },
/*8e*/	{ "jle",   FALSE, NONE,  op1(Dl),     0 },
/*8f*/	{ "jnle",  FALSE, NONE,  op1(Dl),     0 },
};

struct inst	db_inst_0f9x[] = {
/*90*/	{ "seto",  TRUE,  NONE,  op1(Eb),     0 },
/*91*/	{ "setno", TRUE,  NONE,  op1(Eb),     0 },
/*92*/	{ "setb",  TRUE,  NONE,  op1(Eb),     0 },
/*93*/	{ "setnb", TRUE,  NONE,  op1(Eb),     0 },
/*94*/	{ "setz",  TRUE,  NONE,  op1(Eb),     0 },
/*95*/	{ "setnz", TRUE,  NONE,  op1(Eb),     0 },
/*96*/	{ "setbe", TRUE,  NONE,  op1(Eb),     0 },
/*97*/	{ "setnbe",TRUE,  NONE,  op1(Eb),     0 },

/*98*/	{ "sets",  TRUE,  NONE,  op1(Eb),     0 },
/*99*/	{ "setns", TRUE,  NONE,  op1(Eb),     0 },
/*9a*/	{ "setp",  TRUE,  NONE,  op1(Eb),     0 },
/*9b*/	{ "setnp", TRUE,  NONE,  op1(Eb),     0 },
/*9c*/	{ "setl",  TRUE,  NONE,  op1(Eb),     0 },
/*9d*/	{ "setnl", TRUE,  NONE,  op1(Eb),     0 },
/*9e*/	{ "setle", TRUE,  NONE,  op1(Eb),     0 },
/*9f*/	{ "setnle",TRUE,  NONE,  op1(Eb),     0 },
};

struct inst	db_inst_0fax[] = {
/*a0*/	{ "push",  FALSE, NONE,  op1(Si),     0 },
/*a1*/	{ "pop",   FALSE, NONE,  op1(Si),     0 },
/*a2*/	{ "cpuid", FALSE, NONE,  0,	      0 },
/*a3*/	{ "bt",    TRUE,  LONG,  op2(E,R),    0 },
/*a4*/	{ "shld",  TRUE,  LONG,  op3(Ib,E,R), 0 },
/*a5*/	{ "shld",  TRUE,  LONG,  op3(CL,E,R), 0 },
/*a6*/	{ "",      FALSE, NONE,  0,	      0 },
/*a7*/	{ "",      FALSE, NONE,  0,	      0 },

/*a8*/	{ "push",  FALSE, NONE,  op1(Si),     0 },
/*a9*/	{ "pop",   FALSE, NONE,  op1(Si),     0 },
/*aa*/	{ "rsm",   FALSE, NONE,  0,	      0 },
/*ab*/	{ "bts",   TRUE,  LONG,  op2(E,R),    0 },
/*ac*/	{ "shrd",  TRUE,  LONG,  op3(Ib,E,R), 0 },
/*ad*/	{ "shrd",  TRUE,  LONG,  op3(CL,E,R), 0 },
/*a6*/	{ "",      FALSE, NONE,  0,	      0 },
/*a7*/	{ "imul",  TRUE,  LONG,  op2(E,R),    0 },
};

struct inst	db_inst_0fbx[] = {
/*b0*/	{ "",      FALSE, NONE,  0,	      0 },
/*b1*/	{ "",      FALSE, NONE,  0,	      0 },
/*b2*/	{ "lss",   TRUE,  LONG,  op2(E, R),   0 },
/*b3*/	{ "bts",   TRUE,  LONG,  op2(R, E),   0 },
/*b4*/	{ "lfs",   TRUE,  LONG,  op2(E, R),   0 },
/*b5*/	{ "lgs",   TRUE,  LONG,  op2(E, R),   0 },
/*b6*/	{ "movzb", TRUE,  LONG,  op2(E, R),   0 },
/*b7*/	{ "movzw", TRUE,  LONG,  op2(E, R),   0 },

/*b8*/	{ "",      FALSE, NONE,  0,	      0 },
/*b9*/	{ "",      FALSE, NONE,  0,	      0 },
/*ba*/	{ "",      TRUE,  LONG,  op2(Is, E),  (char *)db_Grp8 },
/*bb*/	{ "btc",   TRUE,  LONG,  op2(R, E),   0 },
/*bc*/	{ "bsf",   TRUE,  LONG,  op2(E, R),   0 },
/*bd*/	{ "bsr",   TRUE,  LONG,  op2(E, R),   0 },
/*be*/	{ "movsb", TRUE,  LONG,  op2(E, R),   0 },
/*bf*/	{ "movsw", TRUE,  LONG,  op2(E, R),   0 },
};

struct inst	db_inst_0fcx[] = {
/*c0*/	{ "xadd",  TRUE,  BYTE,	 op2(R, E),   0 },
/*c1*/	{ "xadd",  TRUE,  LONG,	 op2(R, E),   0 },
/*c2*/	{ "",	   FALSE, NONE,	 0,	      0 },
/*c3*/	{ "",	   FALSE, NONE,	 0,	      0 },
/*c4*/	{ "",	   FALSE, NONE,	 0,	      0 },
/*c5*/	{ "",	   FALSE, NONE,	 0,	      0 },
/*c6*/	{ "",	   FALSE, NONE,	 0,	      0 },
/*c7*/	{ "cmpxchg8b", FALSE, NONE, op1(E),   0 },
/*c8*/	{ "bswap", FALSE, LONG,  op1(Ri),     0 },
/*c9*/	{ "bswap", FALSE, LONG,  op1(Ri),     0 },
/*ca*/	{ "bswap", FALSE, LONG,  op1(Ri),     0 },
/*cb*/	{ "bswap", FALSE, LONG,  op1(Ri),     0 },
/*cc*/	{ "bswap", FALSE, LONG,  op1(Ri),     0 },
/*cd*/	{ "bswap", FALSE, LONG,  op1(Ri),     0 },
/*ce*/	{ "bswap", FALSE, LONG,  op1(Ri),     0 },
/*cf*/	{ "bswap", FALSE, LONG,  op1(Ri),     0 },
};

struct inst	db_inst_0fdx[] = {
/*c0*/	{ "cmpxchg",TRUE, BYTE,	 op2(R, E),   0 },
/*c1*/	{ "cmpxchg",TRUE, LONG,	 op2(R, E),   0 },
/*c2*/	{ "",	   FALSE, NONE,	 0,	      0 },
/*c3*/	{ "",	   FALSE, NONE,	 0,	      0 },
/*c4*/	{ "",	   FALSE, NONE,	 0,	      0 },
/*c5*/	{ "",	   FALSE, NONE,	 0,	      0 },
/*c6*/	{ "",	   FALSE, NONE,	 0,	      0 },
/*c7*/	{ "",	   FALSE, NONE,	 0,	      0 },
/*c8*/	{ "",	   FALSE, NONE,	 0,	      0 },
/*c9*/	{ "",	   FALSE, NONE,	 0,	      0 },
/*ca*/	{ "",	   FALSE, NONE,	 0,	      0 },
/*cb*/	{ "",	   FALSE, NONE,	 0,	      0 },
/*cc*/	{ "",	   FALSE, NONE,	 0,	      0 },
/*cd*/	{ "",	   FALSE, NONE,	 0,	      0 },
/*ce*/	{ "",	   FALSE, NONE,	 0,	      0 },
/*cf*/	{ "",	   FALSE, NONE,	 0,	      0 },
};

struct inst *db_inst_0f[] = {
	db_inst_0f0x,
	0,
	db_inst_0f2x,
	db_inst_0f3x,
	0,
	0,
	0,
	0,
	db_inst_0f8x,
	db_inst_0f9x,
	db_inst_0fax,
	db_inst_0fbx,
	db_inst_0fcx,
	db_inst_0fdx,
	0,
	0
};

char *	db_Esc92[] = {
	"fnop",	"",	"",	"",	"",	"",	"",	""
};
char *	db_Esc93[] = {
	"",	"",	"",	"",	"",	"",	"",	""
};
char *	db_Esc94[] = {
	"fchs",	"fabs",	"",	"",	"ftst",	"fxam",	"",	""
};
char *	db_Esc95[] = {
	"fld1",	"fldl2t","fldl2e","fldpi","fldlg2","fldln2","fldz",""
};
char *	db_Esc96[] = {
	"f2xm1","fyl2x","fptan","fpatan","fxtract","fprem1","fdecstp",
	"fincstp"
};
char *	db_Esc97[] = {
	"fprem","fyl2xp1","fsqrt","fsincos","frndint","fscale","fsin","fcos"
};

char *	db_Esca4[] = {
	"",	"fucompp","",	"",	"",	"",	"",	""
};

char *	db_Escb4[] = {
	"",	"",	"fnclex","fninit","",	"",	"",	""
};

char *	db_Esce3[] = {
	"",	"fcompp","",	"",	"",	"",	"",	""
};

char *	db_Escf4[] = {
	"fnstsw","",	"",	"",	"",	"",	"",	""
};

struct finst db_Esc8[] = {
/*0*/	{ "fadd",   SNGL,  op2(STI,ST),	0 },
/*1*/	{ "fmul",   SNGL,  op2(STI,ST),	0 },
/*2*/	{ "fcom",   SNGL,  op2(STI,ST),	0 },
/*3*/	{ "fcomp",  SNGL,  op2(STI,ST),	0 },
/*4*/	{ "fsub",   SNGL,  op2(STI,ST),	0 },
/*5*/	{ "fsubr",  SNGL,  op2(STI,ST),	0 },
/*6*/	{ "fdiv",   SNGL,  op2(STI,ST),	0 },
/*7*/	{ "fdivr",  SNGL,  op2(STI,ST),	0 },
};

struct finst db_Esc9[] = {
/*0*/	{ "fld",    SNGL,  op1(STI),	0 },
/*1*/	{ "",       NONE,  op1(STI),	"fxch" },
/*2*/	{ "fst",    SNGL,  op1(X),	(char *)db_Esc92 },
/*3*/	{ "fstp",   SNGL,  op1(X),	(char *)db_Esc93 },
/*4*/	{ "fldenv", NONE,  op1(X),	(char *)db_Esc94 },
/*5*/	{ "fldcw",  NONE,  op1(X),	(char *)db_Esc95 },
/*6*/	{ "fnstenv",NONE,  op1(X),	(char *)db_Esc96 },
/*7*/	{ "fnstcw", NONE,  op1(X),	(char *)db_Esc97 },
};

struct finst db_Esca[] = {
/*0*/	{ "fiadd",  WORD,  0,		0 },
/*1*/	{ "fimul",  WORD,  0,		0 },
/*2*/	{ "ficom",  WORD,  0,		0 },
/*3*/	{ "ficomp", WORD,  0,		0 },
/*4*/	{ "fisub",  WORD,  op1(X),	(char *)db_Esca4 },
/*5*/	{ "fisubr", WORD,  0,		0 },
/*6*/	{ "fidiv",  WORD,  0,		0 },
/*7*/	{ "fidivr", WORD,  0,		0 }
};

struct finst db_Escb[] = {
/*0*/	{ "fild",   WORD,  0,		0 },
/*1*/	{ "",       NONE,  0,		0 },
/*2*/	{ "fist",   WORD,  0,		0 },
/*3*/	{ "fistp",  WORD,  0,		0 },
/*4*/	{ "",       WORD,  op1(X),	(char *)db_Escb4 },
/*5*/	{ "fld",    EXTR,  0,		0 },
/*6*/	{ "",       WORD,  0,		0 },
/*7*/	{ "fstp",   EXTR,  0,		0 },
};

struct finst db_Escc[] = {
/*0*/	{ "fadd",   DBLR,  op2(ST,STI),	0 },
/*1*/	{ "fmul",   DBLR,  op2(ST,STI),	0 },
/*2*/	{ "fcom",   DBLR,  op2(ST,STI),	0 },
/*3*/	{ "fcomp",  DBLR,  op2(ST,STI),	0 },
/*4*/	{ "fsub",   DBLR,  op2(ST,STI),	"fsubr" },
/*5*/	{ "fsubr",  DBLR,  op2(ST,STI),	"fsub" },
/*6*/	{ "fdiv",   DBLR,  op2(ST,STI),	"fdivr" },
/*7*/	{ "fdivr",  DBLR,  op2(ST,STI),	"fdiv" },
};

struct finst db_Escd[] = {
/*0*/	{ "fld",    DBLR,  op1(STI),	"ffree" },
/*1*/	{ "",       NONE,  0,		0 },
/*2*/	{ "fst",    DBLR,  op1(STI),	0 },
/*3*/	{ "fstp",   DBLR,  op1(STI),	0 },
/*4*/	{ "frstor", NONE,  op1(STI),	"fucom" },
/*5*/	{ "",       NONE,  op1(STI),	"fucomp" },
/*6*/	{ "fnsave", NONE,  0,		0 },
/*7*/	{ "fnstsw", NONE,  0,		0 },
};

struct finst db_Esce[] = {
/*0*/	{ "fiadd",  LONG,  op2(ST,STI),	"faddp" },
/*1*/	{ "fimul",  LONG,  op2(ST,STI),	"fmulp" },
/*2*/	{ "ficom",  LONG,  0,		0 },
/*3*/	{ "ficomp", LONG,  op1(X),	(char *)db_Esce3 },
/*4*/	{ "fisub",  LONG,  op2(ST,STI),	"fsubrp" },
/*5*/	{ "fisubr", LONG,  op2(ST,STI),	"fsubp" },
/*6*/	{ "fidiv",  LONG,  op2(ST,STI),	"fdivrp" },
/*7*/	{ "fidivr", LONG,  op2(ST,STI),	"fdivp" },
};

struct finst db_Escf[] = {
/*0*/	{ "fild",   LONG,  0,		0 },
/*1*/	{ "",       LONG,  0,		0 },
/*2*/	{ "fist",   LONG,  0,		0 },
/*3*/	{ "fistp",  LONG,  0,		0 },
/*4*/	{ "fbld",   NONE,  op1(XA),	(char *)db_Escf4 },
/*5*/	{ "fld",    QUAD,  0,		0 },
/*6*/	{ "fbstp",  NONE,  0,		0 },
/*7*/	{ "fstp",   QUAD,  0,		0 },
};

struct finst *db_Esc_inst[] = {
	db_Esc8, db_Esc9, db_Esca, db_Escb,
	db_Escc, db_Escd, db_Esce, db_Escf
};

char *	db_Grp1[] = {
	"add",
	"or",
	"adc",
	"sbb",
	"and",
	"sub",
	"xor",
	"cmp"
};

char *	db_Grp2[] = {
	"rol",
	"ror",
	"rcl",
	"rcr",
	"shl",
	"shr",
	"shl",
	"sar"
};

struct inst db_Grp3[] = {
	{ "test",  TRUE, NONE, op2(I,E), 0 },
	{ "test",  TRUE, NONE, op2(I,E), 0 },
	{ "not",   TRUE, NONE, op1(E),   0 },
	{ "neg",   TRUE, NONE, op1(E),   0 },
	{ "mul",   TRUE, NONE, op2(E,A), 0 },
	{ "imul",  TRUE, NONE, op2(E,A), 0 },
	{ "div",   TRUE, NONE, op2(E,A), 0 },
	{ "idiv",  TRUE, NONE, op2(E,A), 0 },
};

struct inst	db_Grp4[] = {
	{ "inc",   TRUE, BYTE, op1(E),   0 },
	{ "dec",   TRUE, BYTE, op1(E),   0 },
	{ "",      TRUE, NONE, 0,	 0 },
	{ "",      TRUE, NONE, 0,	 0 },
	{ "",      TRUE, NONE, 0,	 0 },
	{ "",      TRUE, NONE, 0,	 0 },
	{ "",      TRUE, NONE, 0,	 0 },
	{ "",      TRUE, NONE, 0,	 0 }
};

struct inst	db_Grp5[] = {
	{ "inc",   TRUE, LONG, op1(E),   0 },
	{ "dec",   TRUE, LONG, op1(E),   0 },
	{ "call",  TRUE, NONE, op1(Eind),0 },
	{ "lcall", TRUE, NONE, op1(Eind),0 },
	{ "jmp",   TRUE, NONE, op1(Eind),0 },
	{ "ljmp",  TRUE, NONE, op1(Eind),0 },
	{ "push",  TRUE, LONG, op1(E),   0 },
	{ "",      TRUE, NONE, 0,	 0 }
};

struct inst db_inst_table[256] = {
/*00*/	{ "add",   TRUE,  BYTE,  op2(R, E),  0 },
/*01*/	{ "add",   TRUE,  LONG,  op2(R, E),  0 },
/*02*/	{ "add",   TRUE,  BYTE,  op2(E, R),  0 },
/*03*/	{ "add",   TRUE,  LONG,  op2(E, R),  0 },
/*04*/	{ "add",   FALSE, BYTE,  op2(Is, A), 0 },
/*05*/	{ "add",   FALSE, LONG,  op2(Is, A), 0 },
/*06*/	{ "push",  FALSE, NONE,  op1(Si),    0 },
/*07*/	{ "pop",   FALSE, NONE,  op1(Si),    0 },

/*08*/	{ "or",    TRUE,  BYTE,  op2(R, E),  0 },
/*09*/	{ "or",    TRUE,  LONG,  op2(R, E),  0 },
/*0a*/	{ "or",    TRUE,  BYTE,  op2(E, R),  0 },
/*0b*/	{ "or",    TRUE,  LONG,  op2(E, R),  0 },
/*0c*/	{ "or",    FALSE, BYTE,  op2(I, A),  0 },
/*0d*/	{ "or",    FALSE, LONG,  op2(I, A),  0 },
/*0e*/	{ "push",  FALSE, NONE,  op1(Si),    0 },
/*0f*/	{ "",      FALSE, NONE,  0,	     0 },

/*10*/	{ "adc",   TRUE,  BYTE,  op2(R, E),  0 },
/*11*/	{ "adc",   TRUE,  LONG,  op2(R, E),  0 },
/*12*/	{ "adc",   TRUE,  BYTE,  op2(E, R),  0 },
/*13*/	{ "adc",   TRUE,  LONG,  op2(E, R),  0 },
/*14*/	{ "adc",   FALSE, BYTE,  op2(Is, A), 0 },
/*15*/	{ "adc",   FALSE, LONG,  op2(Is, A), 0 },
/*16*/	{ "push",  FALSE, NONE,  op1(Si),    0 },
/*17*/	{ "pop",   FALSE, NONE,  op1(Si),    0 },

/*18*/	{ "sbb",   TRUE,  BYTE,  op2(R, E),  0 },
/*19*/	{ "sbb",   TRUE,  LONG,  op2(R, E),  0 },
/*1a*/	{ "sbb",   TRUE,  BYTE,  op2(E, R),  0 },
/*1b*/	{ "sbb",   TRUE,  LONG,  op2(E, R),  0 },
/*1c*/	{ "sbb",   FALSE, BYTE,  op2(Is, A), 0 },
/*1d*/	{ "sbb",   FALSE, LONG,  op2(Is, A), 0 },
/*1e*/	{ "push",  FALSE, NONE,  op1(Si),    0 },
/*1f*/	{ "pop",   FALSE, NONE,  op1(Si),    0 },

/*20*/	{ "and",   TRUE,  BYTE,  op2(R, E),  0 },
/*21*/	{ "and",   TRUE,  LONG,  op2(R, E),  0 },
/*22*/	{ "and",   TRUE,  BYTE,  op2(E, R),  0 },
/*23*/	{ "and",   TRUE,  LONG,  op2(E, R),  0 },
/*24*/	{ "and",   FALSE, BYTE,  op2(I, A),  0 },
/*25*/	{ "and",   FALSE, LONG,  op2(I, A),  0 },
/*26*/	{ "",      FALSE, NONE,  0,	     0 },
/*27*/	{ "aaa",   FALSE, NONE,  0,	     0 },

/*28*/	{ "sub",   TRUE,  BYTE,  op2(R, E),  0 },
/*29*/	{ "sub",   TRUE,  LONG,  op2(R, E),  0 },
/*2a*/	{ "sub",   TRUE,  BYTE,  op2(E, R),  0 },
/*2b*/	{ "sub",   TRUE,  LONG,  op2(E, R),  0 },
/*2c*/	{ "sub",   FALSE, BYTE,  op2(Is, A), 0 },
/*2d*/	{ "sub",   FALSE, LONG,  op2(Is, A), 0 },
/*2e*/	{ "",      FALSE, NONE,  0,	     0 },
/*2f*/	{ "das",   FALSE, NONE,  0,	     0 },

/*30*/	{ "xor",   TRUE,  BYTE,  op2(R, E),  0 },
/*31*/	{ "xor",   TRUE,  LONG,  op2(R, E),  0 },
/*32*/	{ "xor",   TRUE,  BYTE,  op2(E, R),  0 },
/*33*/	{ "xor",   TRUE,  LONG,  op2(E, R),  0 },
/*34*/	{ "xor",   FALSE, BYTE,  op2(I, A),  0 },
/*35*/	{ "xor",   FALSE, LONG,  op2(I, A),  0 },
/*36*/	{ "",      FALSE, NONE,  0,	     0 },
/*37*/	{ "daa",   FALSE, NONE,  0,	     0 },

/*38*/	{ "cmp",   TRUE,  BYTE,  op2(R, E),  0 },
/*39*/	{ "cmp",   TRUE,  LONG,  op2(R, E),  0 },
/*3a*/	{ "cmp",   TRUE,  BYTE,  op2(E, R),  0 },
/*3b*/	{ "cmp",   TRUE,  LONG,  op2(E, R),  0 },
/*3c*/	{ "cmp",   FALSE, BYTE,  op2(Is, A), 0 },
/*3d*/	{ "cmp",   FALSE, LONG,  op2(Is, A), 0 },
/*3e*/	{ "",      FALSE, NONE,  0,	     0 },
/*3f*/	{ "aas",   FALSE, NONE,  0,	     0 },

/*40*/	{ "inc",   FALSE, LONG,  op1(Ri),    0 },
/*41*/	{ "inc",   FALSE, LONG,  op1(Ri),    0 },
/*42*/	{ "inc",   FALSE, LONG,  op1(Ri),    0 },
/*43*/	{ "inc",   FALSE, LONG,  op1(Ri),    0 },
/*44*/	{ "inc",   FALSE, LONG,  op1(Ri),    0 },
/*45*/	{ "inc",   FALSE, LONG,  op1(Ri),    0 },
/*46*/	{ "inc",   FALSE, LONG,  op1(Ri),    0 },
/*47*/	{ "inc",   FALSE, LONG,  op1(Ri),    0 },

/*48*/	{ "dec",   FALSE, LONG,  op1(Ri),    0 },
/*49*/	{ "dec",   FALSE, LONG,  op1(Ri),    0 },
/*4a*/	{ "dec",   FALSE, LONG,  op1(Ri),    0 },
/*4b*/	{ "dec",   FALSE, LONG,  op1(Ri),    0 },
/*4c*/	{ "dec",   FALSE, LONG,  op1(Ri),    0 },
/*4d*/	{ "dec",   FALSE, LONG,  op1(Ri),    0 },
/*4e*/	{ "dec",   FALSE, LONG,  op1(Ri),    0 },
/*4f*/	{ "dec",   FALSE, LONG,  op1(Ri),    0 },

/*50*/	{ "push",  FALSE, LONG,  op1(Ri),    0 },
/*51*/	{ "push",  FALSE, LONG,  op1(Ri),    0 },
/*52*/	{ "push",  FALSE, LONG,  op1(Ri),    0 },
/*53*/	{ "push",  FALSE, LONG,  op1(Ri),    0 },
/*54*/	{ "push",  FALSE, LONG,  op1(Ri),    0 },
/*55*/	{ "push",  FALSE, LONG,  op1(Ri),    0 },
/*56*/	{ "push",  FALSE, LONG,  op1(Ri),    0 },
/*57*/	{ "push",  FALSE, LONG,  op1(Ri),    0 },

/*58*/	{ "pop",   FALSE, LONG,  op1(Ri),    0 },
/*59*/	{ "pop",   FALSE, LONG,  op1(Ri),    0 },
/*5a*/	{ "pop",   FALSE, LONG,  op1(Ri),    0 },
/*5b*/	{ "pop",   FALSE, LONG,  op1(Ri),    0 },
/*5c*/	{ "pop",   FALSE, LONG,  op1(Ri),    0 },
/*5d*/	{ "pop",   FALSE, LONG,  op1(Ri),    0 },
/*5e*/	{ "pop",   FALSE, LONG,  op1(Ri),    0 },
/*5f*/	{ "pop",   FALSE, LONG,  op1(Ri),    0 },

/*60*/	{ "pusha", FALSE, LONG,  0,	     0 },
/*61*/	{ "popa",  FALSE, LONG,  0,	     0 },
/*62*/  { "bound", TRUE,  LONG,  op2(E, R),  0 },
/*63*/	{ "arpl",  TRUE,  NONE,  op2(Ew,Rw), 0 },

/*64*/	{ "",      FALSE, NONE,  0,	     0 },
/*65*/	{ "",      FALSE, NONE,  0,	     0 },
/*66*/	{ "",      FALSE, NONE,  0,	     0 },
/*67*/	{ "",      FALSE, NONE,  0,	     0 },

/*68*/	{ "push",  FALSE, LONG,  op1(I),     0 },
/*69*/  { "imul",  TRUE,  LONG,  op3(I,E,R), 0 },
/*6a*/	{ "push",  FALSE, LONG,  op1(Ib),    0 },
/*6b*/  { "imul",  TRUE,  LONG,  op3(Ibs,E,R),0 },
/*6c*/	{ "ins",   FALSE, BYTE,  op2(DX, DI), 0 },
/*6d*/	{ "ins",   FALSE, LONG,  op2(DX, DI), 0 },
/*6e*/	{ "outs",  FALSE, BYTE,  op2(SI, DX), 0 },
/*6f*/	{ "outs",  FALSE, LONG,  op2(SI, DX), 0 },

/*70*/	{ "jo",    FALSE, NONE,  op1(Db),     0 },
/*71*/	{ "jno",   FALSE, NONE,  op1(Db),     0 },
/*72*/	{ "jb",    FALSE, NONE,  op1(Db),     0 },
/*73*/	{ "jnb",   FALSE, NONE,  op1(Db),     0 },
/*74*/	{ "jz",    FALSE, NONE,  op1(Db),     0 },
/*75*/	{ "jnz",   FALSE, NONE,  op1(Db),     0 },
/*76*/	{ "jbe",   FALSE, NONE,  op1(Db),     0 },
/*77*/	{ "jnbe",  FALSE, NONE,  op1(Db),     0 },

/*78*/	{ "js",    FALSE, NONE,  op1(Db),     0 },
/*79*/	{ "jns",   FALSE, NONE,  op1(Db),     0 },
/*7a*/	{ "jp",    FALSE, NONE,  op1(Db),     0 },
/*7b*/	{ "jnp",   FALSE, NONE,  op1(Db),     0 },
/*7c*/	{ "jl",    FALSE, NONE,  op1(Db),     0 },
/*7d*/	{ "jnl",   FALSE, NONE,  op1(Db),     0 },
/*7e*/	{ "jle",   FALSE, NONE,  op1(Db),     0 },
/*7f*/	{ "jnle",  FALSE, NONE,  op1(Db),     0 },

/*80*/  { "",	   TRUE,  BYTE,  op2(I, E),   (char *)db_Grp1 },
/*81*/  { "",	   TRUE,  LONG,  op2(I, E),   (char *)db_Grp1 },
/*82*/  { "",	   TRUE,  BYTE,  op2(Is,E),   (char *)db_Grp1 },
/*83*/  { "",	   TRUE,  LONG,  op2(Ibs,E),  (char *)db_Grp1 },
/*84*/	{ "test",  TRUE,  BYTE,  op2(R, E),   0 },
/*85*/	{ "test",  TRUE,  LONG,  op2(R, E),   0 },
/*86*/	{ "xchg",  TRUE,  BYTE,  op2(R, E),   0 },
/*87*/	{ "xchg",  TRUE,  LONG,  op2(R, E),   0 },

/*88*/	{ "mov",   TRUE,  BYTE,  op2(R, E),   0 },
/*89*/	{ "mov",   TRUE,  LONG,  op2(R, E),   0 },
/*8a*/	{ "mov",   TRUE,  BYTE,  op2(E, R),   0 },
/*8b*/	{ "mov",   TRUE,  LONG,  op2(E, R),   0 },
/*8c*/  { "mov",   TRUE,  NONE,  op2(S, Ew),  0 },
/*8d*/	{ "lea",   TRUE,  LONG,  op2(E, R),   0 },
/*8e*/	{ "mov",   TRUE,  NONE,  op2(Ew, S),  0 },
/*8f*/	{ "pop",   TRUE,  LONG,  op1(E),      0 },

/*90*/	{ "nop",   FALSE, NONE,  0,	      0 },
/*91*/	{ "xchg",  FALSE, LONG,  op2(A, Ri),  0 },
/*92*/	{ "xchg",  FALSE, LONG,  op2(A, Ri),  0 },
/*93*/	{ "xchg",  FALSE, LONG,  op2(A, Ri),  0 },
/*94*/	{ "xchg",  FALSE, LONG,  op2(A, Ri),  0 },
/*95*/	{ "xchg",  FALSE, LONG,  op2(A, Ri),  0 },
/*96*/	{ "xchg",  FALSE, LONG,  op2(A, Ri),  0 },
/*97*/	{ "xchg",  FALSE, LONG,  op2(A, Ri),  0 },

/*98*/	{ "cbw",   FALSE, SDEP,  0,	      "cwde" },	/* cbw/cwde */
/*99*/	{ "cwd",   FALSE, SDEP,  0,	      "cdq"  },	/* cwd/cdq */
/*9a*/	{ "lcall", FALSE, NONE,  op1(OS),     0 },
/*9b*/	{ "wait",  FALSE, NONE,  0,	      0 },
/*9c*/	{ "pushf", FALSE, LONG,  0,	      0 },
/*9d*/	{ "popf",  FALSE, LONG,  0,	      0 },
/*9e*/	{ "sahf",  FALSE, NONE,  0,	      0 },
/*9f*/	{ "lahf",  FALSE, NONE,  0,	      0 },

/*a0*/	{ "mov",   FALSE, BYTE,  op2(O, A),   0 },
/*a1*/	{ "mov",   FALSE, LONG,  op2(O, A),   0 },
/*a2*/	{ "mov",   FALSE, BYTE,  op2(A, O),   0 },
/*a3*/	{ "mov",   FALSE, LONG,  op2(A, O),   0 },
/*a4*/	{ "movs",  FALSE, BYTE,  op2(SI,DI),  0 },
/*a5*/	{ "movs",  FALSE, LONG,  op2(SI,DI),  0 },
/*a6*/	{ "cmps",  FALSE, BYTE,  op2(SI,DI),  0 },
/*a7*/	{ "cmps",  FALSE, LONG,  op2(SI,DI),  0 },

/*a8*/	{ "test",  FALSE, BYTE,  op2(I, A),   0 },
/*a9*/	{ "test",  FALSE, LONG,  op2(I, A),   0 },
/*aa*/	{ "stos",  FALSE, BYTE,  op1(DI),     0 },
/*ab*/	{ "stos",  FALSE, LONG,  op1(DI),     0 },
/*ac*/	{ "lods",  FALSE, BYTE,  op1(SI),     0 },
/*ad*/	{ "lods",  FALSE, LONG,  op1(SI),     0 },
/*ae*/	{ "scas",  FALSE, BYTE,  op1(SI),     0 },
/*af*/	{ "scas",  FALSE, LONG,  op1(SI),     0 },

/*b0*/	{ "mov",   FALSE, BYTE,  op2(I, Ri),  0 },
/*b1*/	{ "mov",   FALSE, BYTE,  op2(I, Ri),  0 },
/*b2*/	{ "mov",   FALSE, BYTE,  op2(I, Ri),  0 },
/*b3*/	{ "mov",   FALSE, BYTE,  op2(I, Ri),  0 },
/*b4*/	{ "mov",   FALSE, BYTE,  op2(I, Ri),  0 },
/*b5*/	{ "mov",   FALSE, BYTE,  op2(I, Ri),  0 },
/*b6*/	{ "mov",   FALSE, BYTE,  op2(I, Ri),  0 },
/*b7*/	{ "mov",   FALSE, BYTE,  op2(I, Ri),  0 },

/*b8*/	{ "mov",   FALSE, LONG,  op2(I, Ri),  0 },
/*b9*/	{ "mov",   FALSE, LONG,  op2(I, Ri),  0 },
/*ba*/	{ "mov",   FALSE, LONG,  op2(I, Ri),  0 },
/*bb*/	{ "mov",   FALSE, LONG,  op2(I, Ri),  0 },
/*bc*/	{ "mov",   FALSE, LONG,  op2(I, Ri),  0 },
/*bd*/	{ "mov",   FALSE, LONG,  op2(I, Ri),  0 },
/*be*/	{ "mov",   FALSE, LONG,  op2(I, Ri),  0 },
/*bf*/	{ "mov",   FALSE, LONG,  op2(I, Ri),  0 },

/*c0*/	{ "",	   TRUE,  BYTE,  op2(Ib, E),  (char *)db_Grp2 },
/*c1*/	{ "",	   TRUE,  LONG,  op2(Ib, E),  (char *)db_Grp2 },
/*c2*/	{ "ret",   FALSE, NONE,  op1(Iw),     0 },
/*c3*/	{ "ret",   FALSE, NONE,  0,	      0 },
/*c4*/	{ "les",   TRUE,  LONG,  op2(E, R),   0 },
/*c5*/	{ "lds",   TRUE,  LONG,  op2(E, R),   0 },
/*c6*/	{ "mov",   TRUE,  BYTE,  op2(I, E),   0 },
/*c7*/	{ "mov",   TRUE,  LONG,  op2(I, E),   0 },

/*c8*/	{ "enter", FALSE, NONE,  op2(Ib, Iw), 0 },
/*c9*/	{ "leave", FALSE, NONE,  0,           0 },
/*ca*/	{ "lret",  FALSE, NONE,  op1(Iw),     0 },
/*cb*/	{ "lret",  FALSE, NONE,  0,	      0 },
/*cc*/	{ "int",   FALSE, NONE,  op1(o3),     0 },
/*cd*/	{ "int",   FALSE, NONE,  op1(Ib),     0 },
/*ce*/	{ "into",  FALSE, NONE,  0,	      0 },
/*cf*/	{ "iret",  FALSE, NONE,  0,	      0 },

/*d0*/	{ "",	   TRUE,  BYTE,  op2(o1, E),  (char *)db_Grp2 },
/*d1*/	{ "",	   TRUE,  LONG,  op2(o1, E),  (char *)db_Grp2 },
/*d2*/	{ "",	   TRUE,  BYTE,  op2(CL, E),  (char *)db_Grp2 },
/*d3*/	{ "",	   TRUE,  LONG,  op2(CL, E),  (char *)db_Grp2 },
/*d4*/	{ "aam",   TRUE,  NONE,  0,	      0 },
/*d5*/	{ "aad",   TRUE,  NONE,  0,	      0 },
/*d6*/	{ "",      FALSE, NONE,  0,	      0 },
/*d7*/	{ "xlat",  FALSE, BYTE,  op1(BX),     0 },

/*d8*/  { "",      TRUE,  NONE,  0,	      (char *)db_Esc8 },
/*d9*/  { "",      TRUE,  NONE,  0,	      (char *)db_Esc9 },
/*da*/  { "",      TRUE,  NONE,  0,	      (char *)db_Esca },
/*db*/  { "",      TRUE,  NONE,  0,	      (char *)db_Escb },
/*dc*/  { "",      TRUE,  NONE,  0,	      (char *)db_Escc },
/*dd*/  { "",      TRUE,  NONE,  0,	      (char *)db_Escd },
/*de*/  { "",      TRUE,  NONE,  0,	      (char *)db_Esce },
/*df*/  { "",      TRUE,  NONE,  0,	      (char *)db_Escf },

/*e0*/	{ "loopne",FALSE, NONE,  op1(Db),     0 },
/*e1*/	{ "loope", FALSE, NONE,  op1(Db),     0 },
/*e2*/	{ "loop",  FALSE, NONE,  op1(Db),     0 },
/*e3*/	{ "jcxz",  FALSE, SDEP,  op1(Db),     "jecxz" },
/*e4*/	{ "in",    FALSE, BYTE,  op2(Ib, A),  0 },
/*e5*/	{ "in",    FALSE, LONG,  op2(Ib, A) , 0 },
/*e6*/	{ "out",   FALSE, BYTE,  op2(A, Ib),  0 },
/*e7*/	{ "out",   FALSE, LONG,  op2(A, Ib) , 0 },

/*e8*/	{ "call",  FALSE, NONE,  op1(Dl),     0 },
/*e9*/	{ "jmp",   FALSE, NONE,  op1(Dl),     0 },
/*ea*/	{ "ljmp",  FALSE, NONE,  op1(OS),     0 },
/*eb*/	{ "jmp",   FALSE, NONE,  op1(Db),     0 },
/*ec*/	{ "in",    FALSE, BYTE,  op2(DX, A),  0 },
/*ed*/	{ "in",    FALSE, LONG,  op2(DX, A) , 0 },
/*ee*/	{ "out",   FALSE, BYTE,  op2(A, DX),  0 },
/*ef*/	{ "out",   FALSE, LONG,  op2(A, DX) , 0 },

/*f0*/	{ "",      FALSE, NONE,  0,	     0 },
/*f1*/	{ "",      FALSE, NONE,  0,	     0 },
/*f2*/	{ "",      FALSE, NONE,  0,	     0 },
/*f3*/	{ "",      FALSE, NONE,  0,	     0 },
/*f4*/	{ "hlt",   FALSE, NONE,  0,	     0 },
/*f5*/	{ "cmc",   FALSE, NONE,  0,	     0 },
/*f6*/	{ "",      TRUE,  BYTE,  0,	     (char *)db_Grp3 },
/*f7*/	{ "",	   TRUE,  LONG,  0,	     (char *)db_Grp3 },

/*f8*/	{ "clc",   FALSE, NONE,  0,	     0 },
/*f9*/	{ "stc",   FALSE, NONE,  0,	     0 },
/*fa*/	{ "cli",   FALSE, NONE,  0,	     0 },
/*fb*/	{ "sti",   FALSE, NONE,  0,	     0 },
/*fc*/	{ "cld",   FALSE, NONE,  0,	     0 },
/*fd*/	{ "std",   FALSE, NONE,  0,	     0 },
/*fe*/	{ "",	   TRUE,  NONE,  0,	     (char *)db_Grp4 },
/*ff*/	{ "",	   TRUE,  NONE,  0,	     (char *)db_Grp5 },
};

struct inst	db_bad_inst =
	{ "???",   FALSE, NONE,  0,	      0 }
;

#define	f_mod(byte)	((byte)>>6)
#define	f_reg(byte)	(((byte)>>3)&0x7)
#define	f_rm(byte)	((byte)&0x7)

#define	sib_ss(byte)	((byte)>>6)
#define	sib_index(byte)	(((byte)>>3)&0x7)
#define	sib_base(byte)	((byte)&0x7)

char *	db_index_reg_16[8] = {
	"%bx,%si",
	"%bx,%di",
	"%bp,%si",
	"%bp,%di",
	"%si",
	"%di",
	"%bp",
	"%bx"
};

char *	db_reg[3][8] = {
	"%al",  "%cl",  "%dl",  "%bl",  "%ah",  "%ch",  "%dh",  "%bh",
	"%ax",  "%cx",  "%dx",  "%bx",  "%sp",  "%bp",  "%si",  "%di",
	"%eax", "%ecx", "%edx", "%ebx", "%esp", "%ebp", "%esi", "%edi"
};

char *	db_seg_reg[8] = {
	"%es", "%cs", "%ss", "%ds", "%fs", "%gs", "", ""
};

/*
 * lengths for size attributes
 */
int db_lengths[] = {
	1,	/* BYTE */
	2,	/* WORD */
	4,	/* LONG */
	8,	/* QUAD */
	4,	/* SNGL */
	8,	/* DBLR */
	10,	/* EXTR */
};

#define	get_value_inc(result, loc, size, is_signed, task) \
	result = db_get_task_value((loc), (size), (is_signed), (task)); \
	(loc) += (size);

/*
 * Read address at location and return updated location.
 */
db_addr_t
db_read_address(
	db_addr_t	loc,
	int		short_addr,
	int		regmodrm,
	struct i_addr	*addrp,		/* out */
	task_t		task)
{
	int		mod, rm, sib, index, ss, disp;

	mod = f_mod(regmodrm);
	rm  = f_rm(regmodrm);

	if (mod == 3) {
	    addrp->is_reg = TRUE;
	    addrp->disp = rm;
	    return (loc);
	}
	addrp->is_reg = FALSE;
	addrp->index = 0;

	if (short_addr) {
	    addrp->index = 0;
	    addrp->ss = 0;
	    switch (mod) {
		case 0:
		    if (rm == 6) {
			get_value_inc(disp, loc, 2, TRUE, task);
			addrp->disp = disp;
			addrp->base = 0;
		    }
		    else {
			addrp->disp = 0;
			addrp->base = db_index_reg_16[rm];
		    }
		    break;
		case 1:
		    get_value_inc(disp, loc, 1, TRUE, task);
		    addrp->disp = disp;
		    addrp->base = db_index_reg_16[rm];
		    break;
		case 2:
		    get_value_inc(disp, loc, 2, TRUE, task);
		    addrp->disp = disp;
		    addrp->base = db_index_reg_16[rm];
		    break;
	    }
	}
	else {
	    if (mod != 3 && rm == 4) {
		get_value_inc(sib, loc, 1, FALSE, task);
		rm = sib_base(sib);
		index = sib_index(sib);
		if (index != 4)
		    addrp->index = db_reg[LONG][index];
		addrp->ss = sib_ss(sib);
	    }

	    switch (mod) {
		case 0:
		    if (rm == 5) {
			get_value_inc(addrp->disp, loc, 4, FALSE, task);
			addrp->base = 0;
		    }
		    else {
			addrp->disp = 0;
			addrp->base = db_reg[LONG][rm];
		    }
		    break;

		case 1:
		    get_value_inc(disp, loc, 1, TRUE, task);
		    addrp->disp = disp;
		    addrp->base = db_reg[LONG][rm];
		    break;

		case 2:
		    get_value_inc(disp, loc, 4, FALSE, task);
		    addrp->disp = disp;
		    addrp->base = db_reg[LONG][rm];
		    break;
	    }
	}
	return (loc);
}

void
db_print_address(
	char *		seg,
	int		size,
	struct i_addr	*addrp,
	task_t		task)
{
	if (addrp->is_reg) {
	    db_printf("%s", db_reg[size][addrp->disp]);
	    return;
	}

	if (seg) {
	    db_printf("%s:", seg);
	}

	if (addrp->base != 0 || addrp->index != 0) {
	    db_printf("%#n", addrp->disp);
	    db_printf("(");
	    if (addrp->base)
		db_printf("%s", addrp->base);
	    if (addrp->index)
		db_printf(",%s,%d", addrp->index, 1<<addrp->ss);
	    db_printf(")");
	} else
	    db_task_printsym((db_addr_t)addrp->disp, DB_STGY_ANY, task);
}

/*
 * Disassemble floating-point ("escape") instruction
 * and return updated location.
 */
db_addr_t
db_disasm_esc(
	db_addr_t	loc,
	int		inst,
	int		short_addr,
	int		size,
	char *		seg,
	task_t		task)
{
	int		regmodrm;
	struct finst	*fp;
	int		mod;
	struct i_addr	address;
	char *		name;

	get_value_inc(regmodrm, loc, 1, FALSE, task);
	fp = &db_Esc_inst[inst - 0xd8][f_reg(regmodrm)];
	mod = f_mod(regmodrm);
	if (mod != 3) {
	    /*
	     * Normal address modes.
	     */
	    loc = db_read_address(loc, short_addr, regmodrm, &address, task);
	    db_printf(fp->f_name);
	    switch(fp->f_size) {
		case SNGL:
		    db_printf("s");
		    break;
		case DBLR:
		    db_printf("l");
		    break;
		case EXTR:
		    db_printf("t");
		    break;
		case WORD:
		    db_printf("s");
		    break;
		case LONG:
		    db_printf("l");
		    break;
		case QUAD:
		    db_printf("q");
		    break;
		default:
		    break;
	    }
	    db_printf("\t");
	    db_print_address(seg, BYTE, &address, task);
	}
	else {
	    /*
	     * 'reg-reg' - special formats
	     */
	    switch (fp->f_rrmode) {
		case op2(ST,STI):
		    name = (fp->f_rrname) ? fp->f_rrname : fp->f_name;
		    db_printf("%s\t%%st,%%st(%d)",name,f_rm(regmodrm));
		    break;
		case op2(STI,ST):
		    name = (fp->f_rrname) ? fp->f_rrname : fp->f_name;
		    db_printf("%s\t%%st(%d),%%st",name, f_rm(regmodrm));
		    break;
		case op1(STI):
		    name = (fp->f_rrname) ? fp->f_rrname : fp->f_name;
		    db_printf("%s\t%%st(%d)",name, f_rm(regmodrm));
		    break;
		case op1(X):
		    db_printf("%s", ((char **)fp->f_rrname)[f_rm(regmodrm)]);
		    break;
		case op1(XA):
		    db_printf("%s\t%%ax",
				 ((char **)fp->f_rrname)[f_rm(regmodrm)]);
		    break;
		default:
		    db_printf("<bad instruction>");
		    break;
	    }
	}

	return (loc);
}

/*
 * Disassemble instruction at 'loc'.  'altfmt' specifies an
 * (optional) alternate format.  Return address of start of
 * next instruction.
 */
db_addr_t
db_disasm(
	db_addr_t	loc,
	boolean_t	altfmt,
	task_t		task)
{
	int	inst;
	int	size;
	int	short_addr;
	char *	seg;
	struct inst *	ip;
	char *	i_name;
	int	i_size;
	int	i_mode;
	int	regmodrm;
	boolean_t	first;
	int	displ;
	int	prefix;
	int	imm;
	int	imm2;
	int	len;
	struct i_addr	address;
	char	*filename;
	int	linenum;

	get_value_inc(inst, loc, 1, FALSE, task);
	if (db_disasm_16) {
	    short_addr = TRUE;
	    size = WORD;
	}
	else {
	    short_addr = FALSE;
	    size = LONG;
	}
	seg = 0;

	/*
	 * Get prefixes
	 */
	prefix = TRUE;
	do {
	    switch (inst) {
		case 0x66:		/* data16 */
		    if (size == LONG)
			size = WORD;
		    else
			size = LONG;
		    break;
		case 0x67:
		    short_addr = !short_addr;
		    break;
		case 0x26:
		    seg = "%es";
		    break;
		case 0x36:
		    seg = "%ss";
		    break;
		case 0x2e:
		    seg = "%cs";
		    break;
		case 0x3e:
		    seg = "%ds";
		    break;
		case 0x64:
		    seg = "%fs";
		    break;
		case 0x65:
		    seg = "%gs";
		    break;
		case 0xf0:
		    db_printf("lock ");
		    break;
		case 0xf2:
		    db_printf("repne ");
		    break;
		case 0xf3:
		    db_printf("repe ");	/* XXX repe VS rep */
		    break;
		default:
		    prefix = FALSE;
		    break;
	    }
	    if (prefix) {
		get_value_inc(inst, loc, 1, FALSE, task);
	    }
	} while (prefix);

	if (inst >= 0xd8 && inst <= 0xdf) {
	    loc = db_disasm_esc(loc, inst, short_addr, size, seg, task);
	    db_printf("\n");
	    return (loc);
	}

	if (inst == 0x0f) {
	    get_value_inc(inst, loc, 1, FALSE, task);
	    ip = db_inst_0f[inst>>4];
	    if (ip == 0) {
		ip = &db_bad_inst;
	    }
	    else {
		ip = &ip[inst&0xf];
	    }
	}
	else
	    ip = &db_inst_table[inst];

	if (ip->i_has_modrm) {
	    get_value_inc(regmodrm, loc, 1, FALSE, task);
	    loc = db_read_address(loc, short_addr, regmodrm, &address, task);
	}

	i_name = ip->i_name;
	i_size = ip->i_size;
	i_mode = ip->i_mode;

	if (ip->i_extra == (char *)db_Grp1 ||
	    ip->i_extra == (char *)db_Grp2 ||
	    ip->i_extra == (char *)db_Grp6 ||
	    ip->i_extra == (char *)db_Grp7 ||
	    ip->i_extra == (char *)db_Grp8) {
	    i_name = ((char **)ip->i_extra)[f_reg(regmodrm)];
	}
	else if (ip->i_extra == (char *)db_Grp3) {
	    ip = (struct inst *)ip->i_extra;
	    ip = &ip[f_reg(regmodrm)];
	    i_name = ip->i_name;
	    i_mode = ip->i_mode;
	}
	else if (ip->i_extra == (char *)db_Grp4 ||
		 ip->i_extra == (char *)db_Grp5) {
	    ip = (struct inst *)ip->i_extra;
	    ip = &ip[f_reg(regmodrm)];
	    i_name = ip->i_name;
	    i_mode = ip->i_mode;
	    i_size = ip->i_size;
	}

	if (i_size == SDEP) {
	    if (size == WORD)
		db_printf(i_name);
	    else
		db_printf(ip->i_extra);
	}
	else {
	    db_printf(i_name);
	    if (i_size != NONE) {
		if (i_size == BYTE) {
		    db_printf("b");
		    size = BYTE;
		}
		else if (i_size == WORD) {
		    db_printf("w");
		    size = WORD;
		}
		else if (size == WORD)
		    db_printf("w");
		else
		    db_printf("l");
	    }
	}
	db_printf("\t");
	for (first = TRUE;
	     i_mode != 0;
	     i_mode >>= 8, first = FALSE)
	{
	    if (!first)
		db_printf(",");

	    switch (i_mode & 0xFF) {

		case E:
		    db_print_address(seg, size, &address, task);
		    break;

		case Eind:
		    db_printf("*");
		    db_print_address(seg, size, &address, task);
		    break;

		case Ew:
		    db_print_address(seg, WORD, &address, task);
		    break;

		case Eb:
		    db_print_address(seg, BYTE, &address, task);
		    break;

		case R:
		    db_printf("%s", db_reg[size][f_reg(regmodrm)]);
		    break;

		case Rw:
		    db_printf("%s", db_reg[WORD][f_reg(regmodrm)]);
		    break;

		case Ri:
		    db_printf("%s", db_reg[size][f_rm(inst)]);
		    break;

		case S:
		    db_printf("%s", db_seg_reg[f_reg(regmodrm)]);
		    break;

		case Si:
		    db_printf("%s", db_seg_reg[f_reg(inst)]);
		    break;

		case A:
		    db_printf("%s", db_reg[size][0]);	/* acc */
		    break;

		case BX:
		    if (seg)
			db_printf("%s:", seg);
		    db_printf("(%s)", short_addr ? "%bx" : "%ebx");
		    break;

		case CL:
		    db_printf("%%cl");
		    break;

		case DX:
		    db_printf("%%dx");
		    break;

		case SI:
		    if (seg)
			db_printf("%s:", seg);
		    db_printf("(%s)", short_addr ? "%si" : "%esi");
		    break;

		case DI:
		    db_printf("%%es:(%s)", short_addr ? "%di" : "%edi");
		    break;

		case CR:
		    db_printf("%%cr%d", f_reg(regmodrm));
		    break;

		case DR:
		    db_printf("%%dr%d", f_reg(regmodrm));
		    break;

		case TR:
		    db_printf("%%tr%d", f_reg(regmodrm));
		    break;

		case I:
		    len = db_lengths[size];
		    get_value_inc(imm, loc, len, FALSE, task);/* unsigned */
		    db_printf("$%#n", imm);
		    break;

		case Is:
		    len = db_lengths[size];
		    get_value_inc(imm, loc, len, TRUE, task);	/* signed */
		    db_printf("$%#r", imm);
		    break;

		case Ib:
		    get_value_inc(imm, loc, 1, FALSE, task);	/* unsigned */
		    db_printf("$%#n", imm);
		    break;

		case Ibs:
		    get_value_inc(imm, loc, 1, TRUE, task);	/* signed */
		    db_printf("$%#r", imm);
		    break;

		case Iw:
		    get_value_inc(imm, loc, 2, FALSE, task);	/* unsigned */
		    db_printf("$%#n", imm);
		    break;

		case Il:
		    get_value_inc(imm, loc, 4, FALSE, task);
		    db_printf("$%#n", imm);
		    break;

		case O:
		    if (short_addr) {
			get_value_inc(displ, loc, 2, TRUE, task);
		    }
		    else {
			get_value_inc(displ, loc, 4, TRUE, task);
		    }
		    if (seg)
			db_printf("%s:%#r",seg, displ);
		    else
			db_task_printsym((db_addr_t)displ, DB_STGY_ANY, task);
		    break;

		case Db:
		    get_value_inc(displ, loc, 1, TRUE, task);
		    if (short_addr) {
			/* offset only affects low 16 bits */
		        displ = (loc & 0xffff0000)
			      | ((loc + displ) & 0xffff);
		    }
		    else
			displ = displ + loc;
		    db_task_printsym((db_addr_t)displ,DB_STGY_ANY,task);
		    if (db_line_at_pc(0, &filename, &linenum, displ)) {
			db_printf(" [%s", filename);
			if (linenum > 0)
			    db_printf(":%d", linenum);
			db_printf("]");
		    }
		    break;

		case Dl:
		    if (short_addr) {
			get_value_inc(displ, loc, 2, TRUE, task);
			/* offset only affects low 16 bits */
		        displ = (loc & 0xffff0000)
			      | ((loc + displ) & 0xffff);
		    }
		    else {
			get_value_inc(displ, loc, 4, TRUE, task);
			displ = displ + loc;
		    }
		    db_task_printsym((db_addr_t)displ, DB_STGY_ANY, task);
		    if (db_line_at_pc(0, &filename, &linenum, displ)) {
			db_printf(" [%s", filename);
			if (linenum > 0)
			    db_printf(":%d", linenum);
			db_printf("]");
		    }
		    break;

		case o1:
		    db_printf("$1");
		    break;

		case o3:
		    db_printf("$3");
		    break;

		case OS:
		    if (short_addr) {
			get_value_inc(imm, loc, 2, FALSE, task); /* offset */
		    }
		    else {
			get_value_inc(imm, loc, 4, FALSE, task); /* offset */
		    }
		    get_value_inc(imm2, loc, 2, FALSE, task);	/* segment */
		    db_printf("$%#n,%#n", imm2, imm);
		    break;
	    }
	}

	if (altfmt == 0 && !db_disasm_16) {
	    if (inst == 0xe9 || inst == 0xeb) {	/* jmp, Dl or Db */
		/*
		 * GAS pads to longword boundary after unconditional jumps.
		 */
		while (loc & (4-1)) {
		    get_value_inc(inst, loc, 0, FALSE, task);
		    if (inst != 0x90)	/* nop */
			break;
		    loc++;
		}
	    }
	}
	db_printf("\n");
	return (loc);
}

/*
 * Classify instructions by whether they read or write memory.
 */

#define	DBLS_LOAD	0x01	/* instruction reads from memory */
#define	DBLS_STORE	0x02	/* instruction writes to memory */

#define DBLS_MODRM	0x10	/* instruction uses mod r/m byte */
#define	DBLS_SECOND	0x20	/* instruction does two operations */
#define	DBLS_ESCAPE	0x40	/* escape to two-byte opcodes */
#define DBLS_SWREG	0x80	/* need to switch on reg bits of mod r/m */

#define DBLS_MODS	0xf0
#define DBLS_LMASK	(DBLS_MODS|DBLS_LOAD)
#define DBLS_SMASK	(DBLS_MODS|DBLS_STORE)

char db_ldstrtab[] = {
	0x12, 0x12, 0x11, 0x11, 0x00, 0x00, 0x02, 0x01,
		0x12, 0x12, 0x11, 0x11, 0x00, 0x00, 0x02, 0x40,
	0x12, 0x12, 0x11, 0x11, 0x00, 0x00, 0x02, 0x01,
		0x12, 0x12, 0x11, 0x11, 0x00, 0x00, 0x02, 0x01,
	0x12, 0x12, 0x11, 0x11, 0x00, 0x00, 0x00, 0x00,
		0x12, 0x12, 0x11, 0x11, 0x00, 0x00, 0x00, 0x00,
	0x12, 0x12, 0x11, 0x11, 0x00, 0x00, 0x00, 0x00,
		0x12, 0x12, 0x11, 0x11, 0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x02, 0x01, 0x21, 0x13, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x11, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

	0x12, 0x12, 0x00, 0x12, 0x11, 0x11, 0x13, 0x13,
		0x12, 0x12, 0x11, 0x11, 0x12, 0x00, 0x11, 0x03,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x02, 0x00, 0x02, 0x01, 0x00, 0x00,
	0x01, 0x01, 0x02, 0x02, 0x03, 0x03, 0x21, 0x21,
		0x00, 0x00, 0x02, 0x02, 0x01, 0x01, 0x01, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

	0x13, 0x13, 0x00, 0x00, 0x01, 0x01, 0x12, 0x12,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x13, 0x13, 0x13, 0x13, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x13,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x13,
};

unsigned char db_ldstrtab0f[] = {
	0x80, 0x80, 0x11, 0x11, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
		0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
	0x02, 0x01, 0x00, 0x11, 0x13, 0x13, 0x00, 0x00,
		0x02, 0x01, 0x12, 0x13, 0x13, 0x13, 0x00, 0x11,
	0x00, 0x00, 0x01, 0x13, 0x01, 0x01, 0x11, 0x11,
		0x00, 0x00, 0x80, 0x13, 0x13, 0x13, 0x11, 0x11,

	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

int db_inst_swreg(boolean_t, unsigned long, unsigned char);

/*
 * Given four bytes of instruction (stored as an int, not an
 * array of characters), compute if the instruction reads
 * memory.
 */
int
db_inst_load(
	unsigned long insw)
{
	unsigned char insb, bits;

	insb = insw & 0xff;
	insw >>= 8;
	bits = db_ldstrtab[insb];
	if (!(bits & DBLS_LOAD))
		return (0);
	while (1) {
		switch (bits & DBLS_MODS) {
		case 0:
			return (1);	
		case DBLS_MODRM:
			insb = insw & 0xff;
			return ((insb & 0xc0) != 0xc0);
		case DBLS_SECOND|DBLS_MODRM:
			insb = insw & 0xff;
			return ((insb & 0xc0) != 0xc0 ? 2 : 0);
		case DBLS_SECOND:
			return (2);
		case DBLS_ESCAPE:
			insb = insw & 0xff;
			insw >>= 8;
			bits = db_ldstrtab0f[insb];
			break;
		case DBLS_SWREG:
			return (db_inst_swreg(TRUE, insw, insb));
		default:
			panic ("db_inst_load: unknown mod bits");
		}
	}
}

/*
 * Given four bytes of instruction (stored as an int, not an
 * array of characters), compute if the instruction writes
 * memory.
 */
int
db_inst_store(
	unsigned long insw)
{
	unsigned char insb, bits;

	insb = insw & 0xff;
	insw >>= 8;
	bits = db_ldstrtab[insb];
	if (!(bits & DBLS_STORE))
		return (0);
	while (1) {
		switch (bits & DBLS_MODS) {
		case 0:
			return (1);	
		case DBLS_MODRM:
			insb = insw & 0xff;
			return ((insb & 0xc0) != 0xc0);
		case DBLS_SECOND|DBLS_MODRM:
			insb = insw & 0xff;
			return ((insb & 0xc0) != 0xc0 ? 2 : 0);
		case DBLS_SECOND:
			return (2);
		case DBLS_ESCAPE:
			insb = insw & 0xff;
			insw >>= 8;
			bits = db_ldstrtab0f[insb];
			break;
		case DBLS_SWREG:
			return (db_inst_swreg(FALSE, insw, insb));
		default:
			panic ("db_inst_store: unknown mod bits");
		}
	}
}

/*
 * Parse a mod r/m byte to see if extended opcode reads
 * or writes memory.
 */
int
db_inst_swreg(
	boolean_t isload,
	unsigned long insw,
	unsigned char insb)
{
	unsigned char modrm = insw & 0xff;

	switch (insb) {
	case 0x00:
		switch (modrm & 0x38) {
		case 0x00:
		case 0x08:
		case 0x10:
		case 0x18:
			return ((modrm & 0xc0) != 0xc0);
		}
		break;
	case 0x01:
		switch (modrm & 0x38) {
		case 0x00:
		case 0x08:
		case 0x10:
		case 0x18:
			return ((modrm & 0xc0) != 0xc0 ? 2 : 0);
		case 0x20:
		case 0x30:
			return ((modrm & 0xc0) != 0xc0);
		}
		break;
	case 0xba:
		if (isload)
			return ((modrm & 0xc0) != 0xc0);
		switch (modrm & 0x38) {
		case 0x28:
		case 0x30:
		case 0x38:
			return ((modrm & 0xc0) != 0xc0);
		}
		break;
	}
	return (0);
}
