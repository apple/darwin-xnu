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
 */
/* 
 * Mach Operating System
 * Copyright (c) 1993 Carnegie Mellon University
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

#include <kern/zalloc.h>

#define	NET_REG_EAX	0	/* data segment register */
#define	NET_REG_EDX	1	/* header segment register */
#define	NET_REG_EBX	2	/* free register */
#define	NET_REG_ESI	3	/* free register */
#define	NET_REG_EDI	4	/* free register */
#define	NET_REG_MAX	5	/* number of available registers */

struct net_opt {
	filter_t	val;	/* value */
	unsigned char	reg;	/* register associated */
	unsigned char	used;	/* how many times it will be used */
};

boolean_t net_filter_enable = FALSE;

/*
 * Forward declarations.
 */
void net_filter_optimize(
	struct net_opt	net_o[],
	unsigned 	net_len,
	int		reg[],
	unsigned	nbreg);

/*
 *	Compilation of a source network filter into i386 instructions.
 */
filter_fct_t
net_filter_alloc(
	filter_t	*fpstart,
	unsigned int	fplen,
	unsigned int	*len)
{
	filter_t	*fp;
	unsigned int	op;
	unsigned int	arg;
	unsigned char	*p;
	filter_fct_t	top;
	unsigned char	*pend;
	unsigned char	*pend_old;
	unsigned int	loop;
	unsigned int	use_header;
	unsigned int	use_data;
	unsigned int	push_ecx;
	int		reg[NET_REG_MAX];
	struct net_opt	net_o[NET_MAX_FILTER];
	int		net_i;
	unsigned	net_j;
	unsigned	i;
	unsigned	push;
	unsigned	false_pad;
	struct net_opt	*pn;

	/*
	 * Addresses of end_true and end_false from the end of the program.
	 */
#define	PEND_TRUE	(pend_old - (11 + push + false_pad))
#define	PEND_FALSE	(pend_old - (4 + push))

	/*
	 * Don't produce anything if net_filter generation is not enabled.
	 */
	if (!net_filter_enable) {
		*len = 0;
		return ((filter_fct_t)0);
	}

	/*
	 * called as (*filter)(data, data_count, header)
	 *
	 * %esp -> stack;
	 * %ecx -> arg;
	 * %eax -> data (if needed);
	 * %edx -> header (if needed);
	 */
	loop = 0;
	p = (unsigned char *)0;
	pend = 0;
	use_header = 0;
	use_data = 0;
	net_j = 0;
	false_pad = sizeof(int) - 1;

	/*
	 * The compiler needs 3 passes to produce the compiled net_filter:
	 * 0) compute without optimization the maximum size of the object
	 *	routine (one run),
	 * 1) try to reduce the size of the object procedure (many runs),
	 * 2) produce final object code (one run).
	 */
	for (;;) {
		if (loop == 0)
			pend += 14;

		else if (loop == 1) {
			if (reg[NET_REG_EBX] == -1) {
				/* push and pop it */
				pend++;
				push = 1;
			} else
				push = 0;
			if (reg[NET_REG_ESI] == -1) {
				/* push and pop it */
				pend++;
				push++;
			}
			if (reg[NET_REG_EDI] == -1) {
				/* push and pop it */
				pend++;
				push++;
			}
			if (push) {
				/* restore %esp */
				push += 3;
			}

			if (use_data)
				pend += 3;
			if (use_header)
				pend += 3;
			pend += 8;

		} else {
			*p++ = 0x55;	/* pushl %ebp */
			*p++ = 0x89;	/* movl %esp, %ebp */
			*p++ = 0xE5;
			if (reg[NET_REG_EBX] == -1)
				*p++ = 0x53;	/* pushl %ebx */
			if (reg[NET_REG_ESI] == -1)
				*p++ = 0x56;	/* pushl %esi */
			if (reg[NET_REG_EDI] == -1)
				*p++ = 0x57;	/* pushl %edi */
			*p++ = 0xB9;	/* movl $1, %ecx */
			*p++ = 0x01;
			*p++ = 0x00;
			*p++ = 0x00;
			*p++ = 0x00;
			if (use_data) {
				*p++ = 0x8B;	/* movl 0x8(%ebp), %eax */
				*p++ = 0x45;
				*p++ = 0x08;
			}
			if (use_header) {
				*p++ = 0x8B;	/* movl 0x10(%ebp), %edx */
				*p++ = 0x55;
				*p++ = 0x10;
			}
		}
		push_ecx = 1;
		net_i = -1;

		fp = fpstart;
		while (fp - fpstart < fplen)
		{
			arg = *fp++;
			op = NETF_OP(arg);
			arg = NETF_ARG(arg);

			switch (arg) {
			case NETF_NOPUSH:
				/*
				 * arg = *sp++;
				 */
				if (push_ecx) {
					push_ecx = 0;
					break;
				}
				if (loop < 2)
					pend++;
				else
					*p++ = 0x59;	/* popl %ecx */
				break;

			case NETF_PUSHZERO:
				/*
				 * arg = 0;
				 */
				if (loop < 2) {
					if (push_ecx) {
						pend++;
						push_ecx = 0;
					}
					pend += 2;
				} else {
					if (push_ecx) {
						*p++ = 0x51; /* pushl %ecx */
						push_ecx = 0;
					}
					*p++ = 0x31;	/* xorl %ecx, %ecx */
					*p++ = 0xC9;
				}
				break;

			case NETF_PUSHLIT:
				/*
				 * arg = *fp++;
				 */
				if (loop < 2) {
					if (push_ecx) {
						pend++;
						push_ecx = 0;
					}
					pend += 5;
				} else {
					if (push_ecx) {
						*p++ = 0x51; /* pushl %ecx */
						push_ecx = 0;
					}
					*p++ = 0xB9;	/* movl *fp, %ecx */
					*p++ = *(unsigned char *)fp;
					*p++ = *(((unsigned char *)fp) + 1);
					*p++ = 0x0;
					*p++ = 0x0;
				}
				fp++;
				break;

			case NETF_PUSHIND:
				/*
				 * arg = *sp++;
				 * if (arg >= data_count)
				 *     return FALSE;
				 * arg = data_word[arg];
				 */
				if (loop < 2) {
					if (push_ecx)
						push_ecx = 0;
					else
						pend++;
					if (loop == 0)
						use_data = 1;
					if (loop == 0 ||
					    PEND_FALSE - (pend + 5) >= 128)
						pend += 14;
					else
						pend += 10;
					break;
				}

				if (push_ecx)
					push_ecx = 0;
				else
					*p++ = 0x59; /* popl %ecx */
				*p++ = 0x39; /* cmpl 0xC(%ebp), %ecx */
				*p++ = 0x4D;
				*p++ = 0x0C;

				if (PEND_FALSE - (p + 2) >= 128) {
					*p++ = 0x0F;	/* jle end_false */
					*p++ = 0x8E;
					*(p+0) =  PEND_FALSE - (p + 4);
					*(p+1) = (PEND_FALSE - (p + 4)) >> 8;
					*(p+2) = (PEND_FALSE - (p + 4)) >> 16;
					*(p+3) = (PEND_FALSE - (p + 4)) >> 24;
					p += 4;

				} else {
					*p++ = 0x7E; /* jle end_false */
					*p = PEND_FALSE - (p + 1);
					p++;
				}

				*p++ = 0x0F; /* movzwl 0(%eax,%ecx,2), %ecx */
				*p++ = 0xB7;
				*p++ = 0x4C;
				*p++ = 0x48;
				*p++ = 0x00;
				break;

			case NETF_PUSHHDRIND:
				/*
				 * arg = *sp++;
				 * if (arg >= (NET_HDW_HDR_MAX /
				 *             sizeof(unsigned short))
				 *     return FALSE;
				 * arg = header_word[arg];
				 */
				if (loop < 2) {
					if (push_ecx)
						push_ecx = 0;
					else
						pend++;
					if (loop == 0)
						use_header = 1;
					if (loop == 0 ||
					    PEND_FALSE - (pend + 8) >= 128)
						pend += 17;
					else
						pend += 13;
					break;
				}

				if (push_ecx)
					push_ecx = 0;
				else
					*p++ = 0x59;	/* popl %ecx */
				*p++ = 0x81;	/* cmpl %ecx, <value> */
				*p++ = 0xF9;
				*p++ =  NET_HDW_HDR_MAX /
					sizeof(unsigned short);
				*p++ = (NET_HDW_HDR_MAX /
					sizeof(unsigned short)) >> 8;
				*p++ = (NET_HDW_HDR_MAX /
					sizeof(unsigned short)) >> 16;
				*p++ = (NET_HDW_HDR_MAX /
					sizeof(unsigned short)) >> 24;

				if (PEND_FALSE - (p + 2) >= 128) {
					*p++ = 0x0F;	/* jge end_false */
					*p++ = 0x8D;
					*(p+0) =  PEND_FALSE - (p + 4);
					*(p+1) = (PEND_FALSE - (p + 4)) >> 8;
					*(p+2) = (PEND_FALSE - (p + 4)) >> 16;
					*(p+3) = (PEND_FALSE - (p + 4)) >> 24;
					p += 4;

				} else {
					*p++ = 0x7D;	/* jge end_false */
					*p = PEND_FALSE - (p + 1);
					p++;
				}

				*p++ = 0x0F; /* movzwl 0(%edx,%ecx,2), %ecx */
				*p++ = 0xB7;
				*p++ = 0x4C;
				*p++ = 0x4A;
				*p++ = 0x00;
				break;

			default:
				if (arg >= NETF_PUSHSTK) {
					arg -= NETF_PUSHSTK;
					/*
					 * arg = sp[arg];
					 */
					arg <<= 2;
					if (loop < 2) {
						if (push_ecx) {
							pend++;
							push_ecx = 0;
						}
						pend += (arg < 128) ? 4 : 7;
						break;
					}

					if (push_ecx) {
						*p++ = 0x51; /* pushl %ecx */
						push_ecx = 0;
					}
					*p++ = 0x8B; /* movl arg(%esp), %ecx */
					if (arg < 128) {
						*p++ = 0x4C;
						*p++ = 0x24;
						*p++ = arg;
					} else {
						*p++ = 0x8C;
						*p++ = 0x24;
						*p++ = arg;
						*p++ = arg >> 8;
						*p++ = arg >> 16;
						*p++ = arg >> 24;
					}
				
				} else if (arg >= NETF_PUSHHDR) {
					arg -= NETF_PUSHHDR;
					/*
					 * arg = header_word[arg];
					 */
					arg <<= 1;
					if (loop < 2) {
						if (push_ecx) {
							pend++;
							push_ecx = 0;
						}
						if (loop == 0) {
							use_header = 1;
							net_o[net_j++].val =
							    arg + NETF_PUSHHDR;
						} else {
							net_i++;
							assert(net_i < net_j);
							pn = &net_o[net_i];
							assert(reg[NET_REG_EDX]
							       == -2);
							assert(pn->used == 0 ||
							       reg[pn->reg]
							       != -2);
							assert(pn->val == arg +
							       NETF_PUSHHDR);
							if (pn->used > 0 &&
							    reg[pn->reg] >= 0 &&
							    net_o[reg[pn->reg]]
							    .val == pn->val) {
								pend += 2;
								break;
							}
						}
						pend += (arg < 128) ? 5 : 8;
						if (loop == 1 && pn->used > 1 &&
						    (reg[pn->reg] < 0 ||
						     net_o[reg[pn->reg]].val !=
						     pn->val)) {
							reg[pn->reg] = net_i;
							pend += 2;
						}
						break;
					}

					if (push_ecx) {
						*p++ = 0x51; /* pushl %ecx */
						push_ecx = 0;
					}

					net_i++;
					assert(net_i < net_j);
					pn = &net_o[net_i];
					assert(reg[NET_REG_EDX] == -2);
					assert(pn->used == 0 ||
					       reg[pn->reg] != -2);
					assert(pn->val == arg + NETF_PUSHHDR);
					if (pn->used > 0 &&
					    reg[pn->reg] >= 0 &&
					    net_o[reg[pn->reg]].val ==
					    pn->val) {
						*p++ = 0x89;
						switch (pn->reg) {
						case NET_REG_EAX:
							/* movl %eax, %ecx */
							*p++ = 0xC1;
							break;

						case NET_REG_EBX:
							/* movl %ebx, %ecx */
							*p++ = 0xD9;
							break;

						case NET_REG_ESI:
							/* movl %esi, %ecx */
							*p++ = 0xF1;
							break;

						case NET_REG_EDI:
							/* movl %edi, %ecx */
							*p++ = 0xF9;
							break;
						}
						break;
					}

					*p++ = 0x0F;/* movzwl arg(%edx),%ecx */
					*p++ = 0xB7;
					if (arg < 128) {
						*p++ = 0x4C;
						*p++ = 0x22;
						*p++ = arg;
					} else {
						*p++ = 0x8C;
						*p++ = 0x22;
						*p++ = arg;
						*p++ = arg >> 8;
						*p++ = arg >> 16;
						*p++ = arg >> 24;
					}

					if (pn->used > 1 &&
					    (reg[pn->reg] == -1 ||
					     net_o[reg[pn->reg]].val !=
					     pn->val)) {
						reg[pn->reg] = net_i;
						*p++ = 0x89;
						assert(net_o[net_i].reg !=
						       NET_REG_EDX);
						switch (net_o[net_i].reg) {
						case NET_REG_EAX:
							/* movl %ecx, %eax */
							*p++ = 0xC8;
							break;
						case NET_REG_EBX:
							/* movl %ecx, %ebx */
							*p++ = 0xCB;
							break;
						case NET_REG_ESI:
							/* movl %ecx, %esi */
							*p++ = 0xCE;
							break;
						case NET_REG_EDI:
							/* movl %ecx, %edi */
							*p++ = 0xCF;
							break;
						}
					}

				} else {
					arg -= NETF_PUSHWORD;
					/*
					 *     if (arg >= data_count)
					 *         return FALSE;
					 *     arg = data_word[arg];
					 */
					if (loop < 2) {
						if (push_ecx) {
							pend++;
							push_ecx = 0;
						}
						if (loop == 0) {
							use_data = 1;
							net_o[net_j++].val =
							    arg + NETF_PUSHWORD;
						} else {
							net_i++;
							assert(net_i < net_j);
							pn = &net_o[net_i];
							assert(reg[NET_REG_EAX]
							       == -2);
							assert(pn->used == 0 ||
							       reg[pn->reg]
							       != -2);
							assert(pn->val == arg +
							       NETF_PUSHWORD);
							if (pn->used > 0 &&
							    reg[pn->reg] >= 0 &&
							    net_o[reg[pn->reg]]
							    .val == pn->val) {
								pend += 2;
								break;
							}
						}
						arg <<= 1;
						pend += (arg < 128) ? 4 : 7;
						if (loop == 0 ||
						    (PEND_FALSE -
						     (pend + 2)) >= 128)
							pend += 6;
						else
							pend += 2;

						if (arg < 128)
							pend += 5;
						else
							pend += 8;
						if (loop == 1 && pn->used > 1 &&
						    (reg[pn->reg] < 0 ||
						     net_o[reg[pn->reg]].val !=
						     pn->val)) {
							reg[pn->reg] = net_i;
							pend += 2;
						}
						break;
					}

					if (push_ecx) {
						*p++ = 0x51; /* pushl %ecx */
						push_ecx = 0;
					}

					net_i++;
					assert(net_i < net_j);
					pn = &net_o[net_i];
					assert(reg[NET_REG_EAX] == -2);
					assert(pn->used == 0 ||
					       reg[pn->reg] != -2);
					assert(pn->val == arg + NETF_PUSHWORD);
					if (pn->used > 0 &&
					    reg[pn->reg] >= 0 &&
					    net_o[reg[pn->reg]].val ==
					    pn->val) {
						*p++ = 0x89;
						switch (pn->reg) {
						case NET_REG_EDX:
							/* movl %edx, %ecx */
							*p++ = 0xD1;
							break;

						case NET_REG_EBX:
							/* movl %ebx, %ecx */
							*p++ = 0xD9;
							break;

						case NET_REG_ESI:
							/* movl %esi, %ecx */
							*p++ = 0xF1;
							break;

						case NET_REG_EDI:
							/* movl %edi, %ecx */
							*p++ = 0xF9;
							break;
						}
						break;
					}

					/* cmpl 0xC(%ebp), <arg> */
					arg <<= 1;
					if (arg < 128) {
						*p++ = 0x83;
						*p++ = 0x7D;
						*p++ = 0x0C;
						*p++ = arg;
					} else {
						*p++ = 0x81;
						*p++ = 0x7D;
						*p++ = 0x0C;
						*p++ = arg;
						*p++ = arg >> 8;
						*p++ = arg >> 16;
						*p++ = arg >> 24;
					}

					if (PEND_FALSE - (p + 2) >= 128) {
						*p++ = 0x0F;/* jle end_false */
						*p++ = 0x8E;
						*(p+0) =  PEND_FALSE - (p + 4);
						*(p+1) = (PEND_FALSE - (p + 4))
							  >> 8;
						*(p+2) = (PEND_FALSE - (p + 4))
							  >> 16;
						*(p+3) = (PEND_FALSE - (p + 4))
							  >> 24;
						p += 4;

					} else {
						*p++ = 0x7E;/* jle end_false */
						*p = PEND_FALSE - (p + 1);
						p++;
					}

					*p++ = 0x0F;/* movzwl arg(%eax),%ecx */
					*p++ = 0xB7;
					if (arg < 128) {
						*p++ = 0x4C;
						*p++ = 0x20;
						*p++ = arg;
					} else {
						*p++ = 0x8C;
						*p++ = 0x20;
						*p++ = arg;
						*p++ = arg >> 8;
						*p++ = arg >> 16;
						*p++ = arg >> 24;
					}

					if (pn->used > 1 &&
					    (reg[pn->reg] == -1 ||
					     net_o[reg[pn->reg]].val !=
					     pn->val)) {
						reg[pn->reg] = net_i;
						*p++ = 0x89;
						assert(net_o[net_i].reg !=
						       NET_REG_EAX);
						switch (net_o[net_i].reg) {
						case NET_REG_EDX:
							/* movl %ecx, %edx */
							*p++ = 0xCA;
							break;
						case NET_REG_EBX:
							/* movl %ecx, %ebx */
							*p++ = 0xCB;
							break;
						case NET_REG_ESI:
							/* movl %ecx, %esi */
							*p++ = 0xCE;
							break;
						case NET_REG_EDI:
							/* movl %ecx, %edi */
							*p++ = 0xCF;
							break;
						}
					}
				}
				break;
			}

			switch (op) {
			case NETF_OP(NETF_NOP):
				/*
				 * *--sp = arg;
				 */
				push_ecx = 1;
				break;

			case NETF_OP(NETF_AND):
				/*
				 * *sp &= arg;
				 */
				if (loop < 2)
					pend += 3;
				else {
					*p++ = 0x21;	/* andl (%esp), %ecx */
					*p++ = 0x0C;
					*p++ = 0x24;
				}
				break;

			case NETF_OP(NETF_OR):
				/*
				 * *sp |= arg;
				 */
				if (loop < 2)
					pend += 3;
				else {
					*p++ = 0x09;	/* orl (%esp), %ecx */
					*p++ = 0x0C;
					*p++ = 0x24;
				}
				break;

			case NETF_OP(NETF_XOR):
				/*
				 * sp ^= arg;
				 */
				if (loop < 2)
					pend += 3;
				else {
					*p++ = 0x31;	/* xorl (%esp), %ecx */
					*p++ = 0x0C;
					*p++ = 0x24;
				}
				break;

			case NETF_OP(NETF_EQ):
				/*
				 * *sp = (*sp == arg);
				 */
				if (loop < 2) {
					pend += 14;
					/*
					 * Pad to longword boundary (cf dissas).
					 */
					if (i = ((pend - (unsigned char *)0) &
						 (sizeof(int) - 1)))
						pend += (sizeof(int) - i);
					pend += 7;
					break;
				}
				*p++ = 0x39;	/* cmpl (%esp), %ecx */
				*p++ = 0x0C;
				*p++ = 0x24;

				i = ((p - (unsigned char *)top) + 11) &
					(sizeof(int) - 1);
				*p++ = 0x74;	/* je .+9+<pad> */
				*p++ = 0x09 + (i ? sizeof(int) - i : 0);
				*p++ = 0xC7;	/* movl $0, 0(%esp) */
				*p++ = 0x04;
				*p++ = 0x24;
				*p++ = 0x00;
				*p++ = 0x00;
				*p++ = 0x00;
				*p++ = 0x00;

				i = ((p - (unsigned char *)top) + 2) &
					(sizeof(int) - 1);
				*p++ = 0xEB;	/* jmp .+7+<pad> */
				*p++ = 0x07 + (i ? sizeof(int) - i : 0);

				/*
				 * Pad to longword boundary (cf dissas).
				 */
				if (i = (p - (unsigned char *)top) &
				    (sizeof(int) - 1))
					while (i++ < sizeof(int))
						*p++ = 0x90; /* nop */
				*p++ = 0xC7;	/* movl $1, 0(%esp) */
				*p++ = 0x04;
				*p++ = 0x24;
				*p++ = 0x01;
				*p++ = 0x00;
				*p++ = 0x00;
				*p++ = 0x00;
				break;

			case NETF_OP(NETF_NEQ):
				/*
				 * *sp = (*sp != arg);
				 */
				if (loop < 2) {
					pend += 14;
					/*
					 * Pad to longword boundary (cf dissas).
					 */
					if (i = ((pend - (unsigned char *)0) &
						 (sizeof(int) - 1)))
						pend += (sizeof(int) - i);
					pend += 7;
					break;
				}
				*p++ = 0x39;	/* cmpl (%esp), %ecx */
				*p++ = 0x0C;
				*p++ = 0x24;

				i = ((p - (unsigned char *)top) + 11) &
					(sizeof(int) - 1);
				*p++ = 0x75;	/* jne .+9+<pad> */
				*p++ = 0x09 + (i ? sizeof(int) - i : 0);
				*p++ = 0xC7;	/* movl $0, 0(%esp) */
				*p++ = 0x04;
				*p++ = 0x24;
				*p++ = 0x00;
				*p++ = 0x00;
				*p++ = 0x00;
				*p++ = 0x00;

				i = ((p - (unsigned char *)top) + 2) &
					(sizeof(int) - 1);
				*p++ = 0xEB;	/* jmp .+7+<pad> */
				*p++ = 0x07 + (i ? sizeof(int) - i : 0);

				/*
				 * Pad to longword boundary (cf dissas).
				 */
				if (i = (p - (unsigned char *)top) &
				    (sizeof(int) - 1))
					while (i++ < sizeof(int))
						*p++ = 0x90; /* nop */
				*p++ = 0xC7;	/* movl $1, 0(%esp) */
				*p++ = 0x04;
				*p++ = 0x24;
				*p++ = 0x01;
				*p++ = 0x00;
				*p++ = 0x00;
				*p++ = 0x00;
				break;

			case NETF_OP(NETF_LT):
				/*
				 * *sp = (*sp < arg);
				 */
				if (loop < 2) {
					pend += 14;
					/*
					 * Pad to longword boundary (cf dissas).
					 */
					if (i = ((pend - (unsigned char *)0) &
						 (sizeof(int) - 1)))
						pend += (sizeof(int) - i);
					pend += 7;
					break;
				}
				*p++ = 0x39;	/* cmpl (%esp), %ecx */
				*p++ = 0x0C;
				*p++ = 0x24;

				i = ((p - (unsigned char *)top) + 11) &
					(sizeof(int) - 1);
				*p++ = 0x7C;	/* jl .+9+<pad> */
				*p++ = 0x09 + (i ? sizeof(int) - i : 0);
				*p++ = 0xC7;	/* movl $0, 0(%esp) */
				*p++ = 0x04;
				*p++ = 0x24;
				*p++ = 0x00;
				*p++ = 0x00;
				*p++ = 0x00;
				*p++ = 0x00;

				i = ((p - (unsigned char *)top) + 2) &
					(sizeof(int) - 1);
				*p++ = 0xEB;	/* jmp .+7+<pad> */
				*p++ = 0x07 + (i ? sizeof(int) - i : 0);

				/*
				 * Pad to longword boundary (cf dissas).
				 */
				if (i = (p - (unsigned char *)top) &
				    (sizeof(int) - 1))
					while (i++ < sizeof(int))
						*p++ = 0x90; /* nop */
				*p++ = 0xC7;	/* movl $1, 0(%esp) */
				*p++ = 0x04;
				*p++ = 0x24;
				*p++ = 0x01;
				*p++ = 0x00;
				*p++ = 0x00;
				*p++ = 0x00;
				break;

			case NETF_OP(NETF_LE):
				/*
				 * *sp = (*sp <= arg);
				 */
				if (loop < 2) {
					pend += 14;
					/*
					 * Pad to longword boundary (cf dissas).
					 */
					if (i = ((pend - (unsigned char *)0) &
						 (sizeof(int) - 1)))
						pend += (sizeof(int) - i);
					pend += 7;
					break;
				}
				*p++ = 0x39;	/* cmpl (%esp), %ecx */
				*p++ = 0x0C;
				*p++ = 0x24;

				i = ((p - (unsigned char *)top) + 11) &
					(sizeof(int) - 1);
				*p++ = 0x7E;	/* jle .+9+<pad> */
				*p++ = 0x09 + (i ? sizeof(int) - i : 0);
				*p++ = 0xC7;	/* movl $0, 0(%esp) */
				*p++ = 0x04;
				*p++ = 0x24;
				*p++ = 0x00;
				*p++ = 0x00;
				*p++ = 0x00;
				*p++ = 0x00;

				i = ((p - (unsigned char *)top) + 2) &
					(sizeof(int) - 1);
				*p++ = 0xEB;	/* jmp .+7+<pad> */
				*p++ = 0x07 + (i ? sizeof(int) - i : 0);

				/*
				 * Pad to longword boundary (cf dissas).
				 */
				if (i = (p - (unsigned char *)top) &
				    (sizeof(int) - 1))
					while (i++ < sizeof(int))
						*p++ = 0x90; /* nop */
				*p++ = 0xC7;	/* movl $1, 0(%esp) */
				*p++ = 0x04;
				*p++ = 0x24;
				*p++ = 0x01;
				*p++ = 0x00;
				*p++ = 0x00;
				*p++ = 0x00;
				break;

			case NETF_OP(NETF_GT):
				/*
				 * *sp = (*sp > arg);
				 */
				if (loop < 2) {
					pend += 14;
					/*
					 * Pad to longword boundary (cf dissas).
					 */
					if (i = ((pend - (unsigned char *)0) &
						 (sizeof(int) - 1)))
						pend += (sizeof(int) - i);
					pend += 7;
					break;
				}
				*p++ = 0x39;	/* cmpl (%esp), %ecx */
				*p++ = 0x0C;
				*p++ = 0x24;

				i = ((p - (unsigned char *)top) + 11) &
					(sizeof(int) - 1);
				*p++ = 0x7F;	/* jg .+9+<pad> */
				*p++ = 0x09 + (i ? sizeof(int) - i : 0);
				*p++ = 0xC7;	/* movl $0, 0(%esp) */
				*p++ = 0x04;
				*p++ = 0x24;
				*p++ = 0x00;
				*p++ = 0x00;
				*p++ = 0x00;
				*p++ = 0x00;

				i = ((p - (unsigned char *)top) + 2) &
					(sizeof(int) - 1);
				*p++ = 0xEB;	/* jmp .+7+<pad> */
				*p++ = 0x07 + (i ? sizeof(int) - i : 0);

				/*
				 * Pad to longword boundary (cf dissas).
				 */
				if (i = (p - (unsigned char *)top) &
				    (sizeof(int) - 1))
					while (i++ < sizeof(int))
						*p++ = 0x90; /* nop */
				*p++ = 0xC7;	/* movl $1, 0(%esp) */
				*p++ = 0x04;
				*p++ = 0x24;
				*p++ = 0x01;
				*p++ = 0x00;
				*p++ = 0x00;
				*p++ = 0x00;
				break;

			case NETF_OP(NETF_GE):
				/*
				 * *sp = (*sp >= arg);
				 */
				if (loop < 2) {
					pend += 14;
					/*
					 * Pad to longword boundary (cf dissas).
					 */
					if (i = ((pend - (unsigned char *)0) &
						 (sizeof(int) - 1)))
						pend += (sizeof(int) - i);
					pend += 7;
					break;
				}
				*p++ = 0x39;	/* cmpl (%esp), %ecx */
				*p++ = 0x0C;
				*p++ = 0x24;

				i = ((p - (unsigned char *)top) + 11) &
					(sizeof(int) - 1);
				*p++ = 0x7D;	/* jge .+9+<pad> */
				*p++ = 0x09 + (i ? sizeof(int) - i : 0);
				*p++ = 0xC7;	/* movl $0, 0(%esp) */
				*p++ = 0x04;
				*p++ = 0x24;
				*p++ = 0x00;
				*p++ = 0x00;
				*p++ = 0x00;
				*p++ = 0x00;

				i = ((p - (unsigned char *)top) + 2) &
					(sizeof(int) - 1);
				*p++ = 0xEB;	/* jmp .+7+<pad> */
				*p++ = 0x07 + (i ? sizeof(int) - i : 0);

				/*
				 * Pad to longword boundary (cf dissas).
				 */
				if (i = (p - (unsigned char *)top) &
				    (sizeof(int) - 1))
					while (i++ < sizeof(int))
						*p++ = 0x90; /* nop */
				*p++ = 0xC7;	/* movl $1, 0(%esp) */
				*p++ = 0x04;
				*p++ = 0x24;
				*p++ = 0x01;
				*p++ = 0x00;
				*p++ = 0x00;
				*p++ = 0x00;
				break;

			case NETF_OP(NETF_COR):
				/*
				 * if (*sp++ == arg)
				 *     return (TRUE);
				 */
				if (loop < 2) {
					if (loop == 0 ||
					    PEND_TRUE - (pend + 5) >= 128)
						pend += 12;
					else
						pend += 8;
					break;
				}

				*p++ = 0x39;	/* cmpl (%esp), %ecx */
				*p++ = 0x0C;
				*p++ = 0x24;

				if (PEND_TRUE - (p + 2) >= 128) {
					*p++ = 0x0F;	/* je end_true */
					*p++ = 0x84;
					*(p+0) =  PEND_TRUE - (p + 4);
					*(p+1) = (PEND_TRUE - (p + 4)) >> 8;
					*(p+2) = (PEND_TRUE - (p + 4)) >> 16;
					*(p+3) = (PEND_TRUE - (p + 4)) >> 24;
					p += 4;

				} else {
					*p++ = 0x74;	/* je end_true */
					*p = PEND_TRUE - (p + 1);
					p++;
				}

				*p++ = 0x83;	/* addl $4, %esp */
				*p++ = 0xC4;
				*p++ = 0x04;
				break;

			case NETF_OP(NETF_CAND):
				/*
				 * if (*sp++ != arg)
				 *     return (FALSE);
				 */
				if (loop < 2) {
					if (loop == 0 ||
					    PEND_FALSE - (pend + 5) >= 128)
						pend += 12;
					else
						pend += 8;
					break;
				}

				*p++ = 0x39;	/* cmpl (%esp), %ecx */
				*p++ = 0x0C;
				*p++ = 0x24;

				if (PEND_FALSE - (p + 2) >= 128) {
					*p++ = 0x0F;	/* jne end_false */
					*p++ = 0x85;
					*(p+0) =  PEND_FALSE - (p + 4);
					*(p+1) = (PEND_FALSE - (p + 4)) >> 8;
					*(p+2) = (PEND_FALSE - (p + 4)) >> 16;
					*(p+3) = (PEND_FALSE - (p + 4)) >> 24;
					p += 4;

				} else {
					*p++ = 0x75;	/* jne end_false */
					*p = PEND_FALSE - (p + 1);
					p++;
				}

				*p++ = 0x83;	/* addl $4, %esp */
				*p++ = 0xC4;
				*p++ = 0x04;
				break;

			case NETF_OP(NETF_CNOR):
				/*
				 * if (*sp++ == arg)
				 *     return (FALSE);
				 */
				if (loop < 2) {
					if (loop == 0 ||
					    PEND_FALSE - (pend + 5) >= 128)
						pend += 12;
					else
						pend += 8;
					break;
				}

				*p++ = 0x39;	/* cmpl (%esp), %ecx */
				*p++ = 0x0C;
				*p++ = 0x24;

				if (PEND_FALSE - (p + 2) >= 128) {
					*p++ = 0x0F;	/* je end_false */
					*p++ = 0x84;
					*(p+0) =  PEND_FALSE - (p + 4);
					*(p+1) = (PEND_FALSE - (p + 4)) >> 8;
					*(p+2) = (PEND_FALSE - (p + 4)) >> 16;
					*(p+3) = (PEND_FALSE - (p + 4)) >> 24;
					p += 4;
				} else {
					*p++ = 0x74;	/* je end_false */
					*p = PEND_FALSE - (p + 1);
					p++;
				}

				*p++ = 0x83;	/* addl $4, %esp */
				*p++ = 0xC4;
				*p++ = 0x04;
				break;

			case NETF_OP(NETF_CNAND):
				/*
				 * if (*sp++ != arg)
				 *     return (TRUE);
				 */
				if (loop < 2) {
					if (loop == 0 ||
					    PEND_TRUE - (pend + 5) >= 128)
						pend += 12;
					else
						pend += 8;
					break;
				}

				*p++ = 0x39;	/* cmpl (%esp), %ecx */
				*p++ = 0x0C;
				*p++ = 0x24;

				if (PEND_TRUE - (p + 2) >= 128) {
					*p++ = 0x0F;	/* jne end_true */
					*p++ = 0x85;
					*(p+0) =  PEND_TRUE - (p + 4);
					*(p+1) = (PEND_TRUE - (p + 4)) >> 8;
					*(p+2) = (PEND_TRUE - (p + 4)) >> 16;
					*(p+3) = (PEND_TRUE - (p + 4)) >> 24;
					p += 4;

				} else {
					*p++ = 0x75;	/* jne end_true */
					*p = PEND_TRUE - (p + 1);
					p++;
				}

				*p++ = 0x83;	/* addl $4, %esp */
				*p++ = 0xC4;
				*p++ = 0x04;
				break;

			case NETF_OP(NETF_LSH):
				/*
				 * *sp <<= arg;
				 */
				if (loop < 2)
					pend += 3;
				else {
					*p++ = 0xD3;	/* sall (%esp), %cl */
					*p++ = 0x24;
					*p++ = 0x24;
				}
				break;

			case NETF_OP(NETF_RSH):
				/*
				 * *sp >>= arg;
				 */
				if (loop < 2)
					pend += 3;
				else {
					*p++ = 0xD3;	/* sarl (%esp), %cl */
					*p++ = 0x3C;
					*p++ = 0x24;
				}
				break;

			case NETF_OP(NETF_ADD):
				/*
				 * *sp += arg;
				 */ 
				if (loop < 2)
					pend += 3;
				else {
					*p++ = 0x01;	/* addl (%esp), %ecx */
					*p++ = 0x0C;
					*p++ = 0x24;
				}
				break;

			case NETF_OP(NETF_SUB):
				/*
				 * *sp -= arg;
				 */
				if (loop < 2)
					pend += 3;
				else {
					*p++ = 0x29;	/* subl (%esp), %ecx */
					*p++ = 0x0C;
					*p++ = 0x24;
				}
				break;
			}
		}

		/*
		 * return ((*sp) ? TRUE : FALSE);
		 */
		if (loop < 2) {
			if (push_ecx) {
				pend += 12;
				push_ecx = 0;
			} else
				pend += 13;
			/*
			 * Pad to longword boundary (cf dissas).
			 */
			i = (pend - (unsigned char *)0) & (sizeof(int) - 1);
			false_pad = i ? sizeof(int) - i : 0;
			pend += 4 + push + false_pad;
		} else {
			if (push_ecx) {
				*p++ = 0x83;	/* cmpl %ecx, $0 */
				*p++ = 0xF9;
				*p++ = 0x00;
				push_ecx = 0;
			} else {
				*p++ = 0x83;	/* cmpl (%esp), $0 */
				*p++ = 0x3C;
				*p++ = 0x24;
				*p++ = 0x00;
			}

			i = ((p - (unsigned char *)top) + 9) &
				(sizeof(int) - 1);
			false_pad = i ? sizeof(int) - i : 0;
			*p++ = 0x74;	/* je end_false */
			*p++ = 0x07 + false_pad;

			*p++ = 0xB8;	/* movl $1, %eax */
			*p++ = 0x01;
			*p++ = 0x00;
			*p++ = 0x00;
			*p++ = 0x00;

			*p++ = 0xEB;	/* jmp .+2+<pad> */
			*p++ = 0x02 + false_pad;

			/*
			 * Pad to longword boundary (cf dissas).
			 */
			for (i = 0; i < false_pad; i++)
				*p++ = 0x90; /* nop */
			*p++ = 0x31;	/* xorl %eax, %eax */
			*p++ = 0xC0;
			if (push) {
				*p++ = 0x8D;	/* leal -<push>(%ebx), %esp */
				*p++ = 0x65;
				*p++ = -((push - 3) * 4);
			}
			if (reg[NET_REG_EDI] >= 0)
				*p++ = 0x5F;	/* pop %edi */
			if (reg[NET_REG_ESI] >= 0)
				*p++ = 0x5E;	/* pop %esi */
			if (reg[NET_REG_EBX] >= 0)
				*p++ = 0x5B;	/* pop %ebx */
			*p++ = 0xC9;	/* leave */
			*p++ = 0xC3;	/* ret */
		}

		/*
		 * Prepare next loop if any.
		 */
		if (loop == 2)
			break;

		if (loop == 1 && pend == pend_old) {
			loop = 2;
			*len = pend - (unsigned char *)0;
			top = (filter_fct_t)kalloc(*len);
			p = (unsigned char *)top;
			pend_old = p + (pend - (unsigned char *)0);
		} else {
			if (loop == 0) {
				loop = 1;
				/*
				 * Compute and optimize free registers usage.
				 */
				for (i = 0; i < NET_REG_MAX; i++)
					reg[i] = -1;
				if (use_data)
					reg[NET_REG_EAX] = -2;
				if (use_header)
					reg[NET_REG_EDX] = -2;
				net_filter_optimize(net_o, net_j,
						    reg, NET_REG_MAX);
			}
			pend_old = pend;
			pend = 0;
		}
		for (i = 0; i < NET_REG_MAX; i++)
			if (reg[i] != -2)
				reg[i] = -1;
	}
	return (top);
}

void
net_filter_free(
	filter_fct_t	fp,
	unsigned int	len)
{
	kfree((vm_offset_t)fp, len);
}

/*
 * Try to compute how to use (if needed) extra registers to store
 * values read more than once.
 *
 * Input : 	net_o is an array of used values (only .val is valid).
 *		net_len is the length of net_o.
 *		reg is an array of available registers (-2 ==> used register).
 *		nbreg is the maximum number of registers.
 *
 * Output :	net_o is an array of register usage.
 *			.used == 0 ==> do not used any register.
 *			.used >= 2 ==> how many times the .reg register
 *						will be used.
 *		reg is an array of used registers.
 *			== -2 ==> unused or unavailable register.
 *			>=  0 ==> used register.
 *
 * N.B. This procedure is completely machine-independent and should take place
 *		in a file of the device directory.
 */
void
net_filter_optimize(
	struct net_opt	net_o[],
	unsigned 	net_len,
	int		reg[],
	unsigned	nbreg)
{
	unsigned	i;
	unsigned	j;
	unsigned	nbnet;
	unsigned	avail;
	unsigned	used;
	unsigned	first;
	unsigned	max;
	unsigned	last;
	struct net_opt	*p;
	struct net_opt	*q;

	avail = 0;
	for (i = 0; i < nbreg; i++)
		if (reg[i] != -2)
			avail++;
	if (avail == 0)
		return;

	/*
	 * First step: set up used field.
	 */
	p = &net_o[net_len];
	while (p != net_o) {
		for (q = p--; q < &net_o[net_len]; q++)
			if (q->val == p->val) {
				p->used = q->used + 1;
				break;
			}
		if (q == &net_o[net_len])
			p->used = 1;
	}

	/*
	 * Second step: choose best register and update used field.
	 */
	if (net_len > 0) {
		if (net_o[0].used == 1)
			used = net_o[0].used = 0;
		else {
			net_o[0].reg = 0;
			used = 1;
		}

		for (p = &net_o[1]; p < &net_o[net_len]; p++) {
			max = 0;
			first = avail;
			for (i = 0; i < avail; i++) {
				q = p;
				j = 0;
				while (q-- != net_o)
					if (q->used > 0 && q->reg == i) {
						if (q->used == 1)
							first = i;
						j = 1;
						break;
					}
				if (j == 0)
					continue;

				if (q->val == p->val) {
					p->reg = i;
					break;
				}

				if (p->used == 1)
					continue;

				if (first == avail && used == avail) {
					j = 1;
					for (q = p+1; q->val != p->val; p++)
						j++;
					if (j > max) {
						max = j;
						last = i;
					}
				}
			}
			if (i < avail)
				continue;

			if (p->used > 1) {
				if (first != avail)
					p->reg = first;
				else if (used < avail)
					p->reg = used++;
				else
					p->reg = last;
			} else
				p->used = 0;
		}
	}

	/*
	 * Third step: associate correct register number and keep max value.
	 */
	for (p = net_o; p < &net_o[net_len]; p++) {
		if (p->used == 0)
			continue;
		i = first = 0;
		for (;;) {
			if (reg[i] != -2) {
				if (first == p->reg) {
					p->reg = i;
					break;
				}
				first++;
			}
			i++;
		}
	}

	/*
	 * Forth step: invalidate useless registers.
	 */
	if (net_len == 0) {
		for (i = 0; i < nbreg; i++)
			if (reg[i] != -2)
				reg[i] = -2;

	} else if (used < avail) {
		first = 0;
		for (i = 0; i < nbreg; i++)
			if (reg[i] != -2)
				if (first >= used)
					reg[i] = -2;
				else
					first++;
	}
}
