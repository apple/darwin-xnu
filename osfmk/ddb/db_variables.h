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
 * Revision 1.1.1.1  1998/09/22 21:05:48  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:26:09  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.2.17.5  1996/01/09  19:16:39  devrcs
 * 	Define alternate register definitions.
 * 	[1995/12/01  21:42:46  jfraser]
 *
 * 	Merged '64-bit safe' changes from DEC alpha port.
 * 	[1995/11/21  18:04:00  jfraser]
 *
 * Revision 1.2.17.4  1995/02/23  21:44:00  alanl
 * 	Merged with DIPC2_SHARED.
 * 	[1995/01/05  13:36:23  alanl]
 * 
 * Revision 1.2.20.2  1994/10/14  03:47:19  dwm
 * 	mk6 CR668 - 1.3b26 merge
 * 	64bit cleanup
 * 	[1994/10/14  03:40:00  dwm]
 * 
 * Revision 1.2.17.2  1994/09/23  01:22:42  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:11:29  ezf]
 * 
 * Revision 1.2.17.1  1994/06/11  21:12:42  bolinger
 * 	Merge up to NMK17.2.
 * 	[1994/06/11  20:04:23  bolinger]
 * 
 * Revision 1.2.22.1  1994/12/06  19:43:29  alanl
 * 	Intel merge, Oct 94 code drop.
 * 	Define DB_VAR_NULL.
 * 	Add prototype for db_find_reg_name.
 * 	[94/11/23            mmp]
 * 
 * Revision 1.2.15.1  1994/02/08  10:59:16  bernadat
 * 	Added db_show_one_variable & db_show_variable prototypes
 * 
 * 	Got DB_MACRO_LEVEL and DB_MACRO_NARGS macros from <ddb/db_variables.h>.
 * 	Added new fields (hidden_xxx) into struct db_variable and into
 * 	struct db_var_aux_param.
 * 	Added DB_VAR_SHOW for showing variables.
 * 	[93/08/12            paire]
 * 	[94/02/07            bernadat]
 * 
 * Revision 1.2.4.3  1993/07/27  18:28:29  elliston
 * 	Add ANSI prototypes.  CR #9523.
 * 	[1993/07/27  18:13:26  elliston]
 * 
 * Revision 1.2.4.2  1993/06/09  02:21:06  gm
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  20:57:48  jeffc]
 * 
 * Revision 1.2  1993/04/19  16:03:36  devrcs
 * 	New field used to display old register values with 'set' command
 * 	[barbou@gr.osf.org]
 * 	[92/12/03            bernadat]
 * 
 * Revision 1.1  1992/09/30  02:24:26  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.5  91/10/09  16:04:17  af
 * 	 Revision 2.4.3.1  91/10/05  13:08:42  jeffreyh
 * 	 	Added suffix related field to db_variable structure.
 * 	 	Added macro definitions of db_{read,write}_variable.
 * 	 	[91/08/29            tak]
 * 
 * Revision 2.4.3.1  91/10/05  13:08:42  jeffreyh
 * 	Added suffix related field to db_variable structure.
 * 	Added macro definitions of db_{read,write}_variable.
 * 	[91/08/29            tak]
 * 
 * Revision 2.4  91/05/14  15:37:12  mrt
 * 	Correcting copyright
 * 
 * Revision 2.3  91/02/05  17:07:23  mrt
 * 	Changed to new Mach copyright
 * 	[91/01/31  16:19:54  mrt]
 * 
 * Revision 2.2  90/08/27  21:53:40  dbg
 * 	Modularized typedef name.  Documented the calling sequence of
 * 	the (optional) access function of a variable.  Now the valuep
 * 	field can be made opaque, eg be an offset that fcn() resolves.
 * 	[90/08/20            af]
 * 
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
 * 	Author: David B. Golub, Carnegie Mellon University
 *	Date:	7/90
 */

#ifndef	_DDB_DB_VARIABLES_H_
#define	_DDB_DB_VARIABLES_H_

#include <kern/thread.h>
#include <machine/db_machdep.h>		/* For db_expr_t */


#define DB_VAR_LEVEL	3	/* maximum number of suffix level */

/*
 * auxiliary parameters passed to a variable handler
 */
struct db_var_aux_param {
	char		*modif;			/* option strings */
	short		level;			/* number of levels */
	short		hidden_level;		/* hidden level */
	short		suffix[DB_VAR_LEVEL];	/* suffix */
	thread_t	thr_act;		/* target thr_act */
};

typedef struct db_var_aux_param	*db_var_aux_param_t;
	

/*
 * Debugger variables.
 */
struct db_variable {
	char	*name;		/* Name of variable */
	db_expr_t *valuep;	/* pointer to value of variable */
				/* function to call when reading/writing */
	int	(*fcn)(struct db_variable *,db_expr_t *,int,db_var_aux_param_t);
	short	min_level;	/* number of minimum suffix levels */
	short	max_level;	/* number of maximum suffix levels */
	short	low;		/* low value of level 1 suffix */
	short	high;		/* high value of level 1 suffix */
	boolean_t hidden_level;	/* is there a hidden suffix level ? */
	short	hidden_low;	/* low value of hidden level */
	short	hidden_high;	/* high value of hidden level */
	int	*hidden_levelp;	/* value of current hidden level */
	boolean_t precious;	/* print old value when affecting ? */
#define DB_VAR_GET	0
#define DB_VAR_SET	1
#define DB_VAR_SHOW	2
};

typedef struct db_variable	*db_variable_t;

#define	DB_VAR_NULL	(db_variable_t)0

#define	FCN_NULL	((int (*)(struct db_variable *,			\
				  db_expr_t *,				\
				  int,					\
				  db_var_aux_param_t)) 0)

#define DB_VAR_LEVEL	3	/* maximum number of suffix level */
#define DB_MACRO_LEVEL	5	/* max macro nesting */
#define DB_MACRO_NARGS	10	/* max args per macro */

#define db_read_variable(vp, valuep)	\
	db_read_write_variable(vp, valuep, DB_VAR_GET, 0)
#define db_write_variable(vp, valuep)	\
	db_read_write_variable(vp, valuep, DB_VAR_SET, 0)


extern struct db_variable	db_vars[];	/* debugger variables */
extern struct db_variable	*db_evars;
extern struct db_variable	db_regs[];	/* machine registers */
extern struct db_variable	*db_eregs;

#if defined(ALTERNATE_REGISTER_DEFS)

extern struct db_variable	db_altregs[];	/* alternate machine regs */
extern struct db_variable	*db_ealtregs;

#endif /* defined(ALTERNATE_REGISTER_DEFS) */

/* Prototypes for functions exported by this module.
 */

int db_get_variable(db_expr_t *valuep);

void db_read_write_variable(
	struct db_variable	*vp,
	db_expr_t		*valuep,
	int 			rw_flag,
	db_var_aux_param_t	ap);

void db_set_cmd(void);

void db_show_one_variable(void);

void db_show_variable(void);

db_variable_t db_find_reg_name(char	*s);

#endif	/* !_DDB_DB_VARIABLES_H_ */
