/*
 * Copyright (c) 2000-2008 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991 Carnegie Mellon University
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
 *	Author: David B. Golub, Carnegie Mellon University
 *	Date:	7/90
 */

/*
 * Command dispatcher.
 */
#include <norma_vm.h>
#ifdef	AT386
#include <norma_scsi.h>
#endif	/* AT386 */

#include <mach/boolean.h>
#include <string.h>
#include <machine/db_machdep.h>

#if defined(__alpha)
#  include <kdebug.h>
#  if KDEBUG
#    include <machine/kdebug.h>
#  endif
#endif /* defined(__alpha) */

#include <ddb/db_lex.h>
#include <ddb/db_output.h>
#include <ddb/db_break.h>
#include <ddb/db_command.h>
#include <ddb/db_cond.h>
#include <ddb/db_examine.h>
#include <ddb/db_expr.h>
#if defined(__ppc__)
#include <ppc/db_low_trace.h>
#endif
#include <ddb/db_macro.h>
#include <ddb/db_print.h>
#include <ddb/db_run.h>
#include <ddb/db_task_thread.h>
#include <ddb/db_variables.h>
#include <ddb/db_watch.h>
#include <ddb/db_write_cmd.h>

#include <machine/setjmp.h>
#include <kern/thread.h>

#include <kern/misc_protos.h>
#include <vm/vm_print.h>
#include <ipc/ipc_print.h>
#include <kern/kern_print.h>
#include <machine/db_machdep.h>		/* For db_stack_trace_cmd(). */
#include <kern/zalloc.h>	/* For db_show_one_zone, db_show_all_zones. */
#include <kern/lock.h>			/* For db_show_all_slocks(). */

#if	NORMA_VM
#include <xmm/xmm_obj.h>
#endif	/* NORMA_VM */

/*
 * Exported global variables
 */
boolean_t	db_cmd_loop_done;
jmp_buf_t	*db_recover = 0;
db_addr_t	db_dot;
db_addr_t	db_last_addr;
db_addr_t	db_prev;
db_addr_t	db_next;

/*
 * if 'ed' style: 'dot' is set at start of last item printed,
 * and '+' points to next line.
 * Otherwise: 'dot' points to next item, '..' points to last.
 */
boolean_t	db_ed_style = TRUE;

/*
 * Results of command search.
 */
#define	CMD_UNIQUE	0
#define	CMD_FOUND	1
#define	CMD_NONE	2
#define	CMD_AMBIGUOUS	3
#define	CMD_HELP	4

/* Prototypes for functions local to this file.  XXX -- should be static!
 */

void db_command(
	struct db_command	**last_cmdp,	/* IN_OUT */
	db_expr_t		*last_countp,	/* IN_OUT */
	char			*last_modifp,	/* IN_OUT */
	struct db_command	*cmd_table);

void db_help_cmd(void);

void db_fncall(void);

void db_cmd_list(struct db_command *table);

int db_cmd_search(
	char *			name,
	struct db_command *	table,
	struct db_command **	cmdp);	/* out */

void db_command_list(
	struct db_command	**last_cmdp,	/* IN_OUT */
	db_expr_t		*last_countp,	/* IN_OUT */
	char			*last_modifp,	/* IN_OUT */
	struct db_command	*cmd_table);

/*
 * Search for command prefix.
 */
int
db_cmd_search(
	char *			name,
	struct db_command *	table,
	struct db_command **	cmdp)	/* out */
{
	struct db_command	*cmd;
	int		result = CMD_NONE;

	for (cmd = table; cmd->name != 0; cmd++) {
	    register char *lp;
	    const char *rp;
	    register int  c;

	    lp = name;
	    rp = cmd->name;
	    while ((c = *lp) == *rp) {
		if (c == 0) {
		    /* complete match */
		    *cmdp = cmd;
		    return (CMD_UNIQUE);
		}
		lp++;
		rp++;
	    }
	    if (c == 0) {
		/* end of name, not end of command -
		   partial match */
		if (result == CMD_FOUND) {
		    result = CMD_AMBIGUOUS;
		    /* but keep looking for a full match -
		       this lets us match single letters */
		}
		else {
		    *cmdp = cmd;
		    result = CMD_FOUND;
		}
	    }
	}
	if (result == CMD_NONE) {
	    /* check for 'help' */
	    if (!strncmp(name, "help", strlen(name)))
		result = CMD_HELP;
	}
	return (result);
}

void
db_cmd_list(struct db_command *table)
{
	struct db_command *new;
	struct db_command *old;
	struct db_command *cur;
	unsigned int l;
	unsigned int len;

	len = 1;
	for (cur = table; cur->name != 0; cur++)
	    if ((l = strlen(cur->name)) >= len)
		len = l + 1;

	old = (struct db_command *)0;
	for (;;) {
	    new = (struct db_command *)0;
	    for (cur = table; cur->name != 0; cur++)
		if ((new == (struct db_command *)0 ||
		     strncmp(cur->name, new->name, strlen(cur->name)) < 0) &&
		    (old == (struct db_command *)0 ||
		     strncmp(cur->name, old->name, strlen(cur->name)) > 0))
		    new = cur;
	    if (new == (struct db_command *)0)
		    return;
	    db_reserve_output_position(len);
	    db_printf("%-*s", len, new->name);
	    old = new;
	}
}

void
db_command(
	struct db_command	**last_cmdp,	/* IN_OUT */
	db_expr_t		*last_countp,	/* IN_OUT */
	char			*last_modifp,	/* IN_OUT */
	struct db_command	*cmd_table)
{
	struct db_command	*cmd;
	int		t;
	char		modif[TOK_STRING_SIZE];
	char		*modifp = &modif[0];
	db_expr_t	addr, count;
	boolean_t	have_addr = FALSE;
	int		result;

	t = db_read_token();
	if (t == tEOL || t == tSEMI_COLON) {
	    /* empty line repeats last command, at 'next' */
	    cmd = *last_cmdp;
	    count = *last_countp;
	    modifp = last_modifp;
	    addr = (db_expr_t)db_next;
	    have_addr = FALSE;
	    if (t == tSEMI_COLON)
		db_unread_token(t);
	}
	else if (t == tEXCL) {
	    db_fncall();
	    return;
	}
	else if (t != tIDENT) {
	    db_printf("?\n");
	    db_flush_lex();
	    return;
	}
	else {
	    /*
	     * Search for command
	     */
	    while (cmd_table) {
		result = db_cmd_search(db_tok_string,
				       cmd_table,
				       &cmd);
		switch (result) {
		    case CMD_NONE:
			if (db_exec_macro(db_tok_string) == 0)
			    return;
			db_printf("No such command \"%s\"\n", db_tok_string);
			db_flush_lex();
			return;
		    case CMD_AMBIGUOUS:
			db_printf("Ambiguous\n");
			db_flush_lex();
			return;
		    case CMD_HELP:
			db_cmd_list(cmd_table);
			db_flush_lex();
			return;
		    default:
			break;
		}
		if ((cmd_table = cmd->more) != 0) {
		    t = db_read_token();
		    if (t != tIDENT) {
			db_cmd_list(cmd_table);
			db_flush_lex();
			return;
		    }
		}
	    }

	    if ((cmd->flag & CS_OWN) == 0) {
		/*
		 * Standard syntax:
		 * command [/modifier] [addr] [,count]
		 */
		t = db_read_token();
		if (t == tSLASH) {
		    t = db_read_token();
		    if (t != tIDENT) {
			db_printf("Bad modifier \"/%s\"\n", db_tok_string);
			db_flush_lex();
			return;
		    }
		    strlcpy(modif, db_tok_string, TOK_STRING_SIZE);
		}
		else {
		    db_unread_token(t);
		    modif[0] = '\0';
		}

		if (db_expression(&addr)) {
		    db_dot = (db_addr_t) addr;
		    db_last_addr = db_dot;
		    have_addr = TRUE;
		}
		else {
		    addr = (db_expr_t) db_dot;
		    have_addr = FALSE;
		}
		t = db_read_token();
		if (t == tCOMMA) {
		    if (!db_expression(&count)) {
			db_printf("Count missing after ','\n");
			db_flush_lex();
			return;
		    }
		}
		else {
		    db_unread_token(t);
		    count = -1;
		}
	    }
	}
	if (cmd != 0) {
	    /*
	     * Execute the command.
	     */
	    (*cmd->fcn)(addr, have_addr, count, modifp);

	    if (cmd->flag & CS_SET_DOT) {
		/*
		 * If command changes dot, set dot to
		 * previous address displayed (if 'ed' style).
		 */
		if (db_ed_style) {
		    db_dot = db_prev;
		}
		else {
		    db_dot = db_next;
		}
	    }
	    else {
		/*
		 * If command does not change dot,
		 * set 'next' location to be the same.
		 */
		db_next = db_dot;
	    }
	}
	*last_cmdp = cmd;
	*last_countp = count;
	strlcpy(last_modifp, modifp, TOK_STRING_SIZE);
}

void
db_command_list(
	struct db_command	**last_cmdp,	/* IN_OUT */
	db_expr_t		*last_countp,	/* IN_OUT */
	char			*last_modifp,	/* IN_OUT */
	struct db_command	*cmd_table)
{
	do {
	    db_command(last_cmdp, last_countp, last_modifp, cmd_table);
	    db_skip_to_eol();
	} while (db_read_token() == tSEMI_COLON && db_cmd_loop_done == 0);
}


extern void	db_system_stats(void);

struct db_command db_show_all_cmds[] = {
	{
		.name = "acts",
		.fcn = db_show_all_acts,
	},
	{
		.name = "spaces",
		.fcn = db_show_all_spaces,
	},
	{
		.name = "tasks",
		.fcn = db_show_all_acts,
	},
	/* temporary alias for sanity preservation */
	{
		.name ="threads",
		db_show_all_acts,
	},
	{
		.name = "zones",
		.fcn = db_show_all_zones,
	},
	{
		.name = "vmtask",
		.fcn = db_show_all_task_vm,
	},
	{
		.name = (const char *)NULL,
       	},
};

/* XXX */

extern void		db_show_thread_log(void);
extern void		db_show_etap_log(db_expr_t, int, db_expr_t, char *);

struct db_command db_show_cmds[] = {
	{
		.name = "all",
		.more = db_show_all_cmds
	},
	{
		.name = "registers",
		.fcn = db_show_regs,
	},
	{
		.name = "variables",
		.fcn = db_show_variable,
		.flag = CS_OWN,
	},
	{
		.name = "breaks",
		.fcn = db_listbreak_cmd,
	},
	{
		.name = "watches",
		.fcn = db_listwatch_cmd,
	},
	{
		.name = "task",
		.fcn = db_show_one_task,
	},
	{
		.name = "act",
		.fcn = db_show_one_act,
	},
	{
		.name = "shuttle",
		.fcn = db_show_shuttle,
	},
#if 0
	{
		.name = "thread",
		.fcn = db_show_one_thread,
	},
#endif
	{
		.name = "vmtask",
		.fcn = db_show_one_task_vm,
	},
	{
		.name = "macro",
		.fcn = (db_func)db_show_macro,
		.flag = CS_OWN,
	},
	{
		.name = "runq",
		.fcn = (db_func)db_show_runq,
	},
	{
		.name = "map",
		.fcn = (db_func)vm_map_print,
	},
	{
		.name = "object",
		.fcn = vm_object_print,
	},
	{
		.name = "page",
		.fcn = (db_func)vm_page_print,
	},
	{
		.name = "copy",
		.fcn = (db_func)vm_map_copy_print,
	},
	{
		.name = "port",
		.fcn = (db_func)ipc_port_print,
	},
	{
		.name = "pset",
		.fcn = (db_func)ipc_pset_print,
	},
	{
		.name = "kmsg",
		.fcn = (db_func)ipc_kmsg_print,
	},
	{
		.name = "msg",
		.fcn = (db_func)ipc_msg_print,
	},
	{
		.name = "ipc_port",
		.fcn = db_show_port_id,
	},
#if NORMA_VM
	{
		.name = "xmm_obj",
		.fcn = (db_func)xmm_obj_print,
	},
	{
		.name = "xmm_reply",
		.fcn = (db_func)xmm_reply_print,
	},
#endif	/* NORMA_VM */
	{
		.name = "space",
		.fcn = db_show_one_space,
	},
	{
		.name = "system",
		.fcn = (db_func)db_system_stats,
	},
	{
		.name = "zone",
		.fcn = db_show_one_zone,
	},
	{
		.name = "lock",
		.fcn = (db_func)db_show_one_lock,
	},
	{
		.name = "simple_lock",
		.fcn = (db_func)db_show_one_simple_lock,
	},
	{
		.name = "thread_log",
		(db_func)db_show_thread_log,
	},
	{
		.name = "shuttle",
		.fcn = db_show_shuttle,
	},
	{
		.name = (const char *)NULL,
	},
};

#define	db_switch_cpu kdb_on

struct db_command db_command_table[] = {
#if DB_MACHINE_COMMANDS
	/* this must be the first entry, if it exists */
	{
		.name = "machine",
	},
#endif /* DB_MACHINE_COMMANDS */
	{
		.name = "print",
		.fcn = (db_func)db_print_cmd,
		.flag = CS_OWN,
	},
	{
		.name = "examine",
		.fcn = db_examine_cmd,
		.flag = CS_MORE|CS_SET_DOT,
	},
	{
		.name = "x",
		.fcn = db_examine_cmd,
		.flag = CS_MORE|CS_SET_DOT,
	},
	{
		.name = "xf",
		.fcn = db_examine_forward,
		.flag = CS_SET_DOT,
	},
	{
		.name = "xb",
		.fcn = db_examine_backward,
		.flag = CS_SET_DOT,
	},
	{
		.name = "search",
		.fcn = (db_func)db_search_cmd,
		.flag = CS_OWN|CS_SET_DOT,
	},
	{
		.name = "set",
		.fcn = (db_func)db_set_cmd,
		.flag = CS_OWN,
	},
	{
		.name = "write",
		.fcn = db_write_cmd,
		.flag = CS_MORE|CS_SET_DOT,
	},
	{
		.name = "w",
		.fcn = db_write_cmd,
		.flag = CS_MORE|CS_SET_DOT,
	},
	{
		.name = "delete",
		.fcn = (db_func)db_delete_cmd,
		.flag = CS_OWN,
	},
	{
		.name = "d",
		.fcn = (db_func)db_delete_cmd,
		.flag = CS_OWN,
	},
	{
		.name = "break",
		.fcn = db_breakpoint_cmd,
		.flag = CS_MORE,
	},
	{
		.name = "dwatch",
		.fcn = db_deletewatch_cmd,
		.flag = CS_MORE,
	},
	{
		.name = "watch",
		.fcn = db_watchpoint_cmd,
		.flag = CS_MORE,
	},
	{
		.name = "step",
		.fcn = db_single_step_cmd,
	},
	{
		.name = "s",
		.fcn = db_single_step_cmd,
	},
	{
		.name = "continue",
		.fcn = db_continue_cmd,
	},
	{
		.name = "c",
		.fcn = db_continue_cmd,
	},
	{
		.name = "gdb",
		.fcn = db_continue_gdb,
	},
	{
		.name = "until",
		.fcn = db_trace_until_call_cmd,
	},

	/* As per request of DNoveck, CR1550, leave this disabled	*/
#if 0	/* until CR1440 is fixed, to avoid toe-stubbing			*/
	{
		.name = "next",
		.fcn = db_trace_until_matching_cmd,
	},
#endif
	{
		.name = "match",
		.fcn = db_trace_until_matching_cmd,
	},
	{
		.name = "trace",
		.fcn = db_stack_trace_cmd,
	},
	{
		.name = "cond",
		.fcn = (db_func)db_cond_cmd,
		.flag = CS_OWN,
	},
	{
		.name = "call",
		.fcn = (db_func)db_fncall,
		.flag = CS_OWN,
	},
	{
		.name = "macro",
		.fcn = (db_func)db_def_macro_cmd,
		.flag = CS_OWN,
	},
	{
		.name = "dmacro",
		.fcn = (db_func)db_del_macro_cmd,
		.flag = CS_OWN,
	},
	{
		.name = "show",
		.more = db_show_cmds
	},
	{
		.name = "cpu",
		.fcn = (db_func)db_switch_cpu,
	},
	{
		.name = "dr",
		.fcn = db_display_real,
		.flag = CS_MORE|CS_SET_DOT,
	},
	{
		.name = "di",
		.fcn = db_display_iokit,
		.flag = CS_MORE,
	},
	{
		.name = "dk",
		.fcn = db_display_kmod,
		.flag = CS_MORE,
	},

	{
		.name = "reboot",
		(db_func)db_reboot,
	},
#if !defined(__ppc__)	
	{
		.name = "ms",
		.fcn = db_msr,
		.flag = CS_MORE,
	},
	{
		.name = "cp",
		.fcn = db_cpuid,
		.flag = CS_MORE,
	},
	{
		.name = "da",
		.fcn = db_apic,
		.flag = CS_MORE,
	},
#endif /* !__ppc__ */
#if defined(__ppc__)	
	{
		.name = "lt",
		.fcn = db_low_trace,
		.flag = CS_MORE|CS_SET_DOT,
	},
	{
		.name = "dl",
		.fcn = db_display_long,
		.flag = CS_MORE|CS_SET_DOT,
	},
	{
		.name = "dc",
		.fcn = db_display_char,
		.flag = CS_MORE|CS_SET_DOT,
	},
	{
		.name = "dv",
		.fcn = db_display_virtual,
		.flag = CS_MORE|CS_SET_DOT,
	},
	{
		.name = "dm",
		.fcn = db_display_mappings,
		.flag = CS_MORE|CS_SET_DOT,
	},
	{
		.name = "dh",
		.fcn = db_display_hash,
		.flag = CS_MORE|CS_SET_DOT,
	},
	{
		.name = "dp",
		.fcn = db_display_pmap,
		.flag = CS_MORE,
	},
	{
		.name = "ds",
		.fcn = db_display_save,
		.flag = CS_MORE|CS_SET_DOT,
	},
	{
		.name = "dx",
		.fcn = db_display_xregs,
		.flag = CS_MORE|CS_SET_DOT,
	},
	{
		.name = "gs",
		.fcn = db_gsnoop,
		.flag = CS_MORE,
	},
	{
		.name = "cm",
		.fcn = db_check_mappings,
		.flag = CS_MORE,
	},
	{
		.name = "cp",
		.fcn = db_check_pmaps,
		.flag = CS_MORE,
	},
#endif /* __ppc__ */
	{
		.name = (const char *)NULL,
	},
};

/* this function should be called to install the machine dependent
   commands. It should be called before the debugger is enabled  */
void db_machine_commands_install(struct db_command *ptr)
{
  db_command_table[0].more = ptr;
  return;
}


struct db_command	*db_last_command = 0;
db_expr_t		db_last_count = 0;
char			db_last_modifier[TOK_STRING_SIZE] = { '\0' };

void
db_help_cmd(void)
{
	struct db_command *cmd = db_command_table;

	while (cmd->name != 0) {
	    db_printf("%-12s", cmd->name);
	    db_end_line();
	    cmd++;
	}
}

int	(*ddb_display)(void);

extern int db_output_line;
extern int db_macro_level;

void
db_command_loop(void)
{
	jmp_buf_t db_jmpbuf;
	jmp_buf_t *prev = db_recover;

	/*
	 * Initialize 'prev' and 'next' to dot.
	 */
	db_prev = db_dot;
	db_next = db_dot;

	if (ddb_display)
		(*ddb_display)();

	db_cmd_loop_done = 0;
	while (!db_cmd_loop_done) {
	    (void) _setjmp(db_recover = &db_jmpbuf);
	    db_macro_level = 0;
	    if (db_print_position() != 0)
		db_printf("\n");
	    db_output_line = 0;
	    db_indent = 0;
	    db_reset_more();
	    db_output_prompt();

	    (void) db_read_line("!!");
	    db_command_list(&db_last_command, &db_last_count,
			    db_last_modifier, db_command_table);
	}

	db_recover = prev;
}

boolean_t
db_exec_cmd_nest(
	const char	*cmd,
	int		size)
{
	struct db_lex_context lex_context;

	db_cmd_loop_done = 0;
	if (cmd) {
	    db_save_lex_context(&lex_context);
	    db_switch_input(cmd, size);
	}
	db_command_list(&db_last_command, &db_last_count,
			db_last_modifier, db_command_table);
	if (cmd)
	    db_restore_lex_context(&lex_context);
	return(db_cmd_loop_done == 0);
}

void
db_error(const char *s)
{
	db_macro_level = 0;
	if (db_recover) {
	    if (s > (char *)1)
		db_printf(s);
	    db_flush_lex();
	    _longjmp(db_recover, (s == (char *)1) ? 2 : 1);
	}
	else
	{
	    if (s > (char *)1)
	        db_printf(s);
	    panic("db_error");
	}
}


/*
 * Call random function:
 * !expr(arg,arg,arg)
 */
void
db_fncall(void)
{
	db_expr_t	fn_addr;
#define	MAXARGS		11
	uint32_t	args[MAXARGS];
	db_expr_t argwork;
	int		nargs = 0;
	uint32_t	retval;
	uint32_t	(*func)(uint32_t, ...);
	int		t;

	if (!db_expression(&fn_addr)) {
	    db_printf("Bad function \"%s\"\n", db_tok_string);
	    db_flush_lex();
	    return;
	}
	func = (uint32_t (*) (uint32_t, ...))(unsigned long)fn_addr;

	t = db_read_token();
	if (t == tLPAREN) {
	    if (db_expression(&argwork)) {
			args[nargs] = (uint32_t)argwork;
			nargs++;
			while ((t = db_read_token()) == tCOMMA) {
				if (nargs == MAXARGS) {
					db_printf("Too many arguments\n");
					db_flush_lex();
					return;
				}
				if (!db_expression(&argwork)) {
					db_printf("Argument missing\n");
					db_flush_lex();
					return;
				}
				args[nargs] = (uint32_t)argwork;
				nargs++;
			}
			db_unread_token(t);
	    }
	    if (db_read_token() != tRPAREN) {
			db_printf("?\n");
			db_flush_lex();
			return;
	    }
	}
	while (nargs < MAXARGS) {
	    args[nargs++] = 0;
	}

	retval = (*func)(args[0], args[1], args[2], args[3], args[4],
			 args[5], args[6], args[7], args[8], args[9] );
	db_printf(" %#n\n", retval);
}

boolean_t
db_option(
	const char	*modif,
	int		option)
{
	const char *p;

	for (p = modif; *p; p++)
	    if (*p == option)
		return(TRUE);
	return(FALSE);
}
