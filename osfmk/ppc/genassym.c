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

/*
 * genassym.c is used to produce an
 * assembly file which, intermingled with unuseful assembly code,
 * has all the necessary definitions emitted. This assembly file is
 * then postprocessed with sed to extract only these definitions
 * and thus the final assyms.s is created.
 *
 * This convoluted means is necessary since the structure alignment
 * and packing may be different between the host machine and the
 * target so we are forced into using the cross compiler to generate
 * the values, but we cannot run anything on the target machine.
 */

#include <cpus.h>
#include <va_list.h>
#include <types.h>

#include <kern/task.h>
#include <kern/thread.h>
#include <kern/thread_act.h>
#include <kern/host.h>
#include <kern/lock.h>
#include <kern/processor.h>
#include <ppc/exception.h>
#include <ppc/thread_act.h>
#include <ppc/misc_protos.h>
#include <kern/syscall_sw.h>
#include <kern/ast.h>
#include <ppc/low_trace.h>
#include <ppc/PseudoKernel.h>
#include <ppc/mappings.h>
#include <ppc/Firmware.h>
#include <ppc/low_trace.h>
#include <vm/vm_map.h>
#include <vm/pmap.h>
#include <ppc/pmap.h>
#include <ppc/pmap_internals.h>
#include <ppc/Diagnostics.h>
#include <ppc/POWERMAC/mp/MPPlugIn.h>
#include <pexpert/pexpert.h>
#include <mach/machine.h>
#include <ppc/vmachmon.h>
#include <ppc/PPCcalls.h>

#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE)0)->MEMBER)

#define DECLARE(SYM,VAL) \
	__asm("#DEFINITION##define\t" SYM "\t%0" : : "n" ((u_int)(VAL)))

int main(int argc, char *argv[])
{
	/* Process Control Block */

	DECLARE("PCB_FLOAT_STATE", offsetof(struct pcb *, fs));

	/* Floating point state */

	DECLARE("PCB_FS_F0",	offsetof(struct pcb *, fs.fpregs[0]));
	DECLARE("PCB_FS_F1",	offsetof(struct pcb *, fs.fpregs[1]));
	DECLARE("PCB_FS_F2",	offsetof(struct pcb *, fs.fpregs[2]));
	DECLARE("PCB_FS_F3",	offsetof(struct pcb *, fs.fpregs[3]));
	DECLARE("PCB_FS_F4",	offsetof(struct pcb *, fs.fpregs[4]));
	DECLARE("PCB_FS_F5",	offsetof(struct pcb *, fs.fpregs[5]));
	DECLARE("PCB_FS_F6",	offsetof(struct pcb *, fs.fpregs[6]));
	DECLARE("PCB_FS_F7",	offsetof(struct pcb *, fs.fpregs[7]));
	DECLARE("PCB_FS_F8",	offsetof(struct pcb *, fs.fpregs[8]));
	DECLARE("PCB_FS_F9",	offsetof(struct pcb *, fs.fpregs[9]));
	DECLARE("PCB_FS_F10",	offsetof(struct pcb *, fs.fpregs[10]));
	DECLARE("PCB_FS_F11",	offsetof(struct pcb *, fs.fpregs[11]));
	DECLARE("PCB_FS_F12",	offsetof(struct pcb *, fs.fpregs[12]));
	DECLARE("PCB_FS_F13",	offsetof(struct pcb *, fs.fpregs[13]));
	DECLARE("PCB_FS_F14",	offsetof(struct pcb *, fs.fpregs[14]));
	DECLARE("PCB_FS_F15",	offsetof(struct pcb *, fs.fpregs[15]));
	DECLARE("PCB_FS_F16",	offsetof(struct pcb *, fs.fpregs[16]));
	DECLARE("PCB_FS_F17",	offsetof(struct pcb *, fs.fpregs[17]));
	DECLARE("PCB_FS_F18",	offsetof(struct pcb *, fs.fpregs[18]));
	DECLARE("PCB_FS_F19",	offsetof(struct pcb *, fs.fpregs[19]));
	DECLARE("PCB_FS_F20",	offsetof(struct pcb *, fs.fpregs[20]));
	DECLARE("PCB_FS_F21",	offsetof(struct pcb *, fs.fpregs[21]));
	DECLARE("PCB_FS_F22",	offsetof(struct pcb *, fs.fpregs[22]));
	DECLARE("PCB_FS_F23",	offsetof(struct pcb *, fs.fpregs[23]));
	DECLARE("PCB_FS_F24",	offsetof(struct pcb *, fs.fpregs[24]));
	DECLARE("PCB_FS_F25",	offsetof(struct pcb *, fs.fpregs[25]));
	DECLARE("PCB_FS_F26",	offsetof(struct pcb *, fs.fpregs[26]));
	DECLARE("PCB_FS_F27",	offsetof(struct pcb *, fs.fpregs[27]));
	DECLARE("PCB_FS_F28",	offsetof(struct pcb *, fs.fpregs[28]));
	DECLARE("PCB_FS_F29",	offsetof(struct pcb *, fs.fpregs[29]));
	DECLARE("PCB_FS_F30",	offsetof(struct pcb *, fs.fpregs[30]));
	DECLARE("PCB_FS_F31",	offsetof(struct pcb *, fs.fpregs[31]));
	DECLARE("PCB_FS_FPSCR",	offsetof(struct pcb *, fs.fpscr_pad));

	DECLARE("PCB_SAVED_STATE",offsetof(struct pcb *, ss));
	DECLARE("ACT_MACT_KSP",	offsetof(struct thread_activation *, mact.ksp));
	DECLARE("ACT_MACT_BEDA", offsetof(struct thread_activation *, mact.bbDescAddr));
	DECLARE("ACT_MACT_BTS",	offsetof(struct thread_activation *, mact.bbTableStart));
	DECLARE("ACT_MACT_BTE",	offsetof(struct thread_activation *, mact.bbTaskEnv));
	DECLARE("ACT_MACT_SPF",	offsetof(struct thread_activation *, mact.specFlags));
	DECLARE("qactTimer",	offsetof(struct thread_activation *, mact.qactTimer));
	DECLARE("floatUsed",	floatUsed);
	DECLARE("vectorUsed",	vectorUsed);
	DECLARE("bbNoMachSCbit",bbNoMachSCbit);
	DECLARE("runningVM",	runningVM);
	DECLARE("floatCng",		floatCng);
	DECLARE("vectorCng",	vectorCng);
	DECLARE("floatCngbit",	floatCngbit);
	DECLARE("vectorCngbit",	vectorCngbit);

	DECLARE("PCB_SIZE",	sizeof(struct pcb));

	/* Save State Structure */
	DECLARE("SS_R0",	offsetof(struct ppc_saved_state *, r0));
	DECLARE("SS_R1",	offsetof(struct ppc_saved_state *, r1));
	DECLARE("SS_R2",	offsetof(struct ppc_saved_state *, r2));
	DECLARE("SS_R3",	offsetof(struct ppc_saved_state *, r3));
	DECLARE("SS_R4",	offsetof(struct ppc_saved_state *, r4));
	DECLARE("SS_R5",	offsetof(struct ppc_saved_state *, r5));
	DECLARE("SS_R6",	offsetof(struct ppc_saved_state *, r6));
	DECLARE("SS_R7",	offsetof(struct ppc_saved_state *, r7));
	DECLARE("SS_R8",	offsetof(struct ppc_saved_state *, r8));
	DECLARE("SS_R9",	offsetof(struct ppc_saved_state *, r9));
	DECLARE("SS_R10",	offsetof(struct ppc_saved_state *, r10));
	DECLARE("SS_R11",	offsetof(struct ppc_saved_state *, r11));
	DECLARE("SS_R12",	offsetof(struct ppc_saved_state *, r12));
	DECLARE("SS_R13",	offsetof(struct ppc_saved_state *, r13));
	DECLARE("SS_R14",	offsetof(struct ppc_saved_state *, r14));
	DECLARE("SS_R15",	offsetof(struct ppc_saved_state *, r15));
	DECLARE("SS_R16",	offsetof(struct ppc_saved_state *, r16));
	DECLARE("SS_R17",	offsetof(struct ppc_saved_state *, r17));
	DECLARE("SS_R18",	offsetof(struct ppc_saved_state *, r18));
	DECLARE("SS_R19",	offsetof(struct ppc_saved_state *, r19));
	DECLARE("SS_R20",	offsetof(struct ppc_saved_state *, r20));
	DECLARE("SS_R21",	offsetof(struct ppc_saved_state *, r21));
	DECLARE("SS_R22",	offsetof(struct ppc_saved_state *, r22));
	DECLARE("SS_R23",	offsetof(struct ppc_saved_state *, r23));
	DECLARE("SS_R24",	offsetof(struct ppc_saved_state *, r24));
	DECLARE("SS_R25",	offsetof(struct ppc_saved_state *, r25));
	DECLARE("SS_R26",	offsetof(struct ppc_saved_state *, r26));
	DECLARE("SS_R27",	offsetof(struct ppc_saved_state *, r27));
	DECLARE("SS_R28",	offsetof(struct ppc_saved_state *, r28));
	DECLARE("SS_R29",	offsetof(struct ppc_saved_state *, r29));
	DECLARE("SS_R30",	offsetof(struct ppc_saved_state *, r30));
	DECLARE("SS_R31",	offsetof(struct ppc_saved_state *, r31));
	DECLARE("SS_CR",	offsetof(struct ppc_saved_state *, cr));
	DECLARE("SS_XER",	offsetof(struct ppc_saved_state *, xer));
	DECLARE("SS_LR",	offsetof(struct ppc_saved_state *, lr));
	DECLARE("SS_CTR",	offsetof(struct ppc_saved_state *, ctr));
	DECLARE("SS_SRR0",	offsetof(struct ppc_saved_state *, srr0));
	DECLARE("SS_SRR1",	offsetof(struct ppc_saved_state *, srr1));
	DECLARE("SS_MQ",	offsetof(struct ppc_saved_state *, mq));
	DECLARE("SS_SR_COPYIN",	offsetof(struct ppc_saved_state *, sr_copyin));
	DECLARE("SS_SIZE",	sizeof(struct ppc_saved_state));

	/* Per Proc info structure */
	DECLARE("PP_CPU_NUMBER",		offsetof(struct per_proc_info *, cpu_number));
	DECLARE("PP_CPU_FLAGS",			offsetof(struct per_proc_info *, cpu_flags));
	DECLARE("PP_ISTACKPTR",			offsetof(struct per_proc_info *, istackptr));
	DECLARE("PP_INTSTACK_TOP_SS",	offsetof(struct per_proc_info *, intstack_top_ss));
#if MACH_KDP || MACH_KDB
	DECLARE("PP_DEBSTACKPTR",		offsetof(struct per_proc_info *, debstackptr));
	DECLARE("PP_DEBSTACK_TOP_SS",	offsetof(struct per_proc_info *, debstack_top_ss));
#endif
	DECLARE("PP_TEMPWORK1",			offsetof(struct per_proc_info *, tempwork1));
	DECLARE("PP_USERSPACE",			offsetof(struct per_proc_info *, userspace));
	DECLARE("PP_USERPMAP",			offsetof(struct per_proc_info *, userpmap));
	DECLARE("PP_LASTPMAP",			offsetof(struct per_proc_info *, Lastpmap));
	DECLARE("savedSave",			offsetof(struct per_proc_info *, savedSave));

	DECLARE("PP_SAVE_EXCEPTION_TYPE", offsetof(struct per_proc_info *, save_exception_type));
	DECLARE("PP_CPU_DATA", 			offsetof(struct per_proc_info *, cpu_data));
	DECLARE("PP_ACTIVE_KLOADED", 	offsetof(struct per_proc_info *, active_kloaded));
	DECLARE("PP_ACTIVE_STACKS", 	offsetof(struct per_proc_info *, active_stacks));
	DECLARE("PP_NEED_AST", 			offsetof(struct per_proc_info *, need_ast));
	DECLARE("PP_FPU_THREAD", 		offsetof(struct per_proc_info *, FPU_thread));
	DECLARE("FPU_vmmCtx", 			offsetof(struct per_proc_info *, FPU_vmmCtx));
	DECLARE("PP_VMX_THREAD", 		offsetof(struct per_proc_info *, VMX_thread));
	DECLARE("VMX_vmmCtx", 			offsetof(struct per_proc_info *, VMX_vmmCtx));
	DECLARE("PP_QUICKFRET", 		offsetof(struct per_proc_info *, quickfret));
	DECLARE("UAW", 					offsetof(struct per_proc_info *, Uassist));
	DECLARE("liveVRS", 				offsetof(struct per_proc_info *, liveVRSave));
	DECLARE("liveFPSCR", 			offsetof(struct per_proc_info *, liveFPSCR));
	DECLARE("spcFlags", 			offsetof(struct per_proc_info *, spcFlags));
	DECLARE("spcTRc", 				offsetof(struct per_proc_info *, spcTRc));
	DECLARE("spcTRp", 				offsetof(struct per_proc_info *, spcTRp));
	DECLARE("ruptStamp", 			offsetof(struct per_proc_info *, ruptStamp));
	DECLARE("pfAvailable", 			offsetof(struct per_proc_info *, pf.Available));
	DECLARE("pfFloat",				pfFloat);
	DECLARE("pfFloatb",				pfFloatb);
	DECLARE("pfAltivec",			pfAltivec);
	DECLARE("pfAltivecb",			pfAltivecb);
	DECLARE("pfAvJava",				pfAvJava);
	DECLARE("pfAvJavab",			pfAvJavab);
	DECLARE("pfSMPcap",				pfSMPcap);
	DECLARE("pfSMPcapb",			pfSMPcapb);
	DECLARE("pfCanSleep",			pfCanSleep);
	DECLARE("pfCanSleepb",			pfCanSleepb);
	DECLARE("pfCanNap",				pfCanNap);
	DECLARE("pfCanNapb",			pfCanNapb);
	DECLARE("pfCanDoze",			pfCanDoze);
	DECLARE("pfCanDozeb",			pfCanDozeb);
	DECLARE("pfCanDoze",			pfCanDoze);
	DECLARE("pfCanDozeb",			pfCanDozeb);
	DECLARE("pfThermal",			pfThermal);
	DECLARE("pfThermalb",			pfThermalb);
	DECLARE("pfThermInt",			pfThermInt);
	DECLARE("pfThermIntb",			pfThermIntb);
	DECLARE("pfL23lck",				pfL23lck);
	DECLARE("pfL23lckb",			pfL23lckb);
	DECLARE("pfWillNap",			pfWillNap);
	DECLARE("pfWillNapb",			pfWillNapb);
	DECLARE("pfNoMSRir",			pfNoMSRir);
	DECLARE("pfNoMSRirb",			pfNoMSRirb);
	DECLARE("pfL1nnc",				pfL1nnc);
	DECLARE("pfL1nncb",				pfL1nncb);
	DECLARE("pfL1i",				pfL1i);
	DECLARE("pfL1ib",				pfL1ib);
	DECLARE("pfL1d",				pfL1d);
	DECLARE("pfL1db",				pfL1db);
	DECLARE("pfL1fa",				pfL1fa);
	DECLARE("pfL1fab",				pfL1fab);
	DECLARE("pfL2",					pfL2);
	DECLARE("pfL2b",				pfL2b);
	DECLARE("pfL2fa",				pfL2fa);
	DECLARE("pfL2fab",				pfL2fab);
	DECLARE("pfL2i",				pfL2i);
	DECLARE("pfL2ib",				pfL2ib);
	DECLARE("pfL3",					pfL3);
	DECLARE("pfL3b",				pfL3b);
	DECLARE("pfL3fa",				pfL3fa);
	DECLARE("pfL3fab",				pfL3fab);
	DECLARE("pfValid",				pfValid);
	DECLARE("pfValidb",				pfValidb);
	DECLARE("pfrptdProc", 			offsetof(struct per_proc_info *, pf.rptdProc));
	DECLARE("pflineSize", 			offsetof(struct per_proc_info *, pf.lineSize));
	DECLARE("pfl1iSize", 			offsetof(struct per_proc_info *, pf.l1iSize));
	DECLARE("pfl1dSize", 			offsetof(struct per_proc_info *, pf.l1dSize));
	DECLARE("pfl2cr", 				offsetof(struct per_proc_info *, pf.l2cr));
	DECLARE("pfl2Size", 			offsetof(struct per_proc_info *, pf.l2Size));
	DECLARE("pfl3cr", 				offsetof(struct per_proc_info *, pf.l3cr));
	DECLARE("pfl3Size", 			offsetof(struct per_proc_info *, pf.l3Size));
	DECLARE("pfHID0", 				offsetof(struct per_proc_info *, pf.pfHID0));
	DECLARE("pfHID1", 				offsetof(struct per_proc_info *, pf.pfHID1));
	DECLARE("pfHID2", 				offsetof(struct per_proc_info *, pf.pfHID2));
	DECLARE("pfHID3", 				offsetof(struct per_proc_info *, pf.pfHID3));
	DECLARE("pfMSSCR0", 			offsetof(struct per_proc_info *, pf.pfMSSCR0));
	DECLARE("pfMSSCR1", 			offsetof(struct per_proc_info *, pf.pfMSSCR1));
	DECLARE("pfICTRL", 			offsetof(struct per_proc_info *, pf.pfICTRL));
	DECLARE("pfLDSTCR", 			offsetof(struct per_proc_info *, pf.pfLDSTCR));
	DECLARE("pfSize", 				sizeof(procFeatures));
	
	DECLARE("thrmmaxTemp", 			offsetof(struct per_proc_info *, thrm.maxTemp));
	DECLARE("thrmthrottleTemp", 	offsetof(struct per_proc_info *, thrm.throttleTemp));
	DECLARE("thrmlowTemp", 			offsetof(struct per_proc_info *, thrm.lowTemp));
	DECLARE("thrmhighTemp", 		offsetof(struct per_proc_info *, thrm.highTemp));
	DECLARE("thrm3val", 			offsetof(struct per_proc_info *, thrm.thrm3val));
	DECLARE("thrmSize", 			sizeof(thrmControl));

	DECLARE("napStamp", 			offsetof(struct per_proc_info *, napStamp));
	DECLARE("napTotal", 			offsetof(struct per_proc_info *, napTotal));

	DECLARE("emfp0", 				offsetof(struct per_proc_info *, emfp0));
	DECLARE("emfp1", 				offsetof(struct per_proc_info *, emfp1));
	DECLARE("emfp2", 				offsetof(struct per_proc_info *, emfp2));
	DECLARE("emfp3", 				offsetof(struct per_proc_info *, emfp3));
	DECLARE("emfp4", 				offsetof(struct per_proc_info *, emfp4));
	DECLARE("emfp5", 				offsetof(struct per_proc_info *, emfp5));
	DECLARE("emfp6", 				offsetof(struct per_proc_info *, emfp6));
	DECLARE("emfp7", 				offsetof(struct per_proc_info *, emfp7));
	DECLARE("emfp8", 				offsetof(struct per_proc_info *, emfp8));
	DECLARE("emfp9", 				offsetof(struct per_proc_info *, emfp9));
	DECLARE("emfp10", 				offsetof(struct per_proc_info *, emfp10));
	DECLARE("emfp11", 				offsetof(struct per_proc_info *, emfp11));
	DECLARE("emfp12", 				offsetof(struct per_proc_info *, emfp12));
	DECLARE("emfp13", 				offsetof(struct per_proc_info *, emfp13));
	DECLARE("emfp14", 				offsetof(struct per_proc_info *, emfp14));
	DECLARE("emfp15", 				offsetof(struct per_proc_info *, emfp15));
	DECLARE("emfp16", 				offsetof(struct per_proc_info *, emfp16));
	DECLARE("emfp17", 				offsetof(struct per_proc_info *, emfp17));
	DECLARE("emfp18", 				offsetof(struct per_proc_info *, emfp18));
	DECLARE("emfp19", 				offsetof(struct per_proc_info *, emfp19));
	DECLARE("emfp20", 				offsetof(struct per_proc_info *, emfp20));
	DECLARE("emfp21", 				offsetof(struct per_proc_info *, emfp21));
	DECLARE("emfp22", 				offsetof(struct per_proc_info *, emfp22));
	DECLARE("emfp23", 				offsetof(struct per_proc_info *, emfp23));
	DECLARE("emfp24", 				offsetof(struct per_proc_info *, emfp24));
	DECLARE("emfp25", 				offsetof(struct per_proc_info *, emfp25));
	DECLARE("emfp26", 				offsetof(struct per_proc_info *, emfp26));
	DECLARE("emfp27", 				offsetof(struct per_proc_info *, emfp27));
	DECLARE("emfp28", 				offsetof(struct per_proc_info *, emfp28));
	DECLARE("emfp29", 				offsetof(struct per_proc_info *, emfp29));
	DECLARE("emfp30", 				offsetof(struct per_proc_info *, emfp30));
	DECLARE("emfp31", 				offsetof(struct per_proc_info *, emfp31));
	DECLARE("emfpscr_pad", 			offsetof(struct per_proc_info *, emfpscr_pad));
	DECLARE("emfpscr", 				offsetof(struct per_proc_info *, emfpscr));

	DECLARE("emvr0", 				offsetof(struct per_proc_info *, emvr0));
	DECLARE("emvr1", 				offsetof(struct per_proc_info *, emvr1));
	DECLARE("emvr2", 				offsetof(struct per_proc_info *, emvr2));
	DECLARE("emvr3", 				offsetof(struct per_proc_info *, emvr3));
	DECLARE("emvr4", 				offsetof(struct per_proc_info *, emvr4));
	DECLARE("emvr5", 				offsetof(struct per_proc_info *, emvr5));
	DECLARE("emvr6", 				offsetof(struct per_proc_info *, emvr6));
	DECLARE("emvr7", 				offsetof(struct per_proc_info *, emvr7));
	DECLARE("emvr8", 				offsetof(struct per_proc_info *, emvr8));
	DECLARE("emvr9", 				offsetof(struct per_proc_info *, emvr9));
	DECLARE("emvr10", 				offsetof(struct per_proc_info *, emvr10));
	DECLARE("emvr11", 				offsetof(struct per_proc_info *, emvr11));
	DECLARE("emvr12", 				offsetof(struct per_proc_info *, emvr12));
	DECLARE("emvr13", 				offsetof(struct per_proc_info *, emvr13));
	DECLARE("emvr14", 				offsetof(struct per_proc_info *, emvr14));
	DECLARE("emvr15", 				offsetof(struct per_proc_info *, emvr15));
	DECLARE("emvr16", 				offsetof(struct per_proc_info *, emvr16));
	DECLARE("emvr17", 				offsetof(struct per_proc_info *, emvr17));
	DECLARE("emvr18", 				offsetof(struct per_proc_info *, emvr18));
	DECLARE("emvr19", 				offsetof(struct per_proc_info *, emvr19));
	DECLARE("emvr20", 				offsetof(struct per_proc_info *, emvr20));
	DECLARE("emvr21", 				offsetof(struct per_proc_info *, emvr21));
	DECLARE("emvr22", 				offsetof(struct per_proc_info *, emvr22));
	DECLARE("emvr23", 				offsetof(struct per_proc_info *, emvr23));
	DECLARE("emvr24", 				offsetof(struct per_proc_info *, emvr24));
	DECLARE("emvr25", 				offsetof(struct per_proc_info *, emvr25));
	DECLARE("emvr26", 				offsetof(struct per_proc_info *, emvr26));
	DECLARE("emvr27", 				offsetof(struct per_proc_info *, emvr27));
	DECLARE("emvr28", 				offsetof(struct per_proc_info *, emvr28));
	DECLARE("emvr29", 				offsetof(struct per_proc_info *, emvr29));
	DECLARE("emvr30", 				offsetof(struct per_proc_info *, emvr30));
	DECLARE("emvr31", 				offsetof(struct per_proc_info *, emvr31));
	DECLARE("empadvr", 				offsetof(struct per_proc_info *, empadvr));
	DECLARE("ppSize",				sizeof(struct per_proc_info));

	DECLARE("RESETHANDLER_TYPE", 			offsetof(struct resethandler *, type));
	DECLARE("RESETHANDLER_CALL", 			offsetof(struct resethandler *, call_paddr));
	DECLARE("RESETHANDLER_ARG", 			offsetof(struct resethandler *, arg__paddr));

	/* we want offset from
	 * bottom of kernel stack, not offset into structure
	 */
#define IKSBASE (u_int)STACK_IKS(0)

	/* values from kern/thread.h */
	DECLARE("THREAD_TOP_ACT",
		offsetof(struct thread_shuttle *, top_act));
	DECLARE("THREAD_KERNEL_STACK",
		offsetof(struct thread_shuttle *, kernel_stack));
	DECLARE("THREAD_CONTINUATION",
		offsetof(struct thread_shuttle *, continuation));
	DECLARE("THREAD_RECOVER",
		offsetof(struct thread_shuttle *, recover));
#if	MACH_LDEBUG
	DECLARE("THREAD_MUTEX_COUNT",
		offsetof(struct thread_shuttle *, mutex_count));
#endif	/* MACH_LDEBUG */
	DECLARE("THREAD_PSET", offsetof(struct thread_shuttle *, processor_set));
	DECLARE("THREAD_LINKS", offsetof(struct thread_shuttle *, links));
	DECLARE("THREAD_PSTHRN", offsetof(struct thread_shuttle *, pset_threads.next));

	/* values from kern/thread_act.h */
	DECLARE("ACT_TASK",    offsetof(struct thread_activation *, task));
	DECLARE("ACT_THREAD",    offsetof(struct thread_activation *, thread));
	DECLARE("ACT_LOWER",    offsetof(struct thread_activation *, lower));
	DECLARE("ACT_MACT_PCB",offsetof(struct thread_activation *, mact.pcb));
	DECLARE("ACT_MACT_FPU",offsetof(struct thread_activation *, mact.FPU_pcb));
	DECLARE("ACT_MACT_FPUlvl",offsetof(struct thread_activation *, mact.FPU_lvl));
	DECLARE("ACT_MACT_FPUcpu",offsetof(struct thread_activation *, mact.FPU_cpu));
	DECLARE("ACT_MACT_VMX",offsetof(struct thread_activation *, mact.VMX_pcb));
	DECLARE("ACT_MACT_VMXlvl",offsetof(struct thread_activation *, mact.VMX_lvl));
	DECLARE("ACT_MACT_VMXcpu",offsetof(struct thread_activation *, mact.VMX_cpu));
	DECLARE("ACT_AST",     offsetof(struct thread_activation *, ast));
	DECLARE("ACT_VMMAP",   offsetof(struct thread_activation *, map));
	DECLARE("runningVM",	runningVM);
	DECLARE("runningVMbit",	runningVMbit);
	DECLARE("ACT_KLOADED",
		offsetof(struct thread_activation *, kernel_loaded));
	DECLARE("ACT_KLOADING",
		offsetof(struct thread_activation *, kernel_loading));
	DECLARE("ACT_MACH_EXC_PORT",
		offsetof(struct thread_activation *,
		exc_actions[EXC_MACH_SYSCALL].port));
	DECLARE("vmmCEntry",	offsetof(struct thread_activation *, mact.vmmCEntry));
	DECLARE("vmmControl",	offsetof(struct thread_activation *, mact.vmmControl));
#ifdef MACH_BSD
	DECLARE("CTHREAD_SELF",	offsetof(struct thread_activation *, mact.cthread_self));
#endif  

	/* Values from vmachmon.h */
	
	DECLARE("kVmmGetVersion", 		kVmmGetVersion);
	DECLARE("kVmmvGetFeatures",		kVmmvGetFeatures);
	DECLARE("kVmmInitContext", 		kVmmInitContext);
	DECLARE("kVmmTearDownContext", 	kVmmTearDownContext);
	DECLARE("kVmmTearDownAll", 		kVmmTearDownAll);
	DECLARE("kVmmMapPage", 			kVmmMapPage);
	DECLARE("kVmmGetPageMapping", 	kVmmGetPageMapping);
	DECLARE("kVmmUnmapPage", 		kVmmUnmapPage);
	DECLARE("kVmmUnmapAllPages", 	kVmmUnmapAllPages);
	DECLARE("kVmmGetPageDirtyFlag", kVmmGetPageDirtyFlag);
	DECLARE("kVmmGetFloatState",	kVmmGetFloatState);
	DECLARE("kVmmGetVectorState",	kVmmGetVectorState);
	DECLARE("kVmmSetTimer", 		kVmmSetTimer);
	DECLARE("kVmmExecuteVM", 		kVmmExecuteVM);

	DECLARE("kVmmReturnNull",		kVmmReturnNull);
	DECLARE("kVmmBogusContext",		kVmmBogusContext);
	DECLARE("kVmmReturnDataPageFault",	kVmmReturnDataPageFault);
	DECLARE("kVmmReturnInstrPageFault",	kVmmReturnInstrPageFault);
	DECLARE("kVmmReturnAlignmentFault",	kVmmReturnAlignmentFault);
	DECLARE("kVmmReturnProgramException",	kVmmReturnProgramException);
	DECLARE("kVmmReturnSystemCall",		kVmmReturnSystemCall);
	DECLARE("kVmmReturnTraceException",	kVmmReturnTraceException);
	
	DECLARE("vmmFlags",				offsetof(struct vmmCntrlEntry *, vmmFlags));
	DECLARE("vmmInUseb",			vmmInUseb);
	DECLARE("vmmInUse",				vmmInUse);
	DECLARE("vmmPmap",				offsetof(struct vmmCntrlEntry *, vmmPmap));
	DECLARE("vmmContextKern",		offsetof(struct vmmCntrlEntry *, vmmContextKern));
	DECLARE("vmmContextUser",		offsetof(struct vmmCntrlEntry *, vmmContextUser));
	DECLARE("vmmFPU_pcb",			offsetof(struct vmmCntrlEntry *, vmmFPU_pcb));
	DECLARE("vmmFPU_cpu",			offsetof(struct vmmCntrlEntry *, vmmFPU_cpu));
	DECLARE("vmmVMX_pcb",			offsetof(struct vmmCntrlEntry *, vmmVMX_pcb));
	DECLARE("vmmVMX_cpu",			offsetof(struct vmmCntrlEntry *, vmmVMX_cpu));
	DECLARE("vmmLastMap",			offsetof(struct vmmCntrlEntry *, vmmLastMap));
	DECLARE("vmmCEntrySize",		sizeof(struct vmmCntrlEntry));
	DECLARE("kVmmMaxContextsPerThread",		kVmmMaxContextsPerThread);
	
	DECLARE("interface_version",	offsetof(struct vmm_state_page_t *, interface_version));
	DECLARE("thread_index",			offsetof(struct vmm_state_page_t *, thread_index));
	DECLARE("vmmStat",				offsetof(struct vmm_state_page_t *, vmmStat));
	DECLARE("vmmCntrl",				offsetof(struct vmm_state_page_t *, vmmCntrl));
	DECLARE("return_code",			offsetof(struct vmm_state_page_t *, return_code));
	DECLARE("return_params",		offsetof(struct vmm_state_page_t *, return_params));
	DECLARE("vmm_proc_state",		offsetof(struct vmm_state_page_t *, vmm_proc_state));
	DECLARE("return_params",		offsetof(struct vmm_state_page_t *, return_params));
	DECLARE("vmmppcVRs",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcVRs));
	DECLARE("vmmppcVSCR",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcVSCR));
	DECLARE("vmmppcFPRs",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcFPRs));
	DECLARE("vmmppcFPSCR",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcFPSCR));
	DECLARE("vmmFloatCngd",			vmmFloatCngd);
	DECLARE("vmmFloatCngdb",		vmmFloatCngdb);
	DECLARE("vmmVectCngd",			vmmVectCngd);
	DECLARE("vmmVectCngdb",			vmmVectCngdb);
	DECLARE("vmmTimerPop",			vmmTimerPop);
	DECLARE("vmmTimerPopb",			vmmTimerPopb);
	DECLARE("vmmMapDone",			vmmMapDone);
	DECLARE("vmmMapDoneb",			vmmMapDoneb);
	DECLARE("vmmSpfSave",			vmmSpfSave);
	DECLARE("vmmSpfSaveb",			vmmSpfSaveb);
	DECLARE("vmmFloatLoad",			vmmFloatLoad);
	DECLARE("vmmFloatLoadb",		vmmFloatLoadb);
	DECLARE("vmmVectLoad",			vmmVectLoad);
	DECLARE("vmmVectLoadb",			vmmVectLoadb);
	DECLARE("vmmVectVRall",			vmmVectVRall);
	DECLARE("vmmVectVRallb",		vmmVectVRallb);
	DECLARE("vmmVectVAss",			vmmVectVAss);
	DECLARE("vmmVectVAssb",			vmmVectVAssb);

	/* values from kern/task.h */
	DECLARE("TASK_MACH_EXC_PORT",
		offsetof(struct task *, exc_actions[EXC_MACH_SYSCALL].port));
	DECLARE("TASK_SYSCALLS_MACH",
		offsetof(struct task *, syscalls_mach));

	/* values from vm/vm_map.h */
	DECLARE("VMMAP_PMAP",	offsetof(struct vm_map *, pmap));

	/* values from machine/pmap.h */
	DECLARE("PMAP_SPACE",	offsetof(struct pmap *, space));
	DECLARE("PMAP_BMAPS",	offsetof(struct pmap *, bmaps));
	DECLARE("PMAP_PMAPVR",	offsetof(struct pmap *, pmapvr));
	DECLARE("PMAP_VFLAGS",	offsetof(struct pmap *, vflags));
	DECLARE("PMAP_USAGE",	offsetof(struct pmap *, pmapUsage));
	DECLARE("PMAP_SEGS",	offsetof(struct pmap *, pmapSegs));
	DECLARE("PMAP_SIZE",	pmapSize);
	

	/* Constants from pmap.h */
	DECLARE("PPC_SID_KERNEL", PPC_SID_KERNEL);

	/* values for accessing mach_trap table */
	DECLARE("MACH_TRAP_OFFSET_POW2",	4);

	DECLARE("MACH_TRAP_ARGC",
		offsetof(mach_trap_t *, mach_trap_arg_count));
	DECLARE("MACH_TRAP_FUNCTION",
		offsetof(mach_trap_t *, mach_trap_function));

	DECLARE("HOST_SELF", offsetof(host_t, host_self));
	
	DECLARE("PPCcallmax", sizeof(PPCcalls));

	/* values from cpu_data.h */
	DECLARE("CPU_ACTIVE_THREAD", offsetof(cpu_data_t *, active_thread));
	DECLARE("CPU_PREEMPTION_LEVEL", offsetof(cpu_data_t *, preemption_level));
	DECLARE("CPU_SIMPLE_LOCK_COUNT",
		offsetof(cpu_data_t *, simple_lock_count));
	DECLARE("CPU_INTERRUPT_LEVEL",offsetof(cpu_data_t *, interrupt_level));

	/* Misc values used by assembler */
	DECLARE("AST_ALL", AST_ALL);
	DECLARE("AST_URGENT", AST_URGENT);

	/* Simple Lock structure */
	DECLARE("SLOCK_ILK",	offsetof(simple_lock_t, interlock));
#if	MACH_LDEBUG
	DECLARE("SLOCK_TYPE",	offsetof(simple_lock_t, lock_type));
	DECLARE("SLOCK_PC",	offsetof(simple_lock_t, debug.lock_pc));
	DECLARE("SLOCK_THREAD",	offsetof(simple_lock_t, debug.lock_thread));
	DECLARE("SLOCK_DURATIONH",offsetof(simple_lock_t, debug.duration[0]));
	DECLARE("SLOCK_DURATIONL",offsetof(simple_lock_t, debug.duration[1]));
	DECLARE("USLOCK_TAG",	USLOCK_TAG);
#endif	/* MACH_LDEBUG */

	/* Mutex structure */
	DECLARE("MUTEX_ILK",	offsetof(mutex_t *, interlock));
	DECLARE("MUTEX_LOCKED",	offsetof(mutex_t *, locked));
	DECLARE("MUTEX_WAITERS",offsetof(mutex_t *, waiters));
#if	MACH_LDEBUG
	DECLARE("MUTEX_TYPE",	offsetof(mutex_t *, type));
	DECLARE("MUTEX_PC",	offsetof(mutex_t *, pc));
	DECLARE("MUTEX_THREAD",	offsetof(mutex_t *, thread));
	DECLARE("MUTEX_TAG",	MUTEX_TAG);
#endif	/* MACH_LDEBUG */

#if	NCPUS > 1
	/* values from mp/PlugIn.h */
	
	DECLARE("MPSversionID",	offsetof(struct MPPlugInSpec *, versionID));
	DECLARE("MPSareaAddr",	offsetof(struct MPPlugInSpec *, areaAddr));
	DECLARE("MPSareaSize",	offsetof(struct MPPlugInSpec *, areaSize));
	DECLARE("MPSoffsetTableAddr", offsetof(struct MPPlugInSpec *, offsetTableAddr));
	DECLARE("MPSbaseAddr",	offsetof(struct MPPlugInSpec *, baseAddr));
	DECLARE("MPSdataArea",	offsetof(struct MPPlugInSpec *, dataArea));
	DECLARE("MPSCPUArea",	offsetof(struct MPPlugInSpec *, CPUArea));
	DECLARE("MPSSIGPhandler",	offsetof(struct MPPlugInSpec *, SIGPhandler));

	DECLARE("CSAstate",	offsetof(struct CPUStatusArea *, state));
	DECLARE("CSAregsAreValid", offsetof(struct CPUStatusArea *,
					    regsAreValid));
	DECLARE("CSAgpr",	offsetof(struct CPUStatusArea *, gpr));
	DECLARE("CSAfpr",	offsetof(struct CPUStatusArea *, fpr));
	DECLARE("CSAcr",	offsetof(struct CPUStatusArea *, cr));
	DECLARE("CSAfpscr",	offsetof(struct CPUStatusArea *, fpscr));
	DECLARE("CSAxer",	offsetof(struct CPUStatusArea *, xer));
	DECLARE("CSAlr",	offsetof(struct CPUStatusArea *, lr));
	DECLARE("CSActr",	offsetof(struct CPUStatusArea *, ctr));
	DECLARE("CSAtbu",	offsetof(struct CPUStatusArea *, tbu));
	DECLARE("CSAtbl",	offsetof(struct CPUStatusArea *, tbl));
	DECLARE("CSApvr",	offsetof(struct CPUStatusArea *, pvr));
	DECLARE("CSAibat",	offsetof(struct CPUStatusArea *, ibat));
	DECLARE("CSAdbat",	offsetof(struct CPUStatusArea *, dbat));
	DECLARE("CSAsdr1",	offsetof(struct CPUStatusArea *, sdr1));
	DECLARE("CSAsr",	offsetof(struct CPUStatusArea *, sr));
	DECLARE("CSAdar",	offsetof(struct CPUStatusArea *, dar));
	DECLARE("CSAdsisr",	offsetof(struct CPUStatusArea *, dsisr));
	DECLARE("CSAsprg",	offsetof(struct CPUStatusArea *, sprg));
	DECLARE("CSAsrr0",	offsetof(struct CPUStatusArea *, srr0));
	DECLARE("CSAsrr1",	offsetof(struct CPUStatusArea *, srr1));
	DECLARE("CSAdec",	offsetof(struct CPUStatusArea *, dec));
	DECLARE("CSAdabr",	offsetof(struct CPUStatusArea *, dabr));
	DECLARE("CSAiabr",	offsetof(struct CPUStatusArea *, iabr));
	DECLARE("CSAear",	offsetof(struct CPUStatusArea *, ear));
	DECLARE("CSAhid",	offsetof(struct CPUStatusArea *, hid));
	DECLARE("CSAmmcr",	offsetof(struct CPUStatusArea *, mmcr));
	DECLARE("CSApmc",	offsetof(struct CPUStatusArea *, pmc));
	DECLARE("CSApir",	offsetof(struct CPUStatusArea *, pir));
	DECLARE("CSAsda",	offsetof(struct CPUStatusArea *, sda));
	DECLARE("CSAsia",	offsetof(struct CPUStatusArea *, sia));
	DECLARE("CSAmq",	offsetof(struct CPUStatusArea *, mq));
	DECLARE("CSAmsr",	offsetof(struct CPUStatusArea *, msr));
	DECLARE("CSApc",	offsetof(struct CPUStatusArea *, pc));
	DECLARE("CSAsysregs",	offsetof(struct CPUStatusArea *, sysregs));
	DECLARE("CSAsize",	sizeof(struct CPUStatusArea));


	DECLARE("MPPICStat",	offsetof(struct MPPInterface *, MPPICStat));
	DECLARE("MPPICParm0",	offsetof(struct MPPInterface *, MPPICParm0));
	DECLARE("MPPICParm1",	offsetof(struct MPPInterface *, MPPICParm1));
	DECLARE("MPPICParm2",	offsetof(struct MPPInterface *, MPPICParm2));
	DECLARE("MPPICspare0",	offsetof(struct MPPInterface *, MPPICspare0));
	DECLARE("MPPICspare1",	offsetof(struct MPPInterface *, MPPICspare1));
	DECLARE("MPPICParm0BU",	offsetof(struct MPPInterface *, MPPICParm0BU));
	DECLARE("MPPICPriv",	offsetof(struct MPPInterface *, MPPICPriv));



#endif	/* NCPUS > 1 */
						 
	/* values from low_trace.h */
	DECLARE("LTR_cpu",	offsetof(struct LowTraceRecord *, LTR_cpu));
	DECLARE("LTR_excpt",	offsetof(struct LowTraceRecord *, LTR_excpt));
	DECLARE("LTR_timeHi",	offsetof(struct LowTraceRecord *, LTR_timeHi));
	DECLARE("LTR_timeLo",	offsetof(struct LowTraceRecord *, LTR_timeLo));
	DECLARE("LTR_cr",	offsetof(struct LowTraceRecord *, LTR_cr));
	DECLARE("LTR_srr0",	offsetof(struct LowTraceRecord *, LTR_srr0));
	DECLARE("LTR_srr1",	offsetof(struct LowTraceRecord *, LTR_srr1));
	DECLARE("LTR_dar",	offsetof(struct LowTraceRecord *, LTR_dar));
	DECLARE("LTR_save",	offsetof(struct LowTraceRecord *, LTR_save));
	DECLARE("LTR_lr",	offsetof(struct LowTraceRecord *, LTR_lr));
	DECLARE("LTR_ctr",	offsetof(struct LowTraceRecord *, LTR_ctr));
	DECLARE("LTR_r0",	offsetof(struct LowTraceRecord *, LTR_r0));
	DECLARE("LTR_r1",	offsetof(struct LowTraceRecord *, LTR_r1));
	DECLARE("LTR_r2",	offsetof(struct LowTraceRecord *, LTR_r2));
	DECLARE("LTR_r3",	offsetof(struct LowTraceRecord *, LTR_r3));
	DECLARE("LTR_r4",	offsetof(struct LowTraceRecord *, LTR_r4));
	DECLARE("LTR_r5",	offsetof(struct LowTraceRecord *, LTR_r5));
	DECLARE("LTR_size",	sizeof(struct LowTraceRecord));

/*	Values from pexpert.h */
	DECLARE("PECFIcpurate",	offsetof(struct clock_frequency_info_t *, cpu_clock_rate_hz));
	DECLARE("PECFIbusrate",	offsetof(struct clock_frequency_info_t *, bus_clock_rate_hz));

/*	Values from pmap_internals.h and mappings.h */
	DECLARE("mmnext",		offsetof(struct mapping *, next));
	DECLARE("mmhashnext",	offsetof(struct mapping *, hashnext));
	DECLARE("mmPTEhash",	offsetof(struct mapping *, PTEhash));
	DECLARE("mmPTEent",		offsetof(struct mapping *, PTEent));
	DECLARE("mmPTEv",		offsetof(struct mapping *, PTEv));
	DECLARE("mmPTEr",		offsetof(struct mapping *, PTEr));
	DECLARE("mmphysent",	offsetof(struct mapping *, physent));
	DECLARE("mmpmap",		offsetof(struct mapping *, pmap));
	
	DECLARE("bmnext",		offsetof(struct blokmap *, next));
	DECLARE("bmstart",		offsetof(struct blokmap *, start));
	DECLARE("bmend",		offsetof(struct blokmap *, end));
	DECLARE("bmPTEr",		offsetof(struct blokmap *, PTEr));
	DECLARE("bmspace",		offsetof(struct blokmap *, space));
	DECLARE("blkFlags",		offsetof(struct blokmap *, blkFlags));
	DECLARE("blkPerm",		blkPerm);
	DECLARE("blkPermbit",	blkPermbit);
	
	DECLARE("mbvrswap",		offsetof(struct mappingblok *, mapblokvrswap));
	DECLARE("mbfree",		offsetof(struct mappingblok *, mapblokfree));
	DECLARE("mapcsize",		sizeof(struct mappingctl));

	DECLARE("pephyslink",	offsetof(struct phys_entry *, phys_link));
	DECLARE("pepte1",		offsetof(struct phys_entry *, pte1));

	DECLARE("PCAlock",		offsetof(struct PCA *, PCAlock));
	DECLARE("PCAallo",		offsetof(struct PCA *, flgs.PCAallo));
	DECLARE("PCAfree",		offsetof(struct PCA *, flgs.PCAalflgs.PCAfree));
	DECLARE("PCAauto",		offsetof(struct PCA *, flgs.PCAalflgs.PCAauto));
	DECLARE("PCAslck",		offsetof(struct PCA *, flgs.PCAalflgs.PCAslck));
	DECLARE("PCAsteal",		offsetof(struct PCA *, flgs.PCAalflgs.PCAsteal));
	DECLARE("PCAgas",		offsetof(struct PCA *, PCAgas));
	DECLARE("PCAhash",		offsetof(struct PCA *, PCAhash));

	DECLARE("SVlock",		offsetof(struct Saveanchor *, savelock));
	DECLARE("SVcount",		offsetof(struct Saveanchor *, savecount));
	DECLARE("SVinuse",		offsetof(struct Saveanchor *, saveinuse));
	DECLARE("SVmin",		offsetof(struct Saveanchor *, savemin));
	DECLARE("SVneghyst",	offsetof(struct Saveanchor *, saveneghyst));
	DECLARE("SVtarget",		offsetof(struct Saveanchor *, savetarget));
	DECLARE("SVposhyst",	offsetof(struct Saveanchor *, saveposhyst));
	DECLARE("SVfree",		offsetof(struct Saveanchor *, savefree));
	DECLARE("SVsize",		sizeof(struct Saveanchor));

#if 1
	DECLARE("GDsave",		offsetof(struct GDWorkArea *, GDsave));
	DECLARE("GDfp0",		offsetof(struct GDWorkArea *, GDfp0));
	DECLARE("GDfp1",		offsetof(struct GDWorkArea *, GDfp1));
	DECLARE("GDfp2",		offsetof(struct GDWorkArea *, GDfp2));
	DECLARE("GDfp3",		offsetof(struct GDWorkArea *, GDfp3));
	DECLARE("GDtop",		offsetof(struct GDWorkArea *, GDtop));
	DECLARE("GDleft",		offsetof(struct GDWorkArea *, GDleft));
	DECLARE("GDtopleft",	offsetof(struct GDWorkArea *, GDtopleft));
	DECLARE("GDrowbytes",	offsetof(struct GDWorkArea *, GDrowbytes));
	DECLARE("GDrowchar",	offsetof(struct GDWorkArea *, GDrowchar));
	DECLARE("GDdepth",		offsetof(struct GDWorkArea *, GDdepth));
	DECLARE("GDcollgn",		offsetof(struct GDWorkArea *, GDcollgn));
	DECLARE("GDready",		offsetof(struct GDWorkArea *, GDready));
	DECLARE("GDrowbuf1",	offsetof(struct GDWorkArea *, GDrowbuf1));
	DECLARE("GDrowbuf2",	offsetof(struct GDWorkArea *, GDrowbuf2));
#endif

	DECLARE("dgLock",		offsetof(struct diagWork *, dgLock));
	DECLARE("dgFlags",		offsetof(struct diagWork *, dgFlags));
	DECLARE("dgMisc0",		offsetof(struct diagWork *, dgMisc0));
	DECLARE("enaExpTrace",	enaExpTrace);
	DECLARE("enaExpTraceb",	enaExpTraceb);
	DECLARE("enaUsrFCall",	enaUsrFCall);
	DECLARE("enaUsrFCallb",	enaUsrFCallb);
	DECLARE("enaUsrPhyMp",	enaUsrPhyMp);
	DECLARE("enaUsrPhyMpb",	enaUsrPhyMpb);
	DECLARE("enaDiagSCs",	enaDiagSCs);
	DECLARE("enaDiagSCsb",	enaDiagSCsb);
	DECLARE("disLkType",	disLkType);
	DECLARE("disLktypeb",	disLktypeb);
	DECLARE("disLkThread",	disLkThread);
	DECLARE("disLkThreadb",	disLkThreadb);
	DECLARE("disLkNmSimp",	disLkNmSimp);
	DECLARE("disLkNmSimpb",	disLkNmSimpb);
	DECLARE("disLkMyLck",	disLkMyLck);
	DECLARE("disLkMyLckb",	disLkMyLckb);
	DECLARE("dgMisc1",		offsetof(struct diagWork *, dgMisc1));
	DECLARE("dgMisc2",		offsetof(struct diagWork *, dgMisc2));
	DECLARE("dgMisc3",		offsetof(struct diagWork *, dgMisc3));
	DECLARE("dgMisc4",		offsetof(struct diagWork *, dgMisc4));
	DECLARE("dgMisc5",		offsetof(struct diagWork *, dgMisc5));

	DECLARE("traceMask",	offsetof(struct traceWork *, traceMask));
	DECLARE("traceCurr",	offsetof(struct traceWork *, traceCurr));
	DECLARE("traceStart",	offsetof(struct traceWork *, traceStart));
	DECLARE("traceEnd",		offsetof(struct traceWork *, traceEnd));
	DECLARE("traceMsnd",	offsetof(struct traceWork *, traceMsnd));

	DECLARE("SACsize",		sizeof(struct savectl));				
	DECLARE("SACspot",		4096-sizeof(struct savectl));		
	DECLARE("SACnext",		offsetof(struct savectl *, sac_next)+4096-sizeof(struct savectl));
	DECLARE("SACvrswap",	offsetof(struct savectl *, sac_vrswap)+4096-sizeof(struct savectl));
	DECLARE("SACalloc",		offsetof(struct savectl *, sac_alloc)+4096-sizeof(struct savectl));
	DECLARE("SACflags",		offsetof(struct savectl *, sac_flags)+4096-sizeof(struct savectl));

	DECLARE("SAVprev",		offsetof(struct savearea *, save_prev));
	DECLARE("SAVprefp",		offsetof(struct savearea *, save_prev_float));
	DECLARE("SAVprevec",	offsetof(struct savearea *, save_prev_vector));
	DECLARE("SAVphys",		offsetof(struct savearea *, save_phys));
	DECLARE("SAVqfret",		offsetof(struct savearea *, save_qfret));
	DECLARE("SAVact",		offsetof(struct savearea *, save_act));
	DECLARE("SAVflags",		offsetof(struct savearea *, save_flags));
	DECLARE("SAVlvlfp",		offsetof(struct savearea *, save_level_fp));
	DECLARE("SAVlvlvec",	offsetof(struct savearea *, save_level_vec));
	DECLARE("SAVsize",		sizeof(struct savearea));

	DECLARE("savesrr0",		offsetof(struct savearea *, save_srr0));
	DECLARE("savesrr1",		offsetof(struct savearea *, save_srr1));
	DECLARE("savecr",		offsetof(struct savearea *, save_cr));
	DECLARE("savexer",		offsetof(struct savearea *, save_xer));
	DECLARE("savelr",		offsetof(struct savearea *, save_lr));
	DECLARE("savectr",		offsetof(struct savearea *, save_ctr));
	DECLARE("savemq",		offsetof(struct savearea *, save_mq));
	DECLARE("savecopyin",	offsetof(struct savearea *, save_sr_copyin));
	DECLARE("savedar",		offsetof(struct savearea *, save_dar));
	DECLARE("savedsisr",	offsetof(struct savearea *, save_dsisr));
	DECLARE("saveexception",	offsetof(struct savearea *, save_exception));
	DECLARE("savexfpscrpad",	offsetof(struct savearea *, save_xfpscrpad));
	DECLARE("savexfpscr",	offsetof(struct savearea *, save_xfpscr));
	DECLARE("savevrsave",	offsetof(struct savearea *, save_vrsave));	

	DECLARE("saver0",		offsetof(struct savearea *, save_r0));
	DECLARE("saver1",		offsetof(struct savearea *, save_r1));
	DECLARE("saver2",		offsetof(struct savearea *, save_r2));
	DECLARE("saver3",		offsetof(struct savearea *, save_r3));
	DECLARE("saver4",		offsetof(struct savearea *, save_r4));
	DECLARE("saver5",		offsetof(struct savearea *, save_r5));
	DECLARE("saver6",		offsetof(struct savearea *, save_r6));
	DECLARE("saver7",		offsetof(struct savearea *, save_r7));
	DECLARE("saver8",		offsetof(struct savearea *, save_r8));
	DECLARE("saver9",		offsetof(struct savearea *, save_r9));
	DECLARE("saver10",		offsetof(struct savearea *, save_r10));
	DECLARE("saver11",		offsetof(struct savearea *, save_r11));
	DECLARE("saver12",		offsetof(struct savearea *, save_r12));
	DECLARE("saver13",		offsetof(struct savearea *, save_r13));
	DECLARE("saver14",		offsetof(struct savearea *, save_r14));
	DECLARE("saver15",		offsetof(struct savearea *, save_r15));
	DECLARE("saver16",		offsetof(struct savearea *, save_r16));
	DECLARE("saver17",		offsetof(struct savearea *, save_r17));
	DECLARE("saver18",		offsetof(struct savearea *, save_r18));
	DECLARE("saver19",		offsetof(struct savearea *, save_r19));
	DECLARE("saver20",		offsetof(struct savearea *, save_r20));
	DECLARE("saver21",		offsetof(struct savearea *, save_r21));
	DECLARE("saver22",		offsetof(struct savearea *, save_r22));
	DECLARE("saver23",		offsetof(struct savearea *, save_r23));
	DECLARE("saver24",		offsetof(struct savearea *, save_r24));
	DECLARE("saver25",		offsetof(struct savearea *, save_r25));
	DECLARE("saver26",		offsetof(struct savearea *, save_r26));
	DECLARE("saver27",		offsetof(struct savearea *, save_r27));
	DECLARE("saver28",		offsetof(struct savearea *, save_r28));
	DECLARE("saver29",		offsetof(struct savearea *, save_r29));
	DECLARE("saver30",		offsetof(struct savearea *, save_r30));
	DECLARE("saver31",		offsetof(struct savearea *, save_r31));

	DECLARE("savefp0",		offsetof(struct savearea *, save_fp0));
	DECLARE("savefp1",		offsetof(struct savearea *, save_fp1));
	DECLARE("savefp2",		offsetof(struct savearea *, save_fp2));
	DECLARE("savefp3",		offsetof(struct savearea *, save_fp3));
	DECLARE("savefp4",		offsetof(struct savearea *, save_fp4));
	DECLARE("savefp5",		offsetof(struct savearea *, save_fp5));
	DECLARE("savefp6",		offsetof(struct savearea *, save_fp6));
	DECLARE("savefp7",		offsetof(struct savearea *, save_fp7));
	DECLARE("savefp8",		offsetof(struct savearea *, save_fp8));
	DECLARE("savefp9",		offsetof(struct savearea *, save_fp9));
	DECLARE("savefp10",		offsetof(struct savearea *, save_fp10));
	DECLARE("savefp11",		offsetof(struct savearea *, save_fp11));
	DECLARE("savefp12",		offsetof(struct savearea *, save_fp12));
	DECLARE("savefp13",		offsetof(struct savearea *, save_fp13));
	DECLARE("savefp14",		offsetof(struct savearea *, save_fp14));
	DECLARE("savefp15",		offsetof(struct savearea *, save_fp15));
	DECLARE("savefp16",		offsetof(struct savearea *, save_fp16));
	DECLARE("savefp17",		offsetof(struct savearea *, save_fp17));
	DECLARE("savefp18",		offsetof(struct savearea *, save_fp18));
	DECLARE("savefp19",		offsetof(struct savearea *, save_fp19));
	DECLARE("savefp20",		offsetof(struct savearea *, save_fp20));
	DECLARE("savefp21",		offsetof(struct savearea *, save_fp21));
	DECLARE("savefp22",		offsetof(struct savearea *, save_fp22));
	DECLARE("savefp23",		offsetof(struct savearea *, save_fp23));
	DECLARE("savefp24",		offsetof(struct savearea *, save_fp24));
	DECLARE("savefp25",		offsetof(struct savearea *, save_fp25));
	DECLARE("savefp26",		offsetof(struct savearea *, save_fp26));
	DECLARE("savefp27",		offsetof(struct savearea *, save_fp27));
	DECLARE("savefp28",		offsetof(struct savearea *, save_fp28));
	DECLARE("savefp29",		offsetof(struct savearea *, save_fp29));
	DECLARE("savefp30",		offsetof(struct savearea *, save_fp30));
	DECLARE("savefp31",		offsetof(struct savearea *, save_fp31));
	DECLARE("savefpscrpad",	offsetof(struct savearea *, save_fpscr_pad));
	DECLARE("savefpscr",	offsetof(struct savearea *, save_fpscr));

	DECLARE("savesr0",		offsetof(struct savearea *, save_sr0));
	DECLARE("savesr1",		offsetof(struct savearea *, save_sr1));
	DECLARE("savesr2",		offsetof(struct savearea *, save_sr2));
	DECLARE("savesr3",		offsetof(struct savearea *, save_sr3));
	DECLARE("savesr4",		offsetof(struct savearea *, save_sr4));
	DECLARE("savesr5",		offsetof(struct savearea *, save_sr5));
	DECLARE("savesr6",		offsetof(struct savearea *, save_sr6));
	DECLARE("savesr7",		offsetof(struct savearea *, save_sr7));
	DECLARE("savesr8",		offsetof(struct savearea *, save_sr8));
	DECLARE("savesr9",		offsetof(struct savearea *, save_sr9));
	DECLARE("savesr10",		offsetof(struct savearea *, save_sr10));
	DECLARE("savesr11",		offsetof(struct savearea *, save_sr11));
	DECLARE("savesr12",		offsetof(struct savearea *, save_sr12));
	DECLARE("savesr13",		offsetof(struct savearea *, save_sr13));
	DECLARE("savesr14",		offsetof(struct savearea *, save_sr14));
	DECLARE("savesr15",		offsetof(struct savearea *, save_sr15));
	
	DECLARE("savevr0",		offsetof(struct savearea *, save_vr0));
	DECLARE("savevr1",		offsetof(struct savearea *, save_vr1));
	DECLARE("savevr2",		offsetof(struct savearea *, save_vr2));
	DECLARE("savevr3",		offsetof(struct savearea *, save_vr3));
	DECLARE("savevr4",		offsetof(struct savearea *, save_vr4));
	DECLARE("savevr5",		offsetof(struct savearea *, save_vr5));
	DECLARE("savevr6",		offsetof(struct savearea *, save_vr6));
	DECLARE("savevr7",		offsetof(struct savearea *, save_vr7));
	DECLARE("savevr8",		offsetof(struct savearea *, save_vr8));
	DECLARE("savevr9",		offsetof(struct savearea *, save_vr9));
	DECLARE("savevr10",		offsetof(struct savearea *, save_vr10));
	DECLARE("savevr11",		offsetof(struct savearea *, save_vr11));
	DECLARE("savevr12",		offsetof(struct savearea *, save_vr12));
	DECLARE("savevr13",		offsetof(struct savearea *, save_vr13));
	DECLARE("savevr14",		offsetof(struct savearea *, save_vr14));
	DECLARE("savevr15",		offsetof(struct savearea *, save_vr15));
	DECLARE("savevr16",		offsetof(struct savearea *, save_vr16));
	DECLARE("savevr17",		offsetof(struct savearea *, save_vr17));
	DECLARE("savevr18",		offsetof(struct savearea *, save_vr18));
	DECLARE("savevr19",		offsetof(struct savearea *, save_vr19));
	DECLARE("savevr20",		offsetof(struct savearea *, save_vr20));
	DECLARE("savevr21",		offsetof(struct savearea *, save_vr21));
	DECLARE("savevr22",		offsetof(struct savearea *, save_vr22));
	DECLARE("savevr23",		offsetof(struct savearea *, save_vr23));
	DECLARE("savevr24",		offsetof(struct savearea *, save_vr24));
	DECLARE("savevr25",		offsetof(struct savearea *, save_vr25));
	DECLARE("savevr26",		offsetof(struct savearea *, save_vr26));
	DECLARE("savevr27",		offsetof(struct savearea *, save_vr27));
	DECLARE("savevr28",		offsetof(struct savearea *, save_vr28));
	DECLARE("savevr29",		offsetof(struct savearea *, save_vr29));
	DECLARE("savevr30",		offsetof(struct savearea *, save_vr30));
	DECLARE("savevr31",		offsetof(struct savearea *, save_vr31));
	DECLARE("savevscr",		offsetof(struct savearea *, save_vscr));	
	DECLARE("savevrvalid",	offsetof(struct savearea *, save_vrvalid));	

	/* PseudoKernel Exception Descriptor info */
	DECLARE("BEDA_SRR0",	offsetof(BEDA_t *, srr0));
	DECLARE("BEDA_SRR1",	offsetof(BEDA_t *, srr1));
	DECLARE("BEDA_SPRG0",	offsetof(BEDA_t *, sprg0));
	DECLARE("BEDA_SPRG1",	offsetof(BEDA_t *, sprg1));

	/* PseudoKernel Interrupt Control Word */
	DECLARE("BTTD_INTCONTROLWORD",	offsetof(BTTD_t *, InterruptControlWord));

	/* New state when exiting the pseudokernel */
	DECLARE("BTTD_NEWEXITSTATE",	offsetof(BTTD_t *, NewExitState));

	/* PseudoKernel Test/Post Interrupt */
	DECLARE("BTTD_TESTINTMASK",	offsetof(BTTD_t *, testIntMask));
	DECLARE("BTTD_POSTINTMASK",	offsetof(BTTD_t *, postIntMask));

	/* PseudoKernel Vectors */
	DECLARE("BTTD_TRAP_VECTOR",			offsetof(BTTD_t *, TrapVector));
	DECLARE("BTTD_SYSCALL_VECTOR",		offsetof(BTTD_t *, SysCallVector));
	DECLARE("BTTD_INTERRUPT_VECTOR",	offsetof(BTTD_t *, InterruptVector));
	DECLARE("BTTD_PENDINGINT_VECTOR",	offsetof(BTTD_t *, PendingIntVector));
	
	/* PseudoKernel Bits, Masks and misc */
	DECLARE("SYSCONTEXTSTATE",		kInSystemContext);
	DECLARE("PSEUDOKERNELSTATE",	kInPseudoKernel);
	DECLARE("INTSTATEMASK_B",		12);
	DECLARE("INTSTATEMASK_E",		15);
	DECLARE("INTCR2MASK_B",			8);
	DECLARE("INTCR2MASK_E",			11);
	DECLARE("INTBACKUPCR2MASK_B",	28);
	DECLARE("INTBACKUPCR2MASK_E",	31);
	DECLARE("INTCR2TOBACKUPSHIFT",	kCR2ToBackupShift);
	DECLARE("BB_MAX_TRAP",			bbMaxTrap);
	DECLARE("BB_RFI_TRAP",			bbRFITrap);

	/* Various hackery */
	DECLARE("procState",		offsetof(struct processor *, state));
	
	DECLARE("CPU_SUBTYPE_POWERPC_ALL",		CPU_SUBTYPE_POWERPC_ALL);
	DECLARE("CPU_SUBTYPE_POWERPC_601",		CPU_SUBTYPE_POWERPC_601);
	DECLARE("CPU_SUBTYPE_POWERPC_602",		CPU_SUBTYPE_POWERPC_602);
	DECLARE("CPU_SUBTYPE_POWERPC_603",		CPU_SUBTYPE_POWERPC_603);
	DECLARE("CPU_SUBTYPE_POWERPC_603e",		CPU_SUBTYPE_POWERPC_603e);
	DECLARE("CPU_SUBTYPE_POWERPC_603ev",	CPU_SUBTYPE_POWERPC_603ev);
	DECLARE("CPU_SUBTYPE_POWERPC_604",		CPU_SUBTYPE_POWERPC_604);
	DECLARE("CPU_SUBTYPE_POWERPC_604e",		CPU_SUBTYPE_POWERPC_604e);
	DECLARE("CPU_SUBTYPE_POWERPC_620",		CPU_SUBTYPE_POWERPC_620);
	DECLARE("CPU_SUBTYPE_POWERPC_750",		CPU_SUBTYPE_POWERPC_750);
	DECLARE("CPU_SUBTYPE_POWERPC_7400",		CPU_SUBTYPE_POWERPC_7400);
	DECLARE("CPU_SUBTYPE_POWERPC_7450",		CPU_SUBTYPE_POWERPC_7450);

	
	return(0);  /* For ANSI C :-) */



}
