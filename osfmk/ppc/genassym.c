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
#include <ppc/mem.h>

#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE)0)->MEMBER)

#define DECLARE(SYM,VAL) \
	__asm("#DEFINITION##define\t" SYM "\t%0" : : "n" ((u_int)(VAL)))

int main(int argc, char *argv[])
{
	/* Process Control Block */

	DECLARE("ACT_MACT_KSP",	offsetof(struct thread_activation *, mact.ksp));
	DECLARE("ACT_MACT_BEDA", offsetof(struct thread_activation *, mact.bbDescAddr));
	DECLARE("ACT_MACT_BTS",	offsetof(struct thread_activation *, mact.bbTableStart));
	DECLARE("ACT_MACT_BTE",	offsetof(struct thread_activation *, mact.bbTaskEnv));
	DECLARE("ACT_MACT_SPF",	offsetof(struct thread_activation *, mact.specFlags));
	DECLARE("qactTimer",	offsetof(struct thread_activation *, mact.qactTimer));
	
	DECLARE("floatUsed",	floatUsed);
	DECLARE("vectorUsed",	vectorUsed);
	DECLARE("runningVM",	runningVM);
	DECLARE("runningVMbit",	runningVMbit);
	DECLARE("floatCng",		floatCng);
	DECLARE("floatCngbit",	floatCngbit);
	DECLARE("vectorCng",	vectorCng);
	DECLARE("vectorCngbit",	vectorCngbit);
	DECLARE("userProtKey",	userProtKey);
	DECLARE("userProtKeybit",	userProtKeybit);
	DECLARE("trapUnalign",	trapUnalign);
	DECLARE("trapUnalignbit",	trapUnalignbit);
	DECLARE("notifyUnalign",	notifyUnalign);
	DECLARE("notifyUnalignbit",	notifyUnalignbit);

	DECLARE("bbThread",		bbThread);
	DECLARE("bbThreadbit",	bbThreadbit);
	DECLARE("bbNoMachSCbit",bbNoMachSCbit);
	DECLARE("bbPreemptive",	bbPreemptive);
	DECLARE("bbPreemptivebit",	bbPreemptivebit);

	DECLARE("fvChkb",		fvChkb);
	DECLARE("fvChk",		fvChk);
	DECLARE("FamVMena",		FamVMena);
	DECLARE("FamVMenabit",		FamVMenabit);
	DECLARE("FamVMmode",		FamVMmode);
	DECLARE("FamVMmodebit",		FamVMmodebit);

	/* Per Proc info structure */
	DECLARE("PP_CPU_NUMBER",		offsetof(struct per_proc_info *, cpu_number));
	DECLARE("PP_CPU_FLAGS",			offsetof(struct per_proc_info *, cpu_flags));
	DECLARE("PP_ISTACKPTR",			offsetof(struct per_proc_info *, istackptr));
	DECLARE("PP_INTSTACK_TOP_SS",	offsetof(struct per_proc_info *, intstack_top_ss));
	DECLARE("PP_DEBSTACKPTR",		offsetof(struct per_proc_info *, debstackptr));
	DECLARE("PP_DEBSTACK_TOP_SS",	offsetof(struct per_proc_info *, debstack_top_ss));
	DECLARE("PP_TEMPWORK1",			offsetof(struct per_proc_info *, tempwork1));
	DECLARE("PP_USERSPACE",			offsetof(struct per_proc_info *, userspace));
	DECLARE("PP_USERPMAP",			offsetof(struct per_proc_info *, userpmap));
	DECLARE("PP_LASTPMAP",			offsetof(struct per_proc_info *, Lastpmap));
	DECLARE("FPUowner",				offsetof(struct per_proc_info *, FPU_owner));
	DECLARE("VMXowner",				offsetof(struct per_proc_info *, VMX_owner));

	DECLARE("PP_SAVE_EXCEPTION_TYPE", offsetof(struct per_proc_info *, save_exception_type));
	DECLARE("PP_ACTIVE_KLOADED", 	offsetof(struct per_proc_info *, active_kloaded));
	DECLARE("PP_ACTIVE_STACKS", 	offsetof(struct per_proc_info *, active_stacks));
	DECLARE("PP_NEED_AST", 			offsetof(struct per_proc_info *, need_ast));
	DECLARE("quickfret", 			offsetof(struct per_proc_info *, quickfret));
	DECLARE("lclfree", 				offsetof(struct per_proc_info *, lclfree));
	DECLARE("lclfreecnt",			offsetof(struct per_proc_info *, lclfreecnt));
	DECLARE("PP_INTS_ENABLED", 		offsetof(struct per_proc_info *, interrupts_enabled));
	DECLARE("UAW", 					offsetof(struct per_proc_info *, Uassist));
	DECLARE("VMMareaPhys", 			offsetof(struct per_proc_info *, VMMareaPhys));
	DECLARE("FAMintercept", 		offsetof(struct per_proc_info *, FAMintercept));
	DECLARE("next_savearea", 		offsetof(struct per_proc_info *, next_savearea));
	DECLARE("PP_ACTIVE_THREAD", 	offsetof(struct per_proc_info *, pp_active_thread));
	DECLARE("PP_PREEMPT_CNT", 		offsetof(struct per_proc_info *, pp_preemption_count));
	DECLARE("PP_SIMPLE_LOCK_CNT",	offsetof(struct per_proc_info *, pp_simple_lock_count));
	DECLARE("PP_INTERRUPT_LVL",		offsetof(struct per_proc_info *, pp_interrupt_level));
	DECLARE("ppbbTaskEnv", 			offsetof(struct per_proc_info *, ppbbTaskEnv));
	DECLARE("liveVRS", 				offsetof(struct per_proc_info *, liveVRSave));
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
	DECLARE("pfWillNap",			pfWillNap);
	DECLARE("pfWillNapb",			pfWillNapb);
	DECLARE("pfNoMSRir",			pfNoMSRir);
	DECLARE("pfNoMSRirb",			pfNoMSRirb);
	DECLARE("pfNoL2PFNap",				pfNoL2PFNap);
	DECLARE("pfNoL2PFNapb",				pfNoL2PFNapb);
	DECLARE("pfSlowNap",				pfSlowNap);
	DECLARE("pfSlowNapb",				pfSlowNapb);
	DECLARE("pfNoMuMMCK",				pfNoMuMMCK);
	DECLARE("pfNoMuMMCKb",				pfNoMuMMCKb);
	DECLARE("pfLClck",				pfLClck);
	DECLARE("pfLClckb",				pfLClckb);
	DECLARE("pfL3pdet",				pfL3pdet);
	DECLARE("pfL3pdetb",			pfL3pdetb);
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
	DECLARE("pfICTRL", 				offsetof(struct per_proc_info *, pf.pfICTRL));
	DECLARE("pfLDSTCR", 			offsetof(struct per_proc_info *, pf.pfLDSTCR));
	DECLARE("pfLDSTDB", 			offsetof(struct per_proc_info *, pf.pfLDSTDB));
	DECLARE("pfl2crOriginal", 		offsetof(struct per_proc_info *, pf.l2crOriginal));
	DECLARE("pfl3crOriginal", 		offsetof(struct per_proc_info *, pf.l3crOriginal));
	DECLARE("pfBootConfig",			offsetof(struct per_proc_info *, pf.pfBootConfig));
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
	DECLARE("patcharea", 			offsetof(struct per_proc_info *, patcharea));

	DECLARE("RESETHANDLER_TYPE", 	offsetof(struct resethandler *, type));
	DECLARE("RESETHANDLER_CALL", 	offsetof(struct resethandler *, call_paddr));
	DECLARE("RESETHANDLER_ARG", 	offsetof(struct resethandler *, arg__paddr));

	/* we want offset from
	 * bottom of kernel stack, not offset into structure
	 */
#define IKSBASE (u_int)STACK_IKS(0)

	/* values from kern/thread.h */
	DECLARE("THREAD_TOP_ACT",		offsetof(struct thread_shuttle *, top_act));
	DECLARE("THREAD_KERNEL_STACK",	offsetof(struct thread_shuttle *, kernel_stack));
	DECLARE("THREAD_CONTINUATION",	offsetof(struct thread_shuttle *, continuation));
	DECLARE("THREAD_RECOVER",		offsetof(struct thread_shuttle *, recover));
	DECLARE("THREAD_FUNNEL_LOCK",
			offsetof(struct thread_shuttle *, funnel_lock));
	DECLARE("THREAD_FUNNEL_STATE",
			offsetof(struct thread_shuttle *, funnel_state));
	DECLARE("LOCK_FNL_MUTEX",
			offsetof(struct funnel_lock *, fnl_mutex));
#if	MACH_LDEBUG
	DECLARE("THREAD_MUTEX_COUNT",	offsetof(struct thread_shuttle *, mutex_count));
#endif	/* MACH_LDEBUG */
	DECLARE("THREAD_PSET",			offsetof(struct thread_shuttle *, processor_set));
	DECLARE("THREAD_LINKS",			offsetof(struct thread_shuttle *, links));
	DECLARE("THREAD_PSTHRN",		offsetof(struct thread_shuttle *, pset_threads.next));

	/* values from kern/thread_act.h */
	DECLARE("ACT_TASK",				offsetof(struct thread_activation *, task));
	DECLARE("ACT_THREAD",			offsetof(struct thread_activation *, thread));
	DECLARE("ACT_LOWER",			offsetof(struct thread_activation *, lower));
	DECLARE("ACT_MACT_PCB",			offsetof(struct thread_activation *, mact.pcb));
	DECLARE("ACT_AST",				offsetof(struct thread_activation *, ast));
	DECLARE("ACT_VMMAP",			offsetof(struct thread_activation *, map));
	DECLARE("ACT_KLOADED",			offsetof(struct thread_activation *, kernel_loaded));
	DECLARE("ACT_KLOADING",			offsetof(struct thread_activation *, kernel_loading));
	DECLARE("vmmCEntry",			offsetof(struct thread_activation *, mact.vmmCEntry));
	DECLARE("vmmControl",			offsetof(struct thread_activation *, mact.vmmControl));
	DECLARE("curctx",				offsetof(struct thread_activation *, mact.curctx));
	DECLARE("deferctx",				offsetof(struct thread_activation *, mact.deferctx));
	DECLARE("facctx",				offsetof(struct thread_activation *, mact.facctx));
#ifdef MACH_BSD
	DECLARE("CTHREAD_SELF",			offsetof(struct thread_activation *, mact.cthread_self));
#endif  

	DECLARE("FPUsave",				offsetof(struct facility_context *,FPUsave));
	DECLARE("FPUlevel",				offsetof(struct facility_context *,FPUlevel));
	DECLARE("FPUcpu",				offsetof(struct facility_context *,FPUcpu));
	DECLARE("VMXsave",				offsetof(struct facility_context *,VMXsave));
	DECLARE("VMXlevel",				offsetof(struct facility_context *,VMXlevel));
	DECLARE("VMXcpu",				offsetof(struct facility_context *,VMXcpu));
	DECLARE("facAct",				offsetof(struct facility_context *,facAct));

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
	DECLARE("kVmmProtectPage", 		kVmmProtectPage);

	DECLARE("kvmmExitToHost",		kvmmExitToHost);
	DECLARE("kvmmResumeGuest",		kvmmResumeGuest);
	DECLARE("kvmmGetGuestRegister",	kvmmGetGuestRegister);
	DECLARE("kvmmSetGuestRegister",	kvmmSetGuestRegister);

	DECLARE("kVmmReturnNull",		kVmmReturnNull);
	DECLARE("kVmmStopped",			kVmmStopped);
	DECLARE("kVmmBogusContext",		kVmmBogusContext);
	DECLARE("kVmmReturnDataPageFault",	kVmmReturnDataPageFault);
	DECLARE("kVmmReturnInstrPageFault",	kVmmReturnInstrPageFault);
	DECLARE("kVmmReturnAlignmentFault",	kVmmReturnAlignmentFault);
	DECLARE("kVmmReturnProgramException",	kVmmReturnProgramException);
	DECLARE("kVmmReturnSystemCall",		kVmmReturnSystemCall);
	DECLARE("kVmmReturnTraceException",	kVmmReturnTraceException);

	DECLARE("kVmmProtXtnd",			kVmmProtXtnd);
	DECLARE("kVmmProtNARW",			kVmmProtNARW);
	DECLARE("kVmmProtRORW",			kVmmProtRORW);
	DECLARE("kVmmProtRWRW",			kVmmProtRWRW);
	DECLARE("kVmmProtRORO",			kVmmProtRORO);
	
	DECLARE("vmmFlags",				offsetof(struct vmmCntrlEntry *, vmmFlags));
	DECLARE("vmmInUseb",			vmmInUseb);
	DECLARE("vmmInUse",				vmmInUse);
	DECLARE("vmmPmap",				offsetof(struct vmmCntrlEntry *, vmmPmap));
	DECLARE("vmmContextKern",		offsetof(struct vmmCntrlEntry *, vmmContextKern));
	DECLARE("vmmContextPhys",		offsetof(struct vmmCntrlEntry *, vmmContextPhys));
	DECLARE("vmmContextUser",		offsetof(struct vmmCntrlEntry *, vmmContextUser));
	DECLARE("vmmFacCtx",			offsetof(struct vmmCntrlEntry *, vmmFacCtx));
	DECLARE("vmmLastMap",			offsetof(struct vmmCntrlEntry *, vmmLastMap));
	DECLARE("vmmFAMintercept",		offsetof(struct vmmCntrlEntry *, vmmFAMintercept));
	DECLARE("vmmCEntrySize",		sizeof(struct vmmCntrlEntry));
	DECLARE("kVmmMaxContextsPerThread",		kVmmMaxContextsPerThread);
	
	DECLARE("interface_version",	offsetof(struct vmm_state_page_t *, interface_version));
	DECLARE("thread_index",			offsetof(struct vmm_state_page_t *, thread_index));
	DECLARE("vmmStat",				offsetof(struct vmm_state_page_t *, vmmStat));
	DECLARE("vmmCntrl",				offsetof(struct vmm_state_page_t *, vmmCntrl));
	DECLARE("return_code",			offsetof(struct vmm_state_page_t *, return_code));
	DECLARE("return_params",		offsetof(struct vmm_state_page_t *, return_params));
	DECLARE("vmm_proc_state",		offsetof(struct vmm_state_page_t *, vmm_proc_state));
	DECLARE("vmmppcVRs",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcVRs));
	DECLARE("vmmppcVSCR",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcVSCR));
	DECLARE("vmmppcVSCRshadow",		offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcVSCRshadow));
	DECLARE("vmmppcFPRs",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcFPRs));
	DECLARE("vmmppcFPSCR",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcFPSCR));
	DECLARE("vmmppcFPSCRshadow",	offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcFPSCRshadow));

	DECLARE("vmmppcpc",				offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcPC));
	DECLARE("vmmppcmsr",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcMSR));
	DECLARE("vmmppcr0",				offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x00));
	DECLARE("vmmppcr1",				offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x04));
	DECLARE("vmmppcr2",				offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x08));
	DECLARE("vmmppcr3",				offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x0C));
	DECLARE("vmmppcr4",				offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x10));
	DECLARE("vmmppcr5",				offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x14));

	DECLARE("vmmppcr6",				offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x18));
	DECLARE("vmmppcr7",				offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x1C));
	DECLARE("vmmppcr8",				offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x20));
	DECLARE("vmmppcr9",				offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x24));
	DECLARE("vmmppcr10",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x28));
	DECLARE("vmmppcr11",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x2C));
	DECLARE("vmmppcr12",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x30));
	DECLARE("vmmppcr13",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x34));

	DECLARE("vmmppcr14",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x38));
	DECLARE("vmmppcr15",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x3C));
	DECLARE("vmmppcr16",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x40));
	DECLARE("vmmppcr17",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x44));
	DECLARE("vmmppcr18",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x48));
	DECLARE("vmmppcr19",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x4C));
	DECLARE("vmmppcr20",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x50));
	DECLARE("vmmppcr21",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x54));

	DECLARE("vmmppcr22",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x58));
	DECLARE("vmmppcr23",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x5C));
	DECLARE("vmmppcr24",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x60));
	DECLARE("vmmppcr25",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x64));
	DECLARE("vmmppcr26",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x68));
	DECLARE("vmmppcr27",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x6C));
	DECLARE("vmmppcr28",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x70));
	DECLARE("vmmppcr29",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x74));

	DECLARE("vmmppcr30",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x78));
	DECLARE("vmmppcr31",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcGPRs+0x7C));
	DECLARE("vmmppccr",				offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcCR));
	DECLARE("vmmppcxer",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcXER));
	DECLARE("vmmppclr",				offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcLR));
	DECLARE("vmmppcctr",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcCTR));
	DECLARE("vmmppcmq",				offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcMQ));
	DECLARE("vmmppcvrsave",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcVRSave));	

	DECLARE("vmmppcvscr",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcVSCR+0x00));	
	DECLARE("vmmppcfpscrpad",		offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcFPSCR));
	DECLARE("vmmppcfpscr",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcFPSCR+4));

	DECLARE("famguestr0",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.guest_register));
	DECLARE("famguestr1",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.guest_register+0x4));
	DECLARE("famguestr2",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.guest_register+0x8));
	DECLARE("famguestr3",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.guest_register+0xC));
	DECLARE("famguestr4",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.guest_register+0x10));
	DECLARE("famguestr5",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.guest_register+0x14));
	DECLARE("famguestr6",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.guest_register+0x18));
	DECLARE("famguestr7",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.guest_register+0x1C));
	DECLARE("famguestpc",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.guest_pc));
	DECLARE("famguestmsr",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.guest_msr));

	DECLARE("famdispcode",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.fastassist_dispatch_code));
	DECLARE("famrefcon",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.fastassist_refcon));
	DECLARE("famparam",				offsetof(struct vmm_state_page_t *, vmm_fastassist_state.fastassist_parameter));
	DECLARE("famhandler",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.fastassist_dispatch));
	DECLARE("famintercepts",		offsetof(struct vmm_state_page_t *, vmm_fastassist_state.fastassist_intercepts));

	DECLARE("vmmFloatCngd",			vmmFloatCngd);
	DECLARE("vmmFloatCngdb",		vmmFloatCngdb);
	DECLARE("vmmVectCngd",			vmmVectCngd);
	DECLARE("vmmVectCngdb",			vmmVectCngdb);
	DECLARE("vmmTimerPop",			vmmTimerPop);
	DECLARE("vmmTimerPopb",			vmmTimerPopb);
	DECLARE("vmmMapDone",			vmmMapDone);
	DECLARE("vmmMapDoneb",			vmmMapDoneb);
	DECLARE("vmmFAMmode",			vmmFAMmode);
	DECLARE("vmmFAMmodeb",			vmmFAMmodeb);
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
	DECLARE("vmmXStart",			vmmXStart);
	DECLARE("vmmXStartb",			vmmXStartb);
	DECLARE("vmmXStop",			vmmXStop);
	DECLARE("vmmXStopb",			vmmXStopb);
	DECLARE("vmmKey",			vmmKey);
	DECLARE("vmmKeyb",			vmmKeyb);
	DECLARE("vmmFamSet",			vmmFamSet);
	DECLARE("vmmFamSetb",			vmmFamSetb);
	DECLARE("vmmFamEna",			vmmFamEna);
	DECLARE("vmmFamEnab",			vmmFamEnab);

	/* values from kern/task.h */
	DECLARE("TASK_SYSCALLS_MACH",
		offsetof(struct task *, syscalls_mach));
	DECLARE("TASK_SYSCALLS_UNIX",
		offsetof(struct task *, syscalls_unix));

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

	/* values from kern/processor.h */
	DECLARE("psthreads",	offsetof(struct processor_set *, threads));
	DECLARE("psthreadcnt",	offsetof(struct processor_set *, thread_count));
	

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
	DECLARE("SLOCK_ILK",	offsetof(usimple_lock_t, interlock));
#if	MACH_LDEBUG
	DECLARE("SLOCK_TYPE",	offsetof(usimple_lock_t, lock_type));
	DECLARE("SLOCK_PC",	offsetof(usimple_lock_t, debug.lock_pc));
	DECLARE("SLOCK_THREAD",	offsetof(usimple_lock_t, debug.lock_thread));
	DECLARE("SLOCK_DURATIONH",offsetof(usimple_lock_t, debug.duration[0]));
	DECLARE("SLOCK_DURATIONL",offsetof(usimple_lock_t, debug.duration[1]));
	DECLARE("USLOCK_TAG",	USLOCK_TAG);
#endif	/* MACH_LDEBUG */

	/* Mutex structure */
	DECLARE("LOCK_DATA",	offsetof(mutex_t *, interlock));
	DECLARE("MUTEX_WAITERS",offsetof(mutex_t *, waiters));
	DECLARE("MUTEX_PROMOTED_PRI",offsetof(mutex_t *, promoted_pri));
#if	MACH_LDEBUG
	DECLARE("MUTEX_TYPE",	offsetof(mutex_t *, type));
	DECLARE("MUTEX_PC",	offsetof(mutex_t *, pc));
	DECLARE("MUTEX_THREAD",	offsetof(mutex_t *, thread));
	DECLARE("MUTEX_TAG",	MUTEX_TAG);
#endif	/* MACH_LDEBUG */
						 
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
	DECLARE("bmcurrent",		offsetof(struct blokmap *, current));
	DECLARE("bmPTEr",		offsetof(struct blokmap *, PTEr));
	DECLARE("bmspace",		offsetof(struct blokmap *, space));
	DECLARE("blkFlags",		offsetof(struct blokmap *, blkFlags));
	DECLARE("blkPerm",		blkPerm);
	DECLARE("blkRem",		blkRem);
	DECLARE("blkPermbit",	blkPermbit);
	DECLARE("blkRembit",	blkRembit);
	DECLARE("BLKREMMAX",	BLKREMMAX);
	
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

	DECLARE("MFpcaptr",		offsetof(struct mappingflush *, pcaptr));
	DECLARE("MFmappingcnt",		offsetof(struct mappingflush *, mappingcnt));
	DECLARE("MFmapping",		offsetof(struct mappingflush *, mapping));
	DECLARE("MFmappingSize", 	sizeof(struct mfmapping));

	DECLARE("SVlock",		offsetof(struct Saveanchor *, savelock));
	DECLARE("SVpoolfwd",	offsetof(struct Saveanchor *, savepoolfwd));
	DECLARE("SVpoolbwd",	offsetof(struct Saveanchor *, savepoolbwd));
	DECLARE("SVfree",		offsetof(struct Saveanchor *, savefree));
	DECLARE("SVfreecnt",	offsetof(struct Saveanchor *, savefreecnt));
	DECLARE("SVadjust",		offsetof(struct Saveanchor *, saveadjust));
	DECLARE("SVinuse",		offsetof(struct Saveanchor *, saveinuse));
	DECLARE("SVtarget",		offsetof(struct Saveanchor *, savetarget));
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
	DECLARE("enaDiagEM",	enaDiagEM);
	DECLARE("enaDiagEMb",	enaDiagEMb);
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

	DECLARE("SACnext",		offsetof(struct savearea_comm *, sac_next));
	DECLARE("SACprev",		offsetof(struct savearea_comm *, sac_prev));
	DECLARE("SACvrswap",	offsetof(struct savearea_comm *, sac_vrswap));
	DECLARE("SACalloc",		offsetof(struct savearea_comm *, sac_alloc));
	DECLARE("SACflags",		offsetof(struct savearea_comm *, sac_flags));
	DECLARE("sac_cnt",		sac_cnt);
	DECLARE("sac_empty",	sac_empty);
	DECLARE("sac_perm",		sac_perm);
	DECLARE("sac_permb",	sac_permb);

	DECLARE("LocalSaveTarget",		LocalSaveTarget);
	DECLARE("LocalSaveMin",			LocalSaveMin);
	DECLARE("LocalSaveMax",			LocalSaveMax);
	DECLARE("FreeListMin",			FreeListMin);
	DECLARE("SaveLowHysteresis",	SaveLowHysteresis);
	DECLARE("SaveHighHysteresis",	SaveHighHysteresis);
	DECLARE("InitialSaveAreas",		InitialSaveAreas);
	DECLARE("InitialSaveTarget",	InitialSaveTarget);
	DECLARE("InitialSaveBloks",		InitialSaveBloks);

	DECLARE("SAVprev",		offsetof(struct savearea_comm *, save_prev));
	DECLARE("SAVact",		offsetof(struct savearea_comm *, save_act));
	DECLARE("SAVflags",		offsetof(struct savearea_comm *, save_flags));
	DECLARE("SAVlevel",		offsetof(struct savearea_comm *, save_level));
	DECLARE("SAVtime",		offsetof(struct savearea_comm *, save_time));
	DECLARE("SAVsize",		sizeof(struct savearea));
	DECLARE("SAVsizefpu",	sizeof(struct savearea_vec));
	DECLARE("SAVsizevec",	sizeof(struct savearea_fpu));
	DECLARE("SAVcommsize",	sizeof(struct savearea_comm));

	DECLARE("savesrr0",		offsetof(struct savearea *, save_srr0));
	DECLARE("savesrr1",		offsetof(struct savearea *, save_srr1));
	DECLARE("savecr",		offsetof(struct savearea *, save_cr));
	DECLARE("savexer",		offsetof(struct savearea *, save_xer));
	DECLARE("savelr",		offsetof(struct savearea *, save_lr));
	DECLARE("savectr",		offsetof(struct savearea *, save_ctr));
	DECLARE("savedar",		offsetof(struct savearea *, save_dar));
	DECLARE("savedsisr",	offsetof(struct savearea *, save_dsisr));
	DECLARE("saveexception",	offsetof(struct savearea *, save_exception));
	DECLARE("savefpscrpad",	offsetof(struct savearea *, save_fpscrpad));
	DECLARE("savefpscr",	offsetof(struct savearea *, save_fpscr));
	DECLARE("savevrsave",	offsetof(struct savearea *, save_vrsave));	
	DECLARE("savevscr",		offsetof(struct savearea *, save_vscr));	

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

	DECLARE("savefp0",		offsetof(struct savearea_fpu *, save_fp0));
	DECLARE("savefp1",		offsetof(struct savearea_fpu *, save_fp1));
	DECLARE("savefp2",		offsetof(struct savearea_fpu *, save_fp2));
	DECLARE("savefp3",		offsetof(struct savearea_fpu *, save_fp3));
	DECLARE("savefp4",		offsetof(struct savearea_fpu *, save_fp4));
	DECLARE("savefp5",		offsetof(struct savearea_fpu *, save_fp5));
	DECLARE("savefp6",		offsetof(struct savearea_fpu *, save_fp6));
	DECLARE("savefp7",		offsetof(struct savearea_fpu *, save_fp7));
	DECLARE("savefp8",		offsetof(struct savearea_fpu *, save_fp8));
	DECLARE("savefp9",		offsetof(struct savearea_fpu *, save_fp9));
	DECLARE("savefp10",		offsetof(struct savearea_fpu *, save_fp10));
	DECLARE("savefp11",		offsetof(struct savearea_fpu *, save_fp11));
	DECLARE("savefp12",		offsetof(struct savearea_fpu *, save_fp12));
	DECLARE("savefp13",		offsetof(struct savearea_fpu *, save_fp13));
	DECLARE("savefp14",		offsetof(struct savearea_fpu *, save_fp14));
	DECLARE("savefp15",		offsetof(struct savearea_fpu *, save_fp15));
	DECLARE("savefp16",		offsetof(struct savearea_fpu *, save_fp16));
	DECLARE("savefp17",		offsetof(struct savearea_fpu *, save_fp17));
	DECLARE("savefp18",		offsetof(struct savearea_fpu *, save_fp18));
	DECLARE("savefp19",		offsetof(struct savearea_fpu *, save_fp19));
	DECLARE("savefp20",		offsetof(struct savearea_fpu *, save_fp20));
	DECLARE("savefp21",		offsetof(struct savearea_fpu *, save_fp21));
	DECLARE("savefp22",		offsetof(struct savearea_fpu *, save_fp22));
	DECLARE("savefp23",		offsetof(struct savearea_fpu *, save_fp23));
	DECLARE("savefp24",		offsetof(struct savearea_fpu *, save_fp24));
	DECLARE("savefp25",		offsetof(struct savearea_fpu *, save_fp25));
	DECLARE("savefp26",		offsetof(struct savearea_fpu *, save_fp26));
	DECLARE("savefp27",		offsetof(struct savearea_fpu *, save_fp27));
	DECLARE("savefp28",		offsetof(struct savearea_fpu *, save_fp28));
	DECLARE("savefp29",		offsetof(struct savearea_fpu *, save_fp29));
	DECLARE("savefp30",		offsetof(struct savearea_fpu *, save_fp30));
	DECLARE("savefp31",		offsetof(struct savearea_fpu *, save_fp31));
	
	DECLARE("savevr0",		offsetof(struct savearea_vec *, save_vr0));
	DECLARE("savevr1",		offsetof(struct savearea_vec *, save_vr1));
	DECLARE("savevr2",		offsetof(struct savearea_vec *, save_vr2));
	DECLARE("savevr3",		offsetof(struct savearea_vec *, save_vr3));
	DECLARE("savevr4",		offsetof(struct savearea_vec *, save_vr4));
	DECLARE("savevr5",		offsetof(struct savearea_vec *, save_vr5));
	DECLARE("savevr6",		offsetof(struct savearea_vec *, save_vr6));
	DECLARE("savevr7",		offsetof(struct savearea_vec *, save_vr7));
	DECLARE("savevr8",		offsetof(struct savearea_vec *, save_vr8));
	DECLARE("savevr9",		offsetof(struct savearea_vec *, save_vr9));
	DECLARE("savevr10",		offsetof(struct savearea_vec *, save_vr10));
	DECLARE("savevr11",		offsetof(struct savearea_vec *, save_vr11));
	DECLARE("savevr12",		offsetof(struct savearea_vec *, save_vr12));
	DECLARE("savevr13",		offsetof(struct savearea_vec *, save_vr13));
	DECLARE("savevr14",		offsetof(struct savearea_vec *, save_vr14));
	DECLARE("savevr15",		offsetof(struct savearea_vec *, save_vr15));
	DECLARE("savevr16",		offsetof(struct savearea_vec *, save_vr16));
	DECLARE("savevr17",		offsetof(struct savearea_vec *, save_vr17));
	DECLARE("savevr18",		offsetof(struct savearea_vec *, save_vr18));
	DECLARE("savevr19",		offsetof(struct savearea_vec *, save_vr19));
	DECLARE("savevr20",		offsetof(struct savearea_vec *, save_vr20));
	DECLARE("savevr21",		offsetof(struct savearea_vec *, save_vr21));
	DECLARE("savevr22",		offsetof(struct savearea_vec *, save_vr22));
	DECLARE("savevr23",		offsetof(struct savearea_vec *, save_vr23));
	DECLARE("savevr24",		offsetof(struct savearea_vec *, save_vr24));
	DECLARE("savevr25",		offsetof(struct savearea_vec *, save_vr25));
	DECLARE("savevr26",		offsetof(struct savearea_vec *, save_vr26));
	DECLARE("savevr27",		offsetof(struct savearea_vec *, save_vr27));
	DECLARE("savevr28",		offsetof(struct savearea_vec *, save_vr28));
	DECLARE("savevr29",		offsetof(struct savearea_vec *, save_vr29));
	DECLARE("savevr30",		offsetof(struct savearea_vec *, save_vr30));
	DECLARE("savevr31",		offsetof(struct savearea_vec *, save_vr31));
	DECLARE("savevrvalid",	offsetof(struct savearea_vec *, save_vrvalid));	

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

	DECLARE("shdIBAT",	offsetof(struct shadowBAT *, IBATs));	
	DECLARE("shdDBAT",	offsetof(struct shadowBAT *, DBATs));	
	

	
	return(0);  /* For ANSI C :-) */



}
