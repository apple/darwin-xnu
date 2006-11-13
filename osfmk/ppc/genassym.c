/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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

#include <va_list.h>
#include <types.h>

#include <kern/task.h>
#include <kern/thread.h>
#include <kern/host.h>
#include <kern/lock.h>
#include <kern/locks.h>
#include <kern/processor.h>
#include <ppc/exception.h>
#include <ppc/thread.h>
#include <ppc/misc_protos.h>
#include <kern/syscall_sw.h>
#include <ppc/low_trace.h>
#include <ppc/PseudoKernel.h>
#include <ppc/mappings.h>
#include <ppc/Firmware.h>
#include <ppc/low_trace.h>
#include <vm/vm_map.h>
#include <vm/pmap.h>
#include <ppc/pmap.h>
#include <ppc/Diagnostics.h>
#include <pexpert/pexpert.h>
#include <mach/machine.h>
#include <ppc/vmachmon.h>
#include <ppc/hw_perfmon.h>
#include <ppc/PPCcalls.h>
#include <ppc/mem.h>
#include <ppc/boot.h>
#include <ppc/lowglobals.h>

/* Undefine standard offsetof because it is different than the one here */
#undef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE)0)->MEMBER)

#define DECLARE(SYM,VAL) \
	__asm("#DEFINITION##define\t" SYM "\t%0" : : "n" ((u_int)(VAL)))

int main(int argc, char *argv[])
{
	/* Process Control Block */
	DECLARE("ACT_MACT_KSP",	offsetof(thread_t, machine.ksp));
	DECLARE("ACT_MACT_BEDA", offsetof(thread_t, machine.bbDescAddr));
	DECLARE("ACT_MACT_BTS",	offsetof(thread_t, machine.bbTableStart));
	DECLARE("ACT_MACT_BTE",	offsetof(thread_t, machine.bbTaskEnv));
	DECLARE("ACT_MACT_SPF",	offsetof(thread_t, machine.specFlags));
	DECLARE("ACT_PREEMPT_CNT",	offsetof(thread_t, machine.preemption_count));
	DECLARE("ACT_PER_PROC",	offsetof(thread_t, machine.PerProc));
	DECLARE("qactTimer",	offsetof(thread_t, machine.qactTimer));
	DECLARE("umwSpace",	offsetof(thread_t, machine.umwSpace));
	DECLARE("umwRelo",	offsetof(thread_t, machine.umwRelo));
	DECLARE("umwSwitchAway",	umwSwitchAway);
	DECLARE("umwSwitchAwayb",	umwSwitchAwayb);
	DECLARE("bbTrap",		offsetof(thread_t, machine.bbTrap));
	DECLARE("bbSysCall",	offsetof(thread_t, machine.bbSysCall));
	DECLARE("bbInterrupt",	offsetof(thread_t, machine.bbInterrupt));
	DECLARE("bbPending",	offsetof(thread_t, machine.bbPending));
	
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

	DECLARE("bbThread",		bbThread);
	DECLARE("bbThreadbit",	bbThreadbit);
	DECLARE("bbNoMachSC",	bbNoMachSC);
	DECLARE("bbNoMachSCbit",bbNoMachSCbit);
	DECLARE("bbPreemptive",	bbPreemptive);
	DECLARE("bbPreemptivebit",	bbPreemptivebit);

	DECLARE("fvChkb",		fvChkb);
	DECLARE("fvChk",		fvChk);
	DECLARE("FamVMena",		FamVMena);
	DECLARE("FamVMenabit",		FamVMenabit);
	DECLARE("FamVMmode",		FamVMmode);
	DECLARE("FamVMmodebit",		FamVMmodebit);
	DECLARE("perfMonitor",		perfMonitor);
	DECLARE("perfMonitorbit",	perfMonitorbit);
	DECLARE("OnProc",		OnProc);
	DECLARE("OnProcbit",		OnProcbit);

	/* Per Proc info structure */
	DECLARE("PP_CPU_NUMBER",		offsetof(struct per_proc_info *, cpu_number));
	DECLARE("PP_CPU_FLAGS",			offsetof(struct per_proc_info *, cpu_flags));
	DECLARE("PP_ISTACKPTR",			offsetof(struct per_proc_info *, istackptr));
	DECLARE("PP_INTSTACK_TOP_SS",	offsetof(struct per_proc_info *, intstack_top_ss));
	DECLARE("PP_DEBSTACKPTR",		offsetof(struct per_proc_info *, debstackptr));
	DECLARE("PP_DEBSTACK_TOP_SS",	offsetof(struct per_proc_info *, debstack_top_ss));
	DECLARE("PP_HIBERNATE",	offsetof(struct per_proc_info *, hibernate));
	DECLARE("FPUowner",				offsetof(struct per_proc_info *, FPU_owner));
	DECLARE("VMXowner",				offsetof(struct per_proc_info *, VMX_owner));
	DECLARE("holdQFret",			offsetof(struct per_proc_info *, holdQFret));
	DECLARE("rtcPop",				offsetof(struct per_proc_info *, rtcPop));

	DECLARE("PP_PENDING_AST",		offsetof(struct per_proc_info *, pending_ast));
	DECLARE("quickfret", 			offsetof(struct per_proc_info *, quickfret));
	DECLARE("lclfree", 				offsetof(struct per_proc_info *, lclfree));
	DECLARE("lclfreecnt",			offsetof(struct per_proc_info *, lclfreecnt));
	DECLARE("PP_INTS_ENABLED", 		offsetof(struct per_proc_info *, interrupts_enabled));
	DECLARE("UAW", 					offsetof(struct per_proc_info *, Uassist));
	DECLARE("next_savearea", 		offsetof(struct per_proc_info *, next_savearea));
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
	DECLARE("pfSlowNap",				pfSlowNap);
	DECLARE("pfSlowNapb",				pfSlowNapb);
	DECLARE("pfNoMuMMCK",				pfNoMuMMCK);
	DECLARE("pfNoMuMMCKb",				pfNoMuMMCKb);
	DECLARE("pfNoL2PFNap",				pfNoL2PFNap);
	DECLARE("pfNoL2PFNapb",				pfNoL2PFNapb);
	DECLARE("pfSCOMFixUp",				pfSCOMFixUp);
	DECLARE("pfSCOMFixUpb",				pfSCOMFixUpb);
    DECLARE("pfHasDcba",			pfHasDcba);
	DECLARE("pfHasDcbab",			pfHasDcbab);
	DECLARE("pfL1fa",				pfL1fa);
	DECLARE("pfL1fab",				pfL1fab);
	DECLARE("pfL2",					pfL2);
	DECLARE("pfL2b",				pfL2b);
	DECLARE("pfL2fa",				pfL2fa);
	DECLARE("pfL2fab",				pfL2fab);
	DECLARE("pfL2i",				pfL2i);
	DECLARE("pfL2ib",				pfL2ib);
	DECLARE("pfLClck",				pfLClck);
	DECLARE("pfLClckb",				pfLClckb);
	DECLARE("pfWillNap",			pfWillNap);
	DECLARE("pfWillNapb",			pfWillNapb);
	DECLARE("pfNoMSRir",			pfNoMSRir);
	DECLARE("pfNoMSRirb",			pfNoMSRirb);
	DECLARE("pfL3pdet",				pfL3pdet);
	DECLARE("pfL3pdetb",			pfL3pdetb);
    DECLARE("pf128Byte",			pf128Byte);
    DECLARE("pf128Byteb",			pf128Byteb);
    DECLARE("pf32Byte",				pf32Byte);
    DECLARE("pf32Byteb",			pf32Byteb);
    DECLARE("pf64Bit",				pf64Bit);
    DECLARE("pf64Bitb",				pf64Bitb);
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
	DECLARE("pfHID4", 				offsetof(struct per_proc_info *, pf.pfHID4));
	DECLARE("pfHID5", 				offsetof(struct per_proc_info *, pf.pfHID5));
	DECLARE("pfMSSCR0", 			offsetof(struct per_proc_info *, pf.pfMSSCR0));
	DECLARE("pfMSSCR1", 			offsetof(struct per_proc_info *, pf.pfMSSCR1));
	DECLARE("pfICTRL", 				offsetof(struct per_proc_info *, pf.pfICTRL));
	DECLARE("pfLDSTCR", 			offsetof(struct per_proc_info *, pf.pfLDSTCR));
	DECLARE("pfLDSTDB", 			offsetof(struct per_proc_info *, pf.pfLDSTDB));
	DECLARE("pfl2crOriginal", 		offsetof(struct per_proc_info *, pf.l2crOriginal));
	DECLARE("pfl3crOriginal", 		offsetof(struct per_proc_info *, pf.l3crOriginal));
	DECLARE("pfBootConfig",			offsetof(struct per_proc_info *, pf.pfBootConfig));
	DECLARE("pfPowerModes",			offsetof(struct per_proc_info *, pf.pfPowerModes));
	DECLARE("pfPowerTune0",			offsetof(struct per_proc_info *, pf.pfPowerTune0));
	DECLARE("pfPowerTune1",			offsetof(struct per_proc_info *, pf.pfPowerTune1));
	DECLARE("pmType",				pmType);
	DECLARE("pmDPLLVmin",			pmDPLLVmin);
	DECLARE("pmDPLLVminb",			pmDPLLVminb);
	DECLARE("pmPowerTune",			pmPowerTune);
	DECLARE("pmDFS",				pmDFS);
	DECLARE("pmDualPLL",			pmDualPLL);
	DECLARE("pfPTEG", 				offsetof(struct per_proc_info *, pf.pfPTEG));
	DECLARE("pfMaxVAddr", 			offsetof(struct per_proc_info *, pf.pfMaxVAddr));
	DECLARE("pfMaxPAddr", 			offsetof(struct per_proc_info *, pf.pfMaxPAddr));
	DECLARE("pfSize", 				sizeof(procFeatures));
	
	DECLARE("validSegs", 			offsetof(struct per_proc_info *, validSegs));
	DECLARE("ppUserPmapVirt", 		offsetof(struct per_proc_info *, ppUserPmapVirt));
	DECLARE("ppUserPmap", 			offsetof(struct per_proc_info *, ppUserPmap));
	DECLARE("ppMapFlags", 			offsetof(struct per_proc_info *, ppMapFlags));
	DECLARE("ppInvSeg", 			offsetof(struct per_proc_info *, ppInvSeg));
	DECLARE("ppCurSeg", 			offsetof(struct per_proc_info *, ppCurSeg));
	DECLARE("ppSegSteal", 			offsetof(struct per_proc_info *, ppSegSteal));

	DECLARE("VMMareaPhys", 			offsetof(struct per_proc_info *, VMMareaPhys));
	DECLARE("VMMXAFlgs", 			offsetof(struct per_proc_info *, VMMXAFlgs));
	DECLARE("FAMintercept", 		offsetof(struct per_proc_info *, FAMintercept));

	DECLARE("ppUMWmp", 				offsetof(struct per_proc_info *, ppUMWmp));

	DECLARE("tempr0", 				offsetof(struct per_proc_info *, tempr0));
	DECLARE("tempr1", 				offsetof(struct per_proc_info *, tempr1));
	DECLARE("tempr2", 				offsetof(struct per_proc_info *, tempr2));
	DECLARE("tempr3", 				offsetof(struct per_proc_info *, tempr3));
	DECLARE("tempr4", 				offsetof(struct per_proc_info *, tempr4));
	DECLARE("tempr5", 				offsetof(struct per_proc_info *, tempr5));
	DECLARE("tempr6", 				offsetof(struct per_proc_info *, tempr6));
	DECLARE("tempr7", 				offsetof(struct per_proc_info *, tempr7));
	DECLARE("tempr8", 				offsetof(struct per_proc_info *, tempr8));
	DECLARE("tempr9", 				offsetof(struct per_proc_info *, tempr9));
	DECLARE("tempr10", 				offsetof(struct per_proc_info *, tempr10));
	DECLARE("tempr11", 				offsetof(struct per_proc_info *, tempr11));
	DECLARE("tempr12", 				offsetof(struct per_proc_info *, tempr12));
	DECLARE("tempr13", 				offsetof(struct per_proc_info *, tempr13));
	DECLARE("tempr14", 				offsetof(struct per_proc_info *, tempr14));
	DECLARE("tempr15", 				offsetof(struct per_proc_info *, tempr15));
	DECLARE("tempr16", 				offsetof(struct per_proc_info *, tempr16));
	DECLARE("tempr17", 				offsetof(struct per_proc_info *, tempr17));
	DECLARE("tempr18", 				offsetof(struct per_proc_info *, tempr18));
	DECLARE("tempr19", 				offsetof(struct per_proc_info *, tempr19));
	DECLARE("tempr20", 				offsetof(struct per_proc_info *, tempr20));
	DECLARE("tempr21", 				offsetof(struct per_proc_info *, tempr21));
	DECLARE("tempr22", 				offsetof(struct per_proc_info *, tempr22));
	DECLARE("tempr23", 				offsetof(struct per_proc_info *, tempr23));
	DECLARE("tempr24", 				offsetof(struct per_proc_info *, tempr24));
	DECLARE("tempr25", 				offsetof(struct per_proc_info *, tempr25));
	DECLARE("tempr26", 				offsetof(struct per_proc_info *, tempr26));
	DECLARE("tempr27", 				offsetof(struct per_proc_info *, tempr27));
	DECLARE("tempr28", 				offsetof(struct per_proc_info *, tempr28));
	DECLARE("tempr29", 				offsetof(struct per_proc_info *, tempr29));
	DECLARE("tempr30", 				offsetof(struct per_proc_info *, tempr30));
	DECLARE("tempr31", 				offsetof(struct per_proc_info *, tempr31));

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
	DECLARE("skipListPrev", 		offsetof(struct per_proc_info *, skipListPrev));
	DECLARE("ppSize",				sizeof(struct per_proc_info));
	DECLARE("ppe_paddr", 				offsetof(struct per_proc_entry *, ppe_paddr));
	DECLARE("ppe_vaddr", 				offsetof(struct per_proc_entry *, ppe_vaddr));
	DECLARE("ppeSize",				sizeof(struct per_proc_entry));
	DECLARE("MAX_CPUS",				MAX_CPUS);
	DECLARE("patcharea", 			offsetof(struct per_proc_info *, patcharea));

	DECLARE("hwCounts",				offsetof(struct per_proc_info *, hwCtr));
	DECLARE("hwInVains",			offsetof(struct per_proc_info *, hwCtr.hwInVains));
	DECLARE("hwResets",				offsetof(struct per_proc_info *, hwCtr.hwResets));
	DECLARE("hwMachineChecks",		offsetof(struct per_proc_info *, hwCtr.hwMachineChecks));
	DECLARE("hwDSIs",				offsetof(struct per_proc_info *, hwCtr.hwDSIs));
	DECLARE("hwISIs",				offsetof(struct per_proc_info *, hwCtr.hwISIs));
	DECLARE("hwExternals",			offsetof(struct per_proc_info *, hwCtr.hwExternals));
	DECLARE("hwAlignments",			offsetof(struct per_proc_info *, hwCtr.hwAlignments));
	DECLARE("hwPrograms",			offsetof(struct per_proc_info *, hwCtr.hwPrograms));
	DECLARE("hwFloatPointUnavailable",	offsetof(struct per_proc_info *, hwCtr.hwFloatPointUnavailable));
	DECLARE("hwDecrementers",		offsetof(struct per_proc_info *, hwCtr.hwDecrementers));
	DECLARE("hwIOErrors",			offsetof(struct per_proc_info *, hwCtr.hwIOErrors));
	DECLARE("hwrsvd0",				offsetof(struct per_proc_info *, hwCtr.hwrsvd0));
	DECLARE("hwSystemCalls",		offsetof(struct per_proc_info *, hwCtr.hwSystemCalls));
	DECLARE("hwTraces",				offsetof(struct per_proc_info *, hwCtr.hwTraces));
	DECLARE("hwFloatingPointAssists",	offsetof(struct per_proc_info *, hwCtr.hwFloatingPointAssists));
	DECLARE("hwPerformanceMonitors",	offsetof(struct per_proc_info *, hwCtr.hwPerformanceMonitors));
	DECLARE("hwAltivecs",			offsetof(struct per_proc_info *, hwCtr.hwAltivecs));
	DECLARE("hwrsvd1",				offsetof(struct per_proc_info *, hwCtr.hwrsvd1));
	DECLARE("hwrsvd2",				offsetof(struct per_proc_info *, hwCtr.hwrsvd2));
	DECLARE("hwrsvd3",				offsetof(struct per_proc_info *, hwCtr.hwrsvd3));
	DECLARE("hwInstBreakpoints",	offsetof(struct per_proc_info *, hwCtr.hwInstBreakpoints));
	DECLARE("hwSystemManagements",	offsetof(struct per_proc_info *, hwCtr.hwSystemManagements));
	DECLARE("hwAltivecAssists",		offsetof(struct per_proc_info *, hwCtr.hwAltivecAssists));
	DECLARE("hwThermal",			offsetof(struct per_proc_info *, hwCtr.hwThermal));
	DECLARE("hwrsvd5",				offsetof(struct per_proc_info *, hwCtr.hwrsvd5));
	DECLARE("hwrsvd6",				offsetof(struct per_proc_info *, hwCtr.hwrsvd6));
	DECLARE("hwrsvd7",				offsetof(struct per_proc_info *, hwCtr.hwrsvd7));
	DECLARE("hwrsvd8",				offsetof(struct per_proc_info *, hwCtr.hwrsvd8));
	DECLARE("hwrsvd9",				offsetof(struct per_proc_info *, hwCtr.hwrsvd9));
	DECLARE("hwrsvd10",				offsetof(struct per_proc_info *, hwCtr.hwrsvd10));
	DECLARE("hwrsvd11",				offsetof(struct per_proc_info *, hwCtr.hwrsvd11));
	DECLARE("hwrsvd12",				offsetof(struct per_proc_info *, hwCtr.hwrsvd12));
	DECLARE("hwrsvd13",				offsetof(struct per_proc_info *, hwCtr.hwrsvd13));
	DECLARE("hwTrace601",			offsetof(struct per_proc_info *, hwCtr.hwTrace601));
	DECLARE("hwSIGPs",				offsetof(struct per_proc_info *, hwCtr.hwSIGPs));
	DECLARE("hwPreemptions",		offsetof(struct per_proc_info *, hwCtr.hwPreemptions));
	DECLARE("hwContextSwitchs",		offsetof(struct per_proc_info *, hwCtr.hwContextSwitchs));
	DECLARE("hwShutdowns",			offsetof(struct per_proc_info *, hwCtr.hwShutdowns));
	DECLARE("hwChokes",				offsetof(struct per_proc_info *, hwCtr.hwChokes));
	DECLARE("hwDataSegments",		offsetof(struct per_proc_info *, hwCtr.hwDataSegments));
	DECLARE("hwInstructionSegments",	offsetof(struct per_proc_info *, hwCtr.hwInstructionSegments));
	DECLARE("hwSoftPatches",		offsetof(struct per_proc_info *, hwCtr.hwSoftPatches));
	DECLARE("hwMaintenances",		offsetof(struct per_proc_info *, hwCtr.hwMaintenances));
	DECLARE("hwInstrumentations",	offsetof(struct per_proc_info *, hwCtr.hwInstrumentations));
	DECLARE("hwRedrives",			offsetof(struct per_proc_info *, hwCtr.hwRedrives));
	DECLARE("hwIgnored",			offsetof(struct per_proc_info *, hwCtr.hwIgnored));
	DECLARE("hwhdec",				offsetof(struct per_proc_info *, hwCtr.hwhdec));
	DECLARE("hwSteals",				offsetof(struct per_proc_info *, hwCtr.hwSteals));
	
	DECLARE("hwWalkPhys",			offsetof(struct per_proc_info *, hwCtr.hwWalkPhys));
	DECLARE("hwWalkFull",			offsetof(struct per_proc_info *, hwCtr.hwWalkFull));
	DECLARE("hwWalkMerge",			offsetof(struct per_proc_info *, hwCtr.hwWalkMerge));
	DECLARE("hwWalkQuick",			offsetof(struct per_proc_info *, hwCtr.hwWalkQuick));

	DECLARE("hwMckHang",			offsetof(struct per_proc_info *, hwCtr.hwMckHang));
	DECLARE("hwMckSLBPE",			offsetof(struct per_proc_info *, hwCtr.hwMckSLBPE));
	DECLARE("hwMckTLBPE",			offsetof(struct per_proc_info *, hwCtr.hwMckTLBPE));
	DECLARE("hwMckERCPE",			offsetof(struct per_proc_info *, hwCtr.hwMckERCPE));
	DECLARE("hwMckL1DPE",			offsetof(struct per_proc_info *, hwCtr.hwMckL1DPE));
	DECLARE("hwMckL1TPE",			offsetof(struct per_proc_info *, hwCtr.hwMckL1TPE));
	DECLARE("hwMckUE",				offsetof(struct per_proc_info *, hwCtr.hwMckUE));
	DECLARE("hwMckIUE",				offsetof(struct per_proc_info *, hwCtr.hwMckIUE));
	DECLARE("hwMckIUEr",			offsetof(struct per_proc_info *, hwCtr.hwMckIUEr));
	DECLARE("hwMckDUE",				offsetof(struct per_proc_info *, hwCtr.hwMckDUE));
	DECLARE("hwMckDTW",				offsetof(struct per_proc_info *, hwCtr.hwMckDTW));
	DECLARE("hwMckUnk",				offsetof(struct per_proc_info *, hwCtr.hwMckUnk));
	DECLARE("hwMckExt",				offsetof(struct per_proc_info *, hwCtr.hwMckExt));
	DECLARE("hwMckICachePE",		offsetof(struct per_proc_info *, hwCtr.hwMckICachePE));
	DECLARE("hwMckITagPE",			offsetof(struct per_proc_info *, hwCtr.hwMckITagPE));
	DECLARE("hwMckIEratPE",			offsetof(struct per_proc_info *, hwCtr.hwMckIEratPE));
	DECLARE("hwMckDEratPE",			offsetof(struct per_proc_info *, hwCtr.hwMckDEratPE));

	DECLARE("napStamp", 			offsetof(struct per_proc_info *, hwCtr.napStamp));
	DECLARE("napTotal", 			offsetof(struct per_proc_info *, hwCtr.napTotal));
	DECLARE("PP_PROCESSOR",			offsetof(struct per_proc_info *, processor[0]));
	DECLARE("PP_PROCESSOR_SIZE",	sizeof(((struct per_proc_info *)0)->processor));
	DECLARE("PROCESSOR_SIZE",		sizeof (struct processor));

	DECLARE("patchAddr",			offsetof(struct patch_entry *, addr));
	DECLARE("patchData",			offsetof(struct patch_entry *, data));
	DECLARE("patchType",			offsetof(struct patch_entry *, type));
	DECLARE("patchValue",			offsetof(struct patch_entry *, value));
	DECLARE("peSize", 				sizeof(patch_entry_t));
	DECLARE("PATCH_PROCESSOR",		PATCH_PROCESSOR);
	DECLARE("PATCH_FEATURE",		PATCH_FEATURE);
    DECLARE("PATCH_END_OF_TABLE",   PATCH_END_OF_TABLE);
	DECLARE("PatchExt32",			PatchExt32);
	DECLARE("PatchExt32b",			PatchExt32b);
	DECLARE("PatchLwsync",			PatchLwsync);
	DECLARE("PatchLwsyncb",			PatchLwsyncb);

	DECLARE("RESETHANDLER_TYPE", 	offsetof(struct resethandler *, type));
	DECLARE("RESETHANDLER_CALL", 	offsetof(struct resethandler *, call_paddr));
	DECLARE("RESETHANDLER_ARG", 	offsetof(struct resethandler *, arg__paddr));

	/* we want offset from
	 * bottom of kernel stack, not offset into structure
	 */
#define IKSBASE (u_int)STACK_IKS(0)

	/* values from kern/thread.h */
	DECLARE("THREAD_OPTIONS",		offsetof(thread_t, options));
	DECLARE("TH_OPT_DELAYIDLE", 	TH_OPT_DELAYIDLE);
	DECLARE("THREAD_KERNEL_STACK",	offsetof(thread_t, kernel_stack));
	DECLARE("THREAD_RECOVER",		offsetof(thread_t, recover));
	DECLARE("THREAD_FUNNEL_LOCK",
			offsetof(thread_t, funnel_lock));
	DECLARE("THREAD_FUNNEL_STATE",
			offsetof(thread_t, funnel_state));
	DECLARE("LOCK_FNL_MUTEX",
			offsetof(struct funnel_lock *, fnl_mutex));

	DECLARE("ACT_TASK",				offsetof(thread_t, task));
	DECLARE("ACT_MACT_PCB",			offsetof(thread_t, machine.pcb));
	DECLARE("ACT_MACT_UPCB",		offsetof(thread_t, machine.upcb));
	DECLARE("ACT_AST",				offsetof(thread_t, ast));
	DECLARE("ACT_VMMAP",			offsetof(thread_t, map));
	DECLARE("vmmCEntry",			offsetof(thread_t, machine.vmmCEntry));
	DECLARE("vmmControl",			offsetof(thread_t, machine.vmmControl));
	DECLARE("curctx",				offsetof(thread_t, machine.curctx));
	DECLARE("deferctx",				offsetof(thread_t, machine.deferctx));
	DECLARE("facctx",				offsetof(thread_t, machine.facctx));
#ifdef MACH_BSD
	DECLARE("CTHREAD_SELF",			offsetof(thread_t, machine.cthread_self));
#endif  

	DECLARE("FPUsave",				offsetof(struct facility_context *,FPUsave));
	DECLARE("FPUlevel",				offsetof(struct facility_context *,FPUlevel));
	DECLARE("FPUcpu",				offsetof(struct facility_context *,FPUcpu));
	DECLARE("FPUsync",				offsetof(struct facility_context *,FPUsync));
	DECLARE("VMXsave",				offsetof(struct facility_context *,VMXsave));
	DECLARE("VMXlevel",				offsetof(struct facility_context *,VMXlevel));
	DECLARE("VMXcpu",				offsetof(struct facility_context *,VMXcpu));
	DECLARE("VMXsync",				offsetof(struct facility_context *,VMXsync));
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
	DECLARE("kVmmGetTimer", 		kVmmGetTimer);
	DECLARE("kVmmExecuteVM", 		kVmmExecuteVM);
	DECLARE("kVmmProtectPage", 		kVmmProtectPage);
	DECLARE("kVmmMapList", 			kVmmMapList);
	DECLARE("kVmmUnmapList", 		kVmmUnmapList);
	DECLARE("kVmmActivateXA", 		kVmmActivateXA);
	DECLARE("kVmmDeactivateXA", 	kVmmDeactivateXA);
	DECLARE("kVmmGetXA",			kVmmGetXA);
	DECLARE("kVmmMapPage64", 		kVmmMapPage64);
	DECLARE("kVmmGetPageMapping64",	kVmmGetPageMapping64);
	DECLARE("kVmmUnmapPage64", 		kVmmUnmapPage64);
	DECLARE("kVmmGetPageDirtyFlag64", 	kVmmGetPageDirtyFlag64);
	DECLARE("kVmmMapExecute64", 	kVmmMapExecute64);
	DECLARE("kVmmProtectExecute64", kVmmProtectExecute64);
	DECLARE("kVmmMapList64", 		kVmmMapList64);
	DECLARE("kVmmUnmapList64", 		kVmmUnmapList64);
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
	DECLARE("kVmmInvalidAdSpace",	kVmmInvalidAdSpace);

	DECLARE("kVmmProtXtnd",			kVmmProtXtnd);
	DECLARE("kVmmProtNARW",			kVmmProtNARW);
	DECLARE("kVmmProtRORW",			kVmmProtRORW);
	DECLARE("kVmmProtRWRW",			kVmmProtRWRW);
	DECLARE("kVmmProtRORO",			kVmmProtRORO);
	
	DECLARE("vmmFlags",				offsetof(struct vmmCntrlEntry *, vmmFlags));
	DECLARE("vmmXAFlgs",			offsetof(struct vmmCntrlEntry *, vmmXAFlgs));
	DECLARE("vmmPmap",				offsetof(struct vmmCntrlEntry *, vmmPmap));
	DECLARE("vmmInUseb",			vmmInUseb);
	DECLARE("vmmInUse",				vmmInUse);
	DECLARE("vmmContextKern",		offsetof(struct vmmCntrlEntry *, vmmContextKern));
	DECLARE("vmmContextPhys",		offsetof(struct vmmCntrlEntry *, vmmContextPhys));
	DECLARE("vmmContextUser",		offsetof(struct vmmCntrlEntry *, vmmContextUser));
	DECLARE("vmmFacCtx",			offsetof(struct vmmCntrlEntry *, vmmFacCtx));
	DECLARE("vmmLastMap",			offsetof(struct vmmCntrlTable *, vmmLastMap));
	DECLARE("vmmGFlags",			offsetof(struct vmmCntrlTable *, vmmGFlags));
	DECLARE("vmmc",					offsetof(struct vmmCntrlTable *, vmmc));
	DECLARE("vmmAdsp",				offsetof(struct vmmCntrlTable *, vmmAdsp));
	DECLARE("vmmLastAdSp",			vmmLastAdSp);
	DECLARE("vmmFAMintercept",		offsetof(struct vmmCntrlEntry *, vmmFAMintercept));
	DECLARE("vmmCEntrySize",		sizeof(struct vmmCntrlEntry));
	DECLARE("kVmmMaxContexts",		kVmmMaxContexts);
	
	DECLARE("interface_version",	offsetof(struct vmm_state_page_t *, interface_version));
	DECLARE("thread_index",			offsetof(struct vmm_state_page_t *, thread_index));
	DECLARE("vmmStat",				offsetof(struct vmm_state_page_t *, vmmStat));
	DECLARE("vmmCntrl",				offsetof(struct vmm_state_page_t *, vmmCntrl));
	DECLARE("vmm_proc_state",		offsetof(struct vmm_state_page_t *, vmm_proc_state));

	DECLARE("return_code",			offsetof(struct vmm_state_page_t *, return_code));

	DECLARE("return_params",		offsetof(struct vmm_state_page_t *, vmmRet.vmmrp32.return_params));
	DECLARE("return_paramsX",		offsetof(struct vmm_state_page_t *, vmmRet.vmmrp64.return_params));

#if 0
	DECLARE("return_params",		offsetof(struct vmm_state_page_t *, return_params));
	DECLARE("vmm_proc_state",		offsetof(struct vmm_state_page_t *, vmm_proc_state));
#endif
	DECLARE("vmmppcVRs",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcVRs));
	DECLARE("vmmppcVSCR",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcVSCR));
	DECLARE("vmmppcFPRs",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcFPRs));
	DECLARE("vmmppcFPSCR",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcFPSCR));

	DECLARE("vmmppcpc",				offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcPC));
	DECLARE("vmmppcmsr",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcMSR));
	DECLARE("vmmppcr0",				offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x00));
	DECLARE("vmmppcr1",				offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x04));
	DECLARE("vmmppcr2",				offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x08));
	DECLARE("vmmppcr3",				offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x0C));
	DECLARE("vmmppcr4",				offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x10));
	DECLARE("vmmppcr5",				offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x14));

	DECLARE("vmmppcr6",				offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x18));
	DECLARE("vmmppcr7",				offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x1C));
	DECLARE("vmmppcr8",				offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x20));
	DECLARE("vmmppcr9",				offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x24));
	DECLARE("vmmppcr10",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x28));
	DECLARE("vmmppcr11",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x2C));
	DECLARE("vmmppcr12",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x30));
	DECLARE("vmmppcr13",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x34));

	DECLARE("vmmppcr14",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x38));
	DECLARE("vmmppcr15",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x3C));
	DECLARE("vmmppcr16",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x40));
	DECLARE("vmmppcr17",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x44));
	DECLARE("vmmppcr18",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x48));
	DECLARE("vmmppcr19",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x4C));
	DECLARE("vmmppcr20",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x50));
	DECLARE("vmmppcr21",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x54));

	DECLARE("vmmppcr22",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x58));
	DECLARE("vmmppcr23",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x5C));
	DECLARE("vmmppcr24",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x60));
	DECLARE("vmmppcr25",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x64));
	DECLARE("vmmppcr26",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x68));
	DECLARE("vmmppcr27",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x6C));
	DECLARE("vmmppcr28",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x70));
	DECLARE("vmmppcr29",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x74));

	DECLARE("vmmppcr30",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x78));
	DECLARE("vmmppcr31",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcGPRs+0x7C));
	DECLARE("vmmppccr",				offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcCR));
	DECLARE("vmmppcxer",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcXER));
	DECLARE("vmmppclr",				offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcLR));
	DECLARE("vmmppcctr",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcCTR));
	DECLARE("vmmppcmq",				offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcMQ));
	DECLARE("vmmppcvrsave",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs32.ppcVRSave));	

	DECLARE("vmmppcXpc",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcPC));
	DECLARE("vmmppcXmsr",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcMSR));
	DECLARE("vmmppcXr0",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0x00));
	DECLARE("vmmppcXr1",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0x08));
	DECLARE("vmmppcXr2",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0x10));
	DECLARE("vmmppcXr3",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0x18));
	DECLARE("vmmppcXr4",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0x20));
	DECLARE("vmmppcXr5",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0x28));

	DECLARE("vmmppcXr6",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0x30));
	DECLARE("vmmppcXr7",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0x38));
	DECLARE("vmmppcXr8",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0x40));
	DECLARE("vmmppcXr9",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0x48));
	DECLARE("vmmppcXr10",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0x50));
	DECLARE("vmmppcXr11",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0x58));
	DECLARE("vmmppcXr12",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0x60));
	DECLARE("vmmppcXr13",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0x68));

	DECLARE("vmmppcXr14",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0x70));
	DECLARE("vmmppcXr15",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0x78));
	DECLARE("vmmppcXr16",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0x80));
	DECLARE("vmmppcXr17",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0x88));
	DECLARE("vmmppcXr18",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0x90));
	DECLARE("vmmppcXr19",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0x98));
	DECLARE("vmmppcXr20",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0xA0));
	DECLARE("vmmppcXr21",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0xA8));

	DECLARE("vmmppcXr22",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0xB0));
	DECLARE("vmmppcXr23",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0xB8));
	DECLARE("vmmppcXr24",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0xC0));
	DECLARE("vmmppcXr25",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0xC8));
	DECLARE("vmmppcXr26",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0xD0));
	DECLARE("vmmppcXr27",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0xD8));
	DECLARE("vmmppcXr28",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0xE0));
	DECLARE("vmmppcXr29",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0xE8));

	DECLARE("vmmppcXr30",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0xF0));
	DECLARE("vmmppcXr31",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcGPRs+0xF8));
	DECLARE("vmmppcXcr",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcCR));
	DECLARE("vmmppcXxer",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcXER));
	DECLARE("vmmppcXlr",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcLR));
	DECLARE("vmmppcXctr",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcCTR));
	DECLARE("vmmppcXvrsave",		offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcRegs.ppcRegs64.ppcVRSave));	

	DECLARE("vmmppcvscr",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcVSCR+0x00));	
	DECLARE("vmmppcfpscrpad",		offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcFPSCR));
	DECLARE("vmmppcfpscr",			offsetof(struct vmm_state_page_t *, vmm_proc_state.ppcFPSCR+4));

	DECLARE("famguestr0",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs32.guest_register));
	DECLARE("famguestr1",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs32.guest_register+0x4));
	DECLARE("famguestr2",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs32.guest_register+0x8));
	DECLARE("famguestr3",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs32.guest_register+0xC));
	DECLARE("famguestr4",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs32.guest_register+0x10));
	DECLARE("famguestr5",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs32.guest_register+0x14));
	DECLARE("famguestr6",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs32.guest_register+0x18));
	DECLARE("famguestr7",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs32.guest_register+0x1C));
	DECLARE("famguestpc",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs32.guest_pc));
	DECLARE("famguestmsr",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs32.guest_msr));
	DECLARE("famdispcode",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs32.fastassist_dispatch_code));
	DECLARE("famrefcon",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs32.fastassist_refcon));
	DECLARE("famparam",				offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs32.fastassist_parameter));
	DECLARE("famhandler",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs32.fastassist_dispatch));
	DECLARE("famintercepts",		offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs32.fastassist_intercepts));

	DECLARE("famguestXr0",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs64.guest_register));
	DECLARE("famguestXr1",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs64.guest_register+0x8));
	DECLARE("famguestXr2",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs64.guest_register+0x10));
	DECLARE("famguestXr3",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs64.guest_register+0x18));
	DECLARE("famguestXr4",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs64.guest_register+0x20));
	DECLARE("famguestXr5",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs64.guest_register+0x28));
	DECLARE("famguestXr6",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs64.guest_register+0x30));
	DECLARE("famguestXr7",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs64.guest_register+0x38));
	DECLARE("famguestXpc",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs64.guest_pc));
	DECLARE("famguestXmsr",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs64.guest_msr));
	DECLARE("famdispcodeX",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs64.fastassist_dispatch_code));
	DECLARE("famrefconX",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs64.fastassist_refcon));
	DECLARE("famparamX",				offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs64.fastassist_parameter));
	DECLARE("famhandlerX",			offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs64.fastassist_dispatch));
	DECLARE("faminterceptsX",		offsetof(struct vmm_state_page_t *, vmm_fastassist_state.vmmfs64.fastassist_intercepts));

	DECLARE("vmmFloatCngd",			vmmFloatCngd);
	DECLARE("vmmFloatCngdb",		vmmFloatCngdb);
	DECLARE("vmmVectCngd",			vmmVectCngd);
	DECLARE("vmmVectCngdb",			vmmVectCngdb);
	DECLARE("vmmTimerPop",			vmmTimerPop);
	DECLARE("vmmTimerPopb",			vmmTimerPopb);
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
	DECLARE("vmmXStop",				vmmXStop);
	DECLARE("vmmXStopb",			vmmXStopb);
	DECLARE("vmmKey",				vmmKey);
	DECLARE("vmmKeyb",				vmmKeyb);
	DECLARE("vmmFamSet",			vmmFamSet);
	DECLARE("vmmFamSetb",			vmmFamSetb);
	DECLARE("vmmFamEna",			vmmFamEna);
	DECLARE("vmmFamEnab",			vmmFamEnab);
	DECLARE("vmm64Bit",				vmm64Bit);

	/* values from kern/task.h */
	DECLARE("TASK_SYSCALLS_MACH",
		offsetof(struct task *, syscalls_mach));
	DECLARE("TASK_SYSCALLS_UNIX",
		offsetof(struct task *, syscalls_unix));

	/* values from vm/vm_map.h */
	DECLARE("VMMAP_PMAP",	offsetof(struct vm_map *, pmap));

	/* values from machine/pmap.h */
	DECLARE("pmapSpace",			offsetof(struct pmap *, space));
	DECLARE("spaceNum",				offsetof(struct pmap *, spaceNum));
	DECLARE("pmapSXlk",				offsetof(struct pmap *, pmapSXlk));
	DECLARE("pmapCCtl",				offsetof(struct pmap *, pmapCCtl));
    DECLARE("pmapCCtlVal",			pmapCCtlVal);
    DECLARE("pmapCCtlLck",			pmapCCtlLck);
    DECLARE("pmapCCtlLckb",			pmapCCtlLckb);
    DECLARE("pmapCCtlGen",			pmapCCtlGen);
    DECLARE("pmapSegCacheCnt",		pmapSegCacheCnt);
    DECLARE("pmapSegCacheUse",		pmapSegCacheUse);
	DECLARE("pmapvr",				offsetof(struct pmap *, pmapvr));
	DECLARE("pmapFlags",			offsetof(struct pmap *, pmapFlags));
    DECLARE("pmapKeys",				pmapKeys);
    DECLARE("pmapKeyDef",			pmapKeyDef);
	DECLARE("pmapSCSubTag",			offsetof(struct pmap *, pmapSCSubTag));
	DECLARE("pmapVmmExt",			offsetof(struct pmap *, pmapVmmExt));
	DECLARE("pmapVmmExtPhys",		offsetof(struct pmap *, pmapVmmExtPhys));
	DECLARE("pmapVMhost",			pmapVMhost);
	DECLARE("pmapVMgsaa",			pmapVMgsaa);
	DECLARE("pmapSegCache",			offsetof(struct pmap *, pmapSegCache));
	DECLARE("pmapCurLists",			offsetof(struct pmap *, pmapCurLists));
	DECLARE("pmapRandNum",			offsetof(struct pmap *, pmapRandNum));
	DECLARE("pmapSkipLists",		offsetof(struct pmap *, pmapSkipLists));
	DECLARE("pmapSearchVisits",		offsetof(struct pmap *, pmapSearchVisits));
	DECLARE("pmapSearchCnt",		offsetof(struct pmap *, pmapSearchCnt));
	DECLARE("pmapSize",				pmapSize);
    DECLARE("kSkipListFanoutShift",	kSkipListFanoutShift);
    DECLARE("kSkipListMaxLists",	kSkipListMaxLists);
    DECLARE("invalSpace",			invalSpace);

	DECLARE("sgcESID",				offsetof(struct sgc *, sgcESID));
	DECLARE("sgcESmsk",				sgcESmsk);
	DECLARE("sgcVSID",				offsetof(struct sgc *, sgcVSID));
	DECLARE("sgcVSmsk",				sgcVSmsk);
	DECLARE("sgcVSKeys",			sgcVSKeys);
	DECLARE("sgcVSKeyUsr",			sgcVSKeyUsr);
	DECLARE("sgcVSNoEx",			sgcVSNoEx);
	DECLARE("pmapPAddr",			offsetof(struct pmapTransTab *, pmapPAddr));
	DECLARE("pmapVAddr",			offsetof(struct pmapTransTab *, pmapVAddr));
	DECLARE("pmapTransSize",		sizeof(pmapTransTab));
	DECLARE("pmapResidentCnt",		offsetof(struct pmap *, stats.resident_count));

	DECLARE("maxAdrSp",				maxAdrSp);
	DECLARE("maxAdrSpb",			maxAdrSpb);
	
	DECLARE("cppvPsnkb",			cppvPsnkb);
	DECLARE("cppvPsrcb",			cppvPsrcb);
	DECLARE("cppvFsnkb",			cppvFsnkb);
	DECLARE("cppvFsrcb",			cppvFsrcb);
	DECLARE("cppvNoModSnkb",		cppvNoModSnkb);
	DECLARE("cppvNoRefSrcb",		cppvNoRefSrcb);
	DECLARE("cppvKmapb",			cppvKmapb);
	
	DECLARE("vmxSalt",				offsetof(struct pmap_vmm_ext *, vmxSalt));
	DECLARE("vmxHostPmapPhys",		offsetof(struct pmap_vmm_ext *, vmxHostPmapPhys));
	DECLARE("vmxHostPmap",			offsetof(struct pmap_vmm_ext *,	vmxHostPmap));
	DECLARE("vmxHashPgIdx",			offsetof(struct pmap_vmm_ext *, vmxHashPgIdx));
	DECLARE("vmxHashPgList",		offsetof(struct pmap_vmm_ext *, vmxHashPgList));
	DECLARE("vmxStats",				offsetof(struct pmap_vmm_ext *, vmxStats));
	DECLARE("vmxSize",				sizeof(struct pmap_vmm_ext));
	DECLARE("VMX_HPIDX_OFFSET",		VMX_HPIDX_OFFSET);
	DECLARE("VMX_HPLIST_OFFSET",	VMX_HPLIST_OFFSET);
	DECLARE("VMX_ACTMAP_OFFSET",	VMX_ACTMAP_OFFSET);
	DECLARE("vxsGpf",				offsetof(struct pmap_vmm_ext *, vmxStats.vxsGpf));
	DECLARE("vxsGpfMiss",			offsetof(struct pmap_vmm_ext *, vmxStats.vxsGpfMiss));
	DECLARE("vxsGrm",				offsetof(struct pmap_vmm_ext *, vmxStats.vxsGrm));
	DECLARE("vxsGrmMiss",			offsetof(struct pmap_vmm_ext *, vmxStats.vxsGrmMiss));
	DECLARE("vxsGrmActive",			offsetof(struct pmap_vmm_ext *, vmxStats.vxsGrmActive));
	DECLARE("vxsGra",				offsetof(struct pmap_vmm_ext *, vmxStats.vxsGra));
	DECLARE("vxsGraHits",			offsetof(struct pmap_vmm_ext *, vmxStats.vxsGraHits));
	DECLARE("vxsGraActive",			offsetof(struct pmap_vmm_ext *, vmxStats.vxsGraActive));
	DECLARE("vxsGrl",				offsetof(struct pmap_vmm_ext *, vmxStats.vxsGrl));
	DECLARE("vxsGrlActive",			offsetof(struct pmap_vmm_ext *, vmxStats.vxsGrlActive));
	DECLARE("vxsGrs",				offsetof(struct pmap_vmm_ext *, vmxStats.vxsGrs));
	DECLARE("vxsGrsHitAct",			offsetof(struct pmap_vmm_ext *, vmxStats.vxsGrsHitAct));
	DECLARE("vxsGrsHitSusp",		offsetof(struct pmap_vmm_ext *, vmxStats.vxsGrsHitSusp));
	DECLARE("vxsGrsMissGV",			offsetof(struct pmap_vmm_ext *, vmxStats.vxsGrsMissGV));
	DECLARE("vxsGrsHitPE",			offsetof(struct pmap_vmm_ext *, vmxStats.vxsGrsHitPE));
	DECLARE("vxsGrsMissPE",			offsetof(struct pmap_vmm_ext *, vmxStats.vxsGrsMissPE));
	DECLARE("vxsGad",				offsetof(struct pmap_vmm_ext *, vmxStats.vxsGad));
	DECLARE("vxsGadHit",			offsetof(struct pmap_vmm_ext *, vmxStats.vxsGadHit));
	DECLARE("vxsGadFree",			offsetof(struct pmap_vmm_ext *, vmxStats.vxsGadFree));
	DECLARE("vxsGadDormant",		offsetof(struct pmap_vmm_ext *, vmxStats.vxsGadDormant));
	DECLARE("vxsGadSteal",			offsetof(struct pmap_vmm_ext *, vmxStats.vxsGadSteal));
	DECLARE("vxsGsu",				offsetof(struct pmap_vmm_ext *, vmxStats.vxsGsu));
	DECLARE("vxsGsuHit",			offsetof(struct pmap_vmm_ext *, vmxStats.vxsGsuHit));
	DECLARE("vxsGsuMiss",			offsetof(struct pmap_vmm_ext *, vmxStats.vxsGsuMiss));
	DECLARE("vxsGtd",				offsetof(struct pmap_vmm_ext *, vmxStats.vxsGtd));
	DECLARE("vxsGtdHit",			offsetof(struct pmap_vmm_ext *, vmxStats.vxsGtdHit));
	DECLARE("vxsGtdMiss",			offsetof(struct pmap_vmm_ext *, vmxStats.vxsGtdMiss));

	/* values from kern/timer.h */
	DECLARE("TIMER_LOW",		offsetof(struct timer *, low_bits));
	DECLARE("TIMER_HIGH",		offsetof(struct timer *, high_bits));
	DECLARE("TIMER_HIGHCHK",	offsetof(struct timer *, high_bits_check));
	DECLARE("TIMER_TSTAMP",		offsetof(struct timer *, tstamp));

	DECLARE("CURRENT_TIMER",	offsetof(struct processor *, processor_data.current_timer));
	DECLARE("SYSTEM_TIMER",		offsetof(struct thread *, system_timer));
	DECLARE("USER_TIMER",		offsetof(struct thread *, user_timer));

	/* Constants from pmap.h */
	DECLARE("PPC_SID_KERNEL", PPC_SID_KERNEL);

	/* values for accessing mach_trap table */
	DECLARE("MACH_TRAP_ARG_MUNGE32",
		offsetof(mach_trap_t *, mach_trap_arg_munge32));
	DECLARE("MACH_TRAP_ARG_MUNGE64",
		offsetof(mach_trap_t *, mach_trap_arg_munge64));
	DECLARE("MACH_TRAP_ARGC",
		offsetof(mach_trap_t *, mach_trap_arg_count));
	DECLARE("MACH_TRAP_FUNCTION",
		offsetof(mach_trap_t *, mach_trap_function));

	DECLARE("MACH_TRAP_TABLE_COUNT", MACH_TRAP_TABLE_COUNT);

	DECLARE("PPCcallmax", sizeof(PPCcalls));

	/* Misc values used by assembler */
	DECLARE("AST_ALL", AST_ALL);
	DECLARE("AST_URGENT", AST_URGENT);

	/* Spin Lock structure */
	DECLARE("SLOCK_ILK",	offsetof(lck_spin_t *, interlock));

	/* Mutex structure */
	DECLARE("MUTEX_DATA",	offsetof(lck_mtx_t *, lck_mtx_data));
	DECLARE("MUTEX_WAITERS",offsetof(lck_mtx_t *, lck_mtx_waiters));
	DECLARE("MUTEX_PROMOTED_PRI",offsetof(lck_mtx_t *, lck_mtx_pri));
	DECLARE("MUTEX_TYPE",	offsetof(lck_mtx_ext_t *, lck_mtx_deb.type));
	DECLARE("MUTEX_STACK",	offsetof(lck_mtx_ext_t *, lck_mtx_deb.stack));
	DECLARE("MUTEX_FRAMES",	LCK_FRAMES_MAX);
	DECLARE("MUTEX_THREAD",	offsetof(lck_mtx_ext_t *, lck_mtx_deb.thread));
	DECLARE("MUTEX_ATTR",	offsetof(lck_mtx_ext_t *, lck_mtx_attr));
	DECLARE("MUTEX_ATTR_DEBUG", LCK_MTX_ATTR_DEBUG);
	DECLARE("MUTEX_ATTR_DEBUGb", LCK_MTX_ATTR_DEBUGb);
	DECLARE("MUTEX_ATTR_STAT", LCK_MTX_ATTR_STAT);
	DECLARE("MUTEX_ATTR_STATb", LCK_MTX_ATTR_STATb);
	DECLARE("MUTEX_GRP",	offsetof(lck_mtx_ext_t *, lck_mtx_grp));
	DECLARE("MUTEX_TAG",	MUTEX_TAG);
	DECLARE("MUTEX_IND",	LCK_MTX_TAG_INDIRECT);
	DECLARE("MUTEX_ITAG",offsetof(lck_mtx_t *, lck_mtx_tag));
	DECLARE("MUTEX_PTR",offsetof(lck_mtx_t *, lck_mtx_ptr));
	DECLARE("MUTEX_ASSERT_OWNED",	LCK_MTX_ASSERT_OWNED);
	DECLARE("MUTEX_ASSERT_NOTOWNED",LCK_MTX_ASSERT_NOTOWNED);
	DECLARE("GRP_MTX_STAT_UTIL",	offsetof(lck_grp_t *, lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_util_cnt));
	DECLARE("GRP_MTX_STAT_MISS",	offsetof(lck_grp_t *, lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_miss_cnt));
	DECLARE("GRP_MTX_STAT_WAIT",	offsetof(lck_grp_t *, lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_wait_cnt));

	/* RW lock structure */
	DECLARE("RW_IND",	LCK_RW_TAG_INDIRECT);
	DECLARE("RW_PTR",	offsetof(lck_rw_t *, lck_rw_ptr));
	DECLARE("RW_SHARED",	LCK_RW_TYPE_SHARED);
	DECLARE("RW_EXCL",	LCK_RW_TYPE_EXCLUSIVE);
	DECLARE("RW_EVENT",	(((sizeof(lck_rw_t)-1))/sizeof(unsigned int))*sizeof(unsigned int));

	/* values from low_trace.h */
	DECLARE("LTR_cpu",	offsetof(struct LowTraceRecord *, LTR_cpu));
	DECLARE("LTR_excpt",	offsetof(struct LowTraceRecord *, LTR_excpt));
	DECLARE("LTR_timeHi",	offsetof(struct LowTraceRecord *, LTR_timeHi));
	DECLARE("LTR_timeLo",	offsetof(struct LowTraceRecord *, LTR_timeLo));
	DECLARE("LTR_cr",	offsetof(struct LowTraceRecord *, LTR_cr));
	DECLARE("LTR_srr0",	offsetof(struct LowTraceRecord *, LTR_srr0));
	DECLARE("LTR_srr1",	offsetof(struct LowTraceRecord *, LTR_srr1));
	DECLARE("LTR_dar",	offsetof(struct LowTraceRecord *, LTR_dar));
	DECLARE("LTR_dsisr",	offsetof(struct LowTraceRecord *, LTR_dsisr));
	DECLARE("LTR_rsvd0",	offsetof(struct LowTraceRecord *, LTR_rsvd0));
	DECLARE("LTR_save",	offsetof(struct LowTraceRecord *, LTR_save));
	DECLARE("LTR_lr",	offsetof(struct LowTraceRecord *, LTR_lr));
	DECLARE("LTR_ctr",	offsetof(struct LowTraceRecord *, LTR_ctr));
	DECLARE("LTR_r0",	offsetof(struct LowTraceRecord *, LTR_r0));
	DECLARE("LTR_r1",	offsetof(struct LowTraceRecord *, LTR_r1));
	DECLARE("LTR_r2",	offsetof(struct LowTraceRecord *, LTR_r2));
	DECLARE("LTR_r3",	offsetof(struct LowTraceRecord *, LTR_r3));
	DECLARE("LTR_r4",	offsetof(struct LowTraceRecord *, LTR_r4));
	DECLARE("LTR_r5",	offsetof(struct LowTraceRecord *, LTR_r5));
	DECLARE("LTR_r6",	offsetof(struct LowTraceRecord *, LTR_r6));
	DECLARE("LTR_size",	sizeof(struct LowTraceRecord));

/*	Values from pexpert.h */
	DECLARE("PECFIcpurate",	offsetof(struct clock_frequency_info_t *, cpu_clock_rate_hz));
	DECLARE("PECFIbusrate",	offsetof(struct clock_frequency_info_t *, bus_clock_rate_hz));

/*	Values from pmap_internals.h and mappings.h */

	DECLARE("mpFlags",		offsetof(struct mapping *, mpFlags));
	DECLARE("mpBusy",		mpBusy);
	DECLARE("mpPrevious",	mpPrevious);
	DECLARE("mpNext",		mpNext);
	DECLARE("mpPIndex",		mpPIndex);
	DECLARE("mpType",		mpType);
	DECLARE("mpNormal",		mpNormal);
	DECLARE("mpBlock",		mpBlock);
	DECLARE("mpMinSpecial",	mpMinSpecial);
	DECLARE("mpNest",		mpNest);
	DECLARE("mpLinkage",	mpLinkage);
	DECLARE("mpACID",		mpACID);
	DECLARE("mpGuest",		mpGuest);
	DECLARE("mpFIP",		mpFIP);
	DECLARE("mpFIPb",		mpFIPb);
	DECLARE("mpPcfg",		mpPcfg);
	DECLARE("mpPcfgb",		mpPcfgb);
	DECLARE("mpRIP",		mpRIP);
	DECLARE("mpRIPb",		mpRIPb);
	DECLARE("mpPerm",		mpPerm);
	DECLARE("mpPermb",		mpPermb);
	DECLARE("mpBSu",		mpBSu);
	DECLARE("mpBSub",		mpBSub);
	DECLARE("mpLists",		mpLists);
	DECLARE("mpListsb",		mpListsb);
	DECLARE("mpgFlags",		mpgFlags);
	DECLARE("mpgFree",		mpgFree);
	DECLARE("mpgGlobal",	mpgGlobal);
	DECLARE("mpgDormant",	mpgDormant);

	DECLARE("mpSpace",		offsetof(struct mapping *, mpSpace));
	DECLARE("mpBSize",		offsetof(struct mapping *, u.mpBSize));
	DECLARE("mpgCursor",	offsetof(struct mapping *, u.mpgCursor));
	DECLARE("mpPte",		offsetof(struct mapping *, mpPte));
	DECLARE("mpHValid",		mpHValid);
	DECLARE("mpHValidb",	mpHValidb);

	DECLARE("mpPAddr",		offsetof(struct mapping *, mpPAddr));
	DECLARE("mpVAddr",		offsetof(struct mapping *, mpVAddr));
	DECLARE("mpHWFlags",	mpHWFlags);
	DECLARE("mpHWFlagsb",	mpHWFlagsb);
	DECLARE("mpN",			mpN);
	DECLARE("mpNb",			mpNb);
	DECLARE("mpPP",			mpPP);
	DECLARE("mpPPb",		mpPPb);
	DECLARE("mpPPe",		mpPPe);
	DECLARE("mpKKN",		mpKKN);
	DECLARE("mpKKNb",		mpKKNb);
	DECLARE("mpWIMG",		mpWIMG);
	DECLARE("mpWIMGb",		mpWIMGb);
	DECLARE("mpW",			mpW);
	DECLARE("mpWb",			mpWb);
	DECLARE("mpI",			mpI);
	DECLARE("mpIb",			mpIb);
	DECLARE("mpM",			mpM);
	DECLARE("mpMb",			mpMb);
	DECLARE("mpG",			mpG);
	DECLARE("mpGb",			mpGb);
	DECLARE("mpWIMGe",		mpWIMGe);
	DECLARE("mpC",			mpC);
	DECLARE("mpCb",			mpCb);
	DECLARE("mpR",			mpR);
	DECLARE("mpRb",			mpRb);
	DECLARE("mpAlias",		offsetof(struct mapping *, mpAlias));
	DECLARE("mpNestReloc",	offsetof(struct mapping *, mpNestReloc));	
	DECLARE("mpBlkRemCur",	offsetof(struct mapping *, mpBlkRemCur));	
	DECLARE("mpList0",		offsetof(struct mapping *, mpList0));
	DECLARE("mpList	",		offsetof(struct mapping *, mpList));
	DECLARE("mpBasicSize",	mpBasicSize);
	DECLARE("mpBasicLists",	mpBasicLists);

	DECLARE("mbvrswap",		offsetof(struct mappingblok *, mapblokvrswap));
	DECLARE("mbfree",		offsetof(struct mappingblok *, mapblokfree));
	DECLARE("mapcsize",		sizeof(struct mappingctl));
	
	DECLARE("hwpPurgePTE",	hwpPurgePTE);
	DECLARE("hwpMergePTE",	hwpMergePTE);
	DECLARE("hwpNoopPTE",	hwpNoopPTE);

// DANGER WIL ROBINSON!!! This wonderfully magical tool doesn't seem to handle 64-bit constants,
// leaving us with only the cold ash of a zero. ppI, ppG, and who knows what else is affected.
	DECLARE("ppLink",		offsetof(struct phys_entry *, ppLink));
	DECLARE("ppLock",		ppLock);
	DECLARE("ppFlags",		ppFlags);
//	DECLARE("ppI",			ppI);
	DECLARE("ppIb",			ppIb);
//	DECLARE("ppG",			ppG);
	DECLARE("ppGb",			ppGb);
	DECLARE("ppR",			ppR);
	DECLARE("ppRb",			ppRb);
	DECLARE("ppC",			ppC);
	DECLARE("ppCb",			ppCb);
	DECLARE("physEntrySize",physEntrySize);
	DECLARE("ppLFAmask",	ppLFAmask);
	DECLARE("ppLFArrot",	ppLFArrot);

	DECLARE("pcfFlags",		offsetof(struct pcfg *, pcfFlags));
	DECLARE("pcfEncode",	offsetof(struct pcfg *, pcfEncode));
	DECLARE("pcfPSize",		offsetof(struct pcfg *, pcfPSize));
	DECLARE("pcfShift",		offsetof(struct pcfg *, pcfShift));
	DECLARE("pcfValid",		pcfValid);
	DECLARE("pcfLarge",		pcfLarge);
	DECLARE("pcfDedSeg",	pcfDedSeg);
	DECLARE("pcfSize",		sizeof(struct pcfg));
	DECLARE("pcfDefPcfg",	pcfDefPcfg);
	DECLARE("pcfLargePcfg",	pcfLargePcfg);

	DECLARE("PCAallo",		offsetof(struct PCA *, flgs.PCAallo));
	DECLARE("PCAfree",		offsetof(struct PCA *, flgs.PCAalflgs.PCAfree));
	DECLARE("PCAauto",		offsetof(struct PCA *, flgs.PCAalflgs.PCAauto));
	DECLARE("PCAmisc",		offsetof(struct PCA *, flgs.PCAalflgs.PCAmisc));
	DECLARE("PCAlock",		PCAlock);
	DECLARE("PCAlockb",		PCAlockb);
	DECLARE("PCAsteal",		offsetof(struct PCA *, flgs.PCAalflgs.PCAsteal));

	DECLARE("mrPhysTab",	offsetof(struct mem_region *, mrPhysTab));
	DECLARE("mrStart",		offsetof(struct mem_region *, mrStart));
	DECLARE("mrEnd",		offsetof(struct mem_region *, mrEnd));
	DECLARE("mrAStart",		offsetof(struct mem_region *, mrAStart));
	DECLARE("mrAEnd",		offsetof(struct mem_region *, mrAEnd));
	DECLARE("mrSize",		sizeof(struct mem_region));

	DECLARE("mapRemChunk",	mapRemChunk);

	DECLARE("mapRetCode",	mapRetCode);
	DECLARE("mapRtOK",		mapRtOK);
	DECLARE("mapRtBadLk",	mapRtBadLk);
	DECLARE("mapRtPerm",	mapRtPerm);
	DECLARE("mapRtNotFnd",	mapRtNotFnd);
	DECLARE("mapRtBlock",	mapRtBlock);
	DECLARE("mapRtNest",	mapRtNest);
	DECLARE("mapRtRemove",	mapRtRemove);
	DECLARE("mapRtMapDup",	mapRtMapDup);
	DECLARE("mapRtGuest",	mapRtGuest);
	DECLARE("mapRtEmpty",	mapRtEmpty);
	DECLARE("mapRtSmash",	mapRtSmash);

#if 0
	DECLARE("MFpcaptr",		offsetof(struct mappingflush *, pcaptr));
	DECLARE("MFmappingcnt",		offsetof(struct mappingflush *, mappingcnt));
	DECLARE("MFmapping",		offsetof(struct mappingflush *, mapping));
	DECLARE("MFmappingSize", 	sizeof(struct mfmapping));
#endif

	DECLARE("GV_GROUPS_LG2",	GV_GROUPS_LG2);
	DECLARE("GV_GROUPS",		GV_GROUPS);
	DECLARE("GV_SLOT_SZ_LG2",	GV_SLOT_SZ_LG2);
	DECLARE("GV_SLOT_SZ",		GV_SLOT_SZ);
	DECLARE("GV_SLOTS_LG2",		GV_SLOTS_LG2);
	DECLARE("GV_SLOTS",			GV_SLOTS);
	DECLARE("GV_PGIDX_SZ_LG2",	GV_PGIDX_SZ_LG2);
	DECLARE("GV_PAGE_SZ_LG2",	GV_PAGE_SZ_LG2);
	DECLARE("GV_PAGE_SZ",		GV_PAGE_SZ);
	DECLARE("GV_PAGE_MASK",		GV_PAGE_MASK);
	DECLARE("GV_HPAGES",		GV_HPAGES);
	DECLARE("GV_GRPS_PPG_LG2",	GV_GRPS_PPG_LG2);
	DECLARE("GV_GRPS_PPG",		GV_GRPS_PPG);
	DECLARE("GV_GRP_MASK",		GV_GRP_MASK);
	DECLARE("GV_SLOT_MASK",		GV_SLOT_MASK);
	DECLARE("GV_HPAGE_SHIFT",	GV_HPAGE_SHIFT);
	DECLARE("GV_HPAGE_MASK",	GV_HPAGE_MASK);
	DECLARE("GV_HGRP_SHIFT",	GV_HGRP_SHIFT);
	DECLARE("GV_HGRP_MASK",		GV_HGRP_MASK);
	DECLARE("GV_MAPWD_BITS_LG2",GV_MAPWD_BITS_LG2);
	DECLARE("GV_MAPWD_SZ_LG2",	GV_MAPWD_SZ_LG2);
	DECLARE("GV_MAP_WORDS",		GV_MAP_WORDS);
	DECLARE("GV_MAP_MASK",		GV_MAP_MASK);
	DECLARE("GV_MAP_SHIFT",		GV_MAP_SHIFT);
	DECLARE("GV_BAND_SHIFT",	GV_BAND_SHIFT);
	DECLARE("GV_BAND_SZ_LG2",	GV_BAND_SZ_LG2);
	DECLARE("GV_BAND_MASK",		GV_BAND_MASK);

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
	DECLARE("enaNotifyEM",	enaNotifyEM);
	DECLARE("enaNotifyEMb",	enaNotifyEMb);
	DECLARE("disLkType",	disLkType);
	DECLARE("disLktypeb",	disLktypeb);
	DECLARE("disLkThread",	disLkThread);
	DECLARE("disLkThreadb",	disLkThreadb);
	DECLARE("enaLkExtStck",	enaLkExtStck);
	DECLARE("enaLkExtStckb",enaLkExtStckb);
	DECLARE("disLkMyLck",	disLkMyLck);
	DECLARE("disLkMyLckb",	disLkMyLckb);
	DECLARE("dgMisc1",		offsetof(struct diagWork *, dgMisc1));
	DECLARE("dgMisc2",		offsetof(struct diagWork *, dgMisc2));
	DECLARE("dgMisc3",		offsetof(struct diagWork *, dgMisc3));
	DECLARE("dgMisc4",		offsetof(struct diagWork *, dgMisc4));
	DECLARE("dgMisc5",		offsetof(struct diagWork *, dgMisc5));

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
	DECLARE("savemisc0",	offsetof(struct savearea_comm *, save_misc0));
	DECLARE("savemisc1",	offsetof(struct savearea_comm *, save_misc1));
	DECLARE("savemisc2",	offsetof(struct savearea_comm *, save_misc2));
	DECLARE("savemisc3",	offsetof(struct savearea_comm *, save_misc3));

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

	DECLARE("savemmcr0",	offsetof(struct savearea *, save_mmcr0));
	DECLARE("savemmcr1",	offsetof(struct savearea *, save_mmcr1));
	DECLARE("savemmcr2",	offsetof(struct savearea *, save_mmcr2));
	DECLARE("savepmc",		offsetof(struct savearea *, save_pmc));
	
	DECLARE("saveinstr",	offsetof(struct savearea *, save_instr));

	DECLARE("savexdat0",	offsetof(struct savearea *, save_xdat0));
	DECLARE("savexdat1",	offsetof(struct savearea *, save_xdat1));
	DECLARE("savexdat2",	offsetof(struct savearea *, save_xdat2));
	DECLARE("savexdat3",	offsetof(struct savearea *, save_xdat3));
	
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
	DECLARE("CPU_SUBTYPE_POWERPC_750",		CPU_SUBTYPE_POWERPC_750);
	DECLARE("CPU_SUBTYPE_POWERPC_7400",		CPU_SUBTYPE_POWERPC_7400);
	DECLARE("CPU_SUBTYPE_POWERPC_7450",		CPU_SUBTYPE_POWERPC_7450);
	DECLARE("CPU_SUBTYPE_POWERPC_970",		CPU_SUBTYPE_POWERPC_970);

	DECLARE("shdIBAT",	offsetof(struct shadowBAT *, IBATs));	
	DECLARE("shdDBAT",	offsetof(struct shadowBAT *, DBATs));	
	
	/* Low Memory Globals */

	DECLARE("lgVerCode", 			offsetof(struct lowglo *, lgVerCode));
	DECLARE("lgPPStart", 			offsetof(struct lowglo *, lgPPStart));
	DECLARE("maxDec", 				offsetof(struct lowglo *, lgMaxDec));
	DECLARE("mckFlags", 			offsetof(struct lowglo *, lgMckFlags));
	DECLARE("lgPMWvaddr",			offsetof(struct lowglo *, lgPMWvaddr));
	DECLARE("lgUMWvaddr",			offsetof(struct lowglo *, lgUMWvaddr));
	DECLARE("trcWork", 				offsetof(struct lowglo *, lgTrcWork));
	DECLARE("traceMask",			offsetof(struct lowglo *, lgTrcWork.traceMask));
	DECLARE("traceCurr",			offsetof(struct lowglo *, lgTrcWork.traceCurr));
	DECLARE("traceStart",			offsetof(struct lowglo *, lgTrcWork.traceStart));
	DECLARE("traceEnd",				offsetof(struct lowglo *, lgTrcWork.traceEnd));
	DECLARE("traceMsnd",			offsetof(struct lowglo *, lgTrcWork.traceMsnd));

	DECLARE("Zero", 				offsetof(struct lowglo *, lgZero));
	DECLARE("saveanchor", 			offsetof(struct lowglo *, lgSaveanchor));

	DECLARE("SVlock",				offsetof(struct lowglo *, lgSaveanchor.savelock));
	DECLARE("SVpoolfwd",			offsetof(struct lowglo *, lgSaveanchor.savepoolfwd));
	DECLARE("SVpoolbwd",			offsetof(struct lowglo *, lgSaveanchor.savepoolbwd));
	DECLARE("SVfree",				offsetof(struct lowglo *, lgSaveanchor.savefree));
	DECLARE("SVfreecnt",			offsetof(struct lowglo *, lgSaveanchor.savefreecnt));
	DECLARE("SVadjust",				offsetof(struct lowglo *, lgSaveanchor.saveadjust));
	DECLARE("SVinuse",				offsetof(struct lowglo *, lgSaveanchor.saveinuse));
	DECLARE("SVtarget",				offsetof(struct lowglo *, lgSaveanchor.savetarget));
	DECLARE("SVsaveinusesnapshot",		offsetof(struct lowglo *, lgSaveanchor.saveinusesnapshot));
	DECLARE("SVsavefreesnapshot",		offsetof(struct lowglo *, lgSaveanchor.savefreesnapshot));
	DECLARE("SVsize",				sizeof(struct Saveanchor));

	DECLARE("tlbieLock", 			offsetof(struct lowglo *, lgTlbieLck));

	DECLARE("dgFlags",				offsetof(struct lowglo *, lgdgWork.dgFlags));
	DECLARE("dgLock",				offsetof(struct lowglo *, lgdgWork.dgLock));
	DECLARE("dgMisc0",				offsetof(struct lowglo *, lgdgWork.dgMisc0));
	
	DECLARE("lglcksWork",			offsetof(struct lowglo *, lglcksWork));
	DECLARE("lgKillResv",			offsetof(struct lowglo *, lgKillResv));
	DECLARE("lgpPcfg",				offsetof(struct lowglo *, lgpPcfg));


	DECLARE("scomcpu",				offsetof(struct scomcomm *, scomcpu));
	DECLARE("scomfunc",				offsetof(struct scomcomm *, scomfunc));
	DECLARE("scomreg",				offsetof(struct scomcomm *, scomreg));
	DECLARE("scomstat",				offsetof(struct scomcomm *, scomstat));
	DECLARE("scomdata",				offsetof(struct scomcomm *, scomdata));

	return(0);  /* For ANSI C :-) */
}
