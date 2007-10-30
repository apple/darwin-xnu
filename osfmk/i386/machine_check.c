/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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

#include <i386/cpu_data.h>
#include <i386/cpuid.h>
#include <i386/machine_check.h>
#include <i386/proc_reg.h>

#define IF(bool,str)	((bool) ? (str) : "")

static boolean_t	mca_initialized = FALSE;
static boolean_t	mca_MCE_present = FALSE;
static boolean_t	mca_MCA_present = FALSE;
static unsigned int	mca_error_bank_count = 0;
static boolean_t	mca_control_MSR_present = FALSE;
static boolean_t	mca_threshold_status_present = FALSE;
static boolean_t	mca_extended_MSRs_present = FALSE;
static unsigned int	mca_extended_MSRs_count = 0;
static ia32_mcg_cap_t	ia32_mcg_cap;

static void
mca_get_availability(void)
{
	uint64_t	features = cpuid_info()->cpuid_features;
	uint32_t	family =  cpuid_info()->cpuid_family;

	mca_MCE_present = (features & CPUID_FEATURE_MCE) != 0;
	mca_MCA_present = (features & CPUID_FEATURE_MCA) != 0;
	
	/*
	 * If MCA, the number of banks etc is reported by the IA32_MCG_CAP MSR.
	 */
	if (mca_MCA_present) {
		ia32_mcg_cap.u64 = rdmsr64(IA32_MCG_CAP);
		mca_error_bank_count = ia32_mcg_cap.bits.count;
		mca_control_MSR_present = ia32_mcg_cap.bits.mcg_ctl_p;
		mca_threshold_status_present = ia32_mcg_cap.bits.mcg_tes_p;
		if (family == 0x0F) {
			mca_extended_MSRs_present = ia32_mcg_cap.bits.mcg_ext_p;
			mca_extended_MSRs_count = ia32_mcg_cap.bits.mcg_ext_cnt;
		}
	}
}

void
mca_cpu_init(void)
{
	unsigned int	i;

	/*
	 * The first (boot) processor is responsible for discovering the
	 * machine check architecture present on this machine.
	 */
	if (!mca_initialized) {
		mca_get_availability();
		mca_initialized = TRUE;
	}

	if (mca_MCA_present) {

		/* Enable all MCA features */
		if (mca_control_MSR_present)
			wrmsr64(IA32_MCG_CTL, IA32_MCG_CTL_ENABLE);
	
		switch (cpuid_family()) {
		case 0x06:
			/* Enable all but mc0 */
			for (i = 1; i < mca_error_bank_count; i++)
				wrmsr64(IA32_MCi_CTL(i),0xFFFFFFFFFFFFFFFFULL); 
			
			/* Clear all errors */
			for (i = 0; i < mca_error_bank_count; i++)
				wrmsr64(IA32_MCi_STATUS(i), 0ULL);
			break;
		case 0x0F:
			/* Enable all banks */
			for (i = 0; i < mca_error_bank_count; i++)
				wrmsr64(IA32_MCi_CTL(i),0xFFFFFFFFFFFFFFFFULL); 
			
			/* Clear all errors */
			for (i = 0; i < mca_error_bank_count; i++)
				wrmsr64(IA32_MCi_STATUS(i), 0ULL);
			break;
		}
	}

	/* Enable machine check exception handling if available */
	if (mca_MCE_present) {
		set_cr4(get_cr4()|CR4_MCE);
	}
}

static void mca_dump_64bit_state(void)
{
	kdb_printf("Extended Machine Check State:\n");
	kdb_printf("  IA32_MCG_RAX:    0x%016qx\n", rdmsr64(IA32_MCG_RAX));
	kdb_printf("  IA32_MCG_RBX:    0x%016qx\n", rdmsr64(IA32_MCG_RBX));
	kdb_printf("  IA32_MCG_RCX:    0x%016qx\n", rdmsr64(IA32_MCG_RCX));
	kdb_printf("  IA32_MCG_RDX:    0x%016qx\n", rdmsr64(IA32_MCG_RDX));
	kdb_printf("  IA32_MCG_RSI:    0x%016qx\n", rdmsr64(IA32_MCG_RSI));
	kdb_printf("  IA32_MCG_RDI:    0x%016qx\n", rdmsr64(IA32_MCG_RDI));
	kdb_printf("  IA32_MCG_RBP:    0x%016qx\n", rdmsr64(IA32_MCG_RBP));
	kdb_printf("  IA32_MCG_RSP:    0x%016qx\n", rdmsr64(IA32_MCG_RSP));
	kdb_printf("  IA32_MCG_RFLAGS: 0x%016qx\n", rdmsr64(IA32_MCG_RFLAGS));
	kdb_printf("  IA32_MCG_RIP:    0x%016qx\n", rdmsr64(IA32_MCG_RIP));
	kdb_printf("  IA32_MCG_MISC:   0x%016qx\n", rdmsr64(IA32_MCG_MISC));
	kdb_printf("  IA32_MCG_R8:     0x%016qx\n", rdmsr64(IA32_MCG_R8));
	kdb_printf("  IA32_MCG_R9:     0x%016qx\n", rdmsr64(IA32_MCG_R9));
	kdb_printf("  IA32_MCG_R10:    0x%016qx\n", rdmsr64(IA32_MCG_R10));
	kdb_printf("  IA32_MCG_R11:    0x%016qx\n", rdmsr64(IA32_MCG_R11));
	kdb_printf("  IA32_MCG_R12:    0x%016qx\n", rdmsr64(IA32_MCG_R12));
	kdb_printf("  IA32_MCG_R13:    0x%016qx\n", rdmsr64(IA32_MCG_R13));
	kdb_printf("  IA32_MCG_R14:    0x%016qx\n", rdmsr64(IA32_MCG_R14));
	kdb_printf("  IA32_MCG_R15:    0x%016qx\n", rdmsr64(IA32_MCG_R15));
}

static uint32_t rdmsr32(uint32_t msr)
{
	return (uint32_t) rdmsr64(msr);
}

static void mca_dump_32bit_state(void)
{
	kdb_printf("Extended Machine Check State:\n");
	kdb_printf("  IA32_MCG_EAX:    0x%08x\n", rdmsr32(IA32_MCG_EAX));
	kdb_printf("  IA32_MCG_EBX:    0x%08x\n", rdmsr32(IA32_MCG_EBX));
	kdb_printf("  IA32_MCG_ECX:    0x%08x\n", rdmsr32(IA32_MCG_ECX));
	kdb_printf("  IA32_MCG_EDX:    0x%08x\n", rdmsr32(IA32_MCG_EDX));
	kdb_printf("  IA32_MCG_ESI:    0x%08x\n", rdmsr32(IA32_MCG_ESI));
	kdb_printf("  IA32_MCG_EDI:    0x%08x\n", rdmsr32(IA32_MCG_EDI));
	kdb_printf("  IA32_MCG_EBP:    0x%08x\n", rdmsr32(IA32_MCG_EBP));
	kdb_printf("  IA32_MCG_ESP:    0x%08x\n", rdmsr32(IA32_MCG_ESP));
	kdb_printf("  IA32_MCG_EFLAGS: 0x%08x\n", rdmsr32(IA32_MCG_EFLAGS));
	kdb_printf("  IA32_MCG_EIP:    0x%08x\n", rdmsr32(IA32_MCG_EIP));
	kdb_printf("  IA32_MCG_MISC:   0x%08x\n", rdmsr32(IA32_MCG_MISC));
}

static const char *mca_threshold_status[] = {
	[THRESHOLD_STATUS_NO_TRACKING]	"No tracking",
	[THRESHOLD_STATUS_GREEN]	"Green",
	[THRESHOLD_STATUS_YELLOW]	"Yellow",
	[THRESHOLD_STATUS_RESERVED]	"Reserved"
};

static void
mca_dump_error_banks(void)
{
	unsigned int 		i;
	ia32_mci_status_t	status;

	kdb_printf("MCA error-reporting registers:\n");
	for (i = 0; i < mca_error_bank_count; i++ ) {
		status.u64 = rdmsr64(IA32_MCi_STATUS(i));
		kdb_printf(
			" IA32_MC%d_STATUS(0x%x): 0x%016qx %svalid\n",
			i, IA32_MCi_STATUS(i), status.u64,
			IF(!status.bits.val, "in"));
		if (!status.bits.val)
			continue;
		kdb_printf(
			"  MCA error code           : 0x%04x\n",
			status.bits.mca_error);
		kdb_printf(
			"  Model specific error code: 0x%04x\n",
			status.bits.model_specific_error);
		if (!mca_threshold_status_present) {
			kdb_printf(
				"  Other information        : 0x%08x\n",
				status.bits.other_information);
		} else {
			int	threshold = status.bits_tes_p.threshold;
			kdb_printf(
				"  Other information        : 0x%08x\n"
			        "  Threshold-based status   : %s\n",
				status.bits_tes_p.other_information,
				(status.bits_tes_p.uc == 0) ?
					mca_threshold_status[threshold] :
					"Undefined");
		}
		kdb_printf(
			"  Status bits:\n%s%s%s%s%s%s",
			IF(status.bits.pcc,   "   Processor context corrupt\n"),
			IF(status.bits.addrv, "   ADDR register valid\n"),
			IF(status.bits.miscv, "   MISC register valid\n"),
			IF(status.bits.en,    "   Error enabled\n"),
			IF(status.bits.uc,    "   Uncorrected error\n"),
			IF(status.bits.over,  "   Error overflow\n"));
		if (status.bits.addrv)
			kdb_printf(
				"  IA32_MC%d_ADDR(0x%x): 0x%016qx\n",
				i, IA32_MCi_ADDR(i), rdmsr64(IA32_MCi_ADDR(i)));
		if (status.bits.miscv)
			kdb_printf(
				"  IA32_MC%d_MISC(0x%x): 0x%016qx\n",
				i, IA32_MCi_MISC(i), rdmsr64(IA32_MCi_MISC(i)));
	}
}

void
mca_dump(void)
{
	ia32_mcg_status_t	status;

	/*
	 * Report machine-check capabilities:
	 */
	kdb_printf(
		"Machine-check capabilities 0x%016qx:\n", ia32_mcg_cap.u64);
	kdb_printf(
		" %d error-reporting banks\n%s%s", mca_error_bank_count,
		IF(mca_control_MSR_present,
		   " control MSR present\n"),
		IF(mca_threshold_status_present,
		   " threshold-based error status present\n"));
	if (mca_extended_MSRs_present)
		kdb_printf(
			" %d extended MSRs present\n", mca_extended_MSRs_count);
 
	/*
	 * Report machine-check status:
	 */
	status.u64 = rdmsr64(IA32_MCG_STATUS);
	kdb_printf(
		"Machine-check status 0x%016qx\n%s%s%s", status.u64,
		IF(status.bits.ripv, " restart IP valid\n"),
		IF(status.bits.eipv, " error IP valid\n"),
		IF(status.bits.mcip, " machine-check in progress\n"));

	/*
	 * Dump error-reporting registers:
	 */
	mca_dump_error_banks();

	/*
	 * Dump any extended machine state:
	 */
	if (mca_extended_MSRs_present) {
		if (cpu_mode_is64bit())
			mca_dump_64bit_state();
		else
			mca_dump_32bit_state();
	}
}
