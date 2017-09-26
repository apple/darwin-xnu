/*
 * Copyright (c) 2012-2015 Apple Inc. All rights reserved.
 */

#ifndef _PEXPERT_ARM64_COMMON_H
#define _PEXPERT_ARM64_COMMON_H

#ifdef APPLE_ARM64_ARCH_FAMILY

#define ARM64_REG_HID0						S3_0_c15_c0_0
#define ARM64_REG_HID0_LoopBuffDisb				(1<<20)
#define ARM64_REG_HID0_ICPrefLimitOneBrn			(1<<25)	
#define ARM64_REG_HID0_PMULLFuseDisable				(1ULL<<33)
#define ARM64_REG_HID0_ICPrefDepth_bshift			60
#define ARM64_REG_HID0_ICPrefDepth_bmsk				(7ULL <<ARM64_REG_HID0_ICPrefDepth_bshift)

#define ARM64_REG_EHID0						S3_0_c15_c0_1
#define ARM64_REG_EHID0_nfpRetFwdDisb				(1ULL<<45)

#define ARM64_REG_HID1						S3_0_c15_c1_0
#define ARM64_REG_HID1_disCmpBrFusion				(1<<14)
#define ARM64_REG_HID1_rccDisStallInactiveIexCtl		(1<<24)
#define ARM64_REG_HID1_disLspFlushWithContextSwitch		(1<<25)
#define ARM64_REG_HID1_disAESFuseAcrossGrp			(1<<44)

#define ARM64_REG_HID2						S3_0_c15_c2_0
#define ARM64_REG_HID2_disMMUmtlbPrefetch			(1<<13)

#define ARM64_REG_HID3						S3_0_c15_c3_0
#define ARM64_REG_HID3_DisDcZvaCmdOnly			(1<<25)
#define ARM64_REG_HID3_DisXmonSnpEvictTriggerL2StarvationMode	(1<<54)

#define ARM64_REG_EHID3						S3_0_c15_c3_1
#define ARM64_REG_EHID3_DisDcZvaCmdOnly			(1<<25)

#define ARM64_REG_HID4						S3_0_c15_c4_0
#define ARM64_REG_HID4_DisDcMVAOps				(1<<11)
#define ARM64_REG_HID4_DisSpecLnchRead			(1<<33)
#define ARM64_REG_HID4_ForceNsOrdLdReqNoOlderLd			(1<<39)
#define ARM64_REG_HID4_DisDcSWL2Ops				(1<<44)

#define ARM64_REG_HID5						S3_0_c15_c5_0
#define ARM64_REG_HID5_DisHwpLd					(1<<44)
#define ARM64_REG_HID5_DisHwpSt					(1<<45)
#define ARM64_REG_HID5_DisFullLineWr				(1ULL << 57)
#define ARM64_REG_HID5_CrdEdbSnpRsvd_mask			(3ULL << 14)
#define ARM64_REG_HID5_CrdEdbSnpRsvd_VALUE			(2ULL << 14)

#define ARM64_REG_EHID5						S3_0_c15_c5_1
#define ARM64_REG_EHID5_DisFillByp			(1 << 35)

#define ARM64_REG_HID6						S3_0_c15_c6_0
#define ARM64_REG_HID6_DisClkDivGating				(1ULL << 55)

#define ARM64_REG_HID7						S3_0_c15_c7_0
#define ARM64_REG_HID7_disNexFastFmul				(1 << 10)
#define ARM64_REG_HID7_disCrossPick2				(1ULL << 7)

#define ARM64_REG_HID8						S3_0_c15_c8_0
#define ARM64_REG_HID8_DataSetID0_VALUE				(0xF << 4)
#define ARM64_REG_HID8_DataSetID1_VALUE				(0xF << 8)
#define ARM64_REG_HID8_WkeForceStrictOrder			(0x1ULL << 35)
#define ARM64_REG_HID8_DataSetID2_VALUE				(0xF << 56)
#define ARM64_REG_HID8_DataSetID3_VALUE				(0xF << 60)

#define ARM64_REG_HID9						S3_0_c15_c9_0

#define ARM64_REG_HID10						S3_0_c15_c10_0
#define ARM64_REG_HID10_DisHwpGups				(1ULL << 0)

#if defined(APPLECYCLONE) || defined(APPLETYPHOON) || defined(APPLETWISTER)
#define ARM64_REG_HID11						S3_0_c15_c13_0
#else
#define ARM64_REG_HID11						S3_0_c15_c11_0
#endif
#define ARM64_REG_HID11_DisFillC1BubOpt				(1<<7)
#define ARM64_REG_HID11_DisFastDrainOpt				(1ULL << 23)

#define ARM64_REG_EHID11					S3_0_c15_c11_1
#define ARM64_REG_EHID11_SmbDrainThresh_mask			(3ULL << 40)

#if defined(APPLECYCLONE) || defined(APPLETYPHOON) || defined(APPLETWISTER)
#define ARM64_REG_CYC_CFG					S3_5_c15_c4_0
#define ARM64_REG_CYC_CFG_deepSleep				(1ULL<<24)
#else
#define ARM64_REG_ACC_OVRD					S3_5_c15_c6_0
#define ARM64_REG_ACC_OVRD_enDeepSleep				(1ULL << 34)


#define ARM64_REG_ACC_OVRD_dsblClkDtr				(1ULL << 29)
#define ARM64_REG_ACC_OVRD_cpmWakeUp_mask			(3ULL << 27)
#define ARM64_REG_ACC_OVRD_cpmWakeUp_force			(3ULL << 27)
#define ARM64_REG_ACC_OVRD_ok2PwrDnCPM_mask			(3ULL << 25)
#define ARM64_REG_ACC_OVRD_ok2PwrDnCPM_deny			(2ULL << 25)
#define ARM64_REG_ACC_OVRD_ok2PwrDnCPM_deepsleep		(3ULL << 25)
#define ARM64_REG_ACC_OVRD_ok2TrDnLnk_mask			(3ULL << 17)
#define ARM64_REG_ACC_OVRD_ok2TrDnLnk_deepsleep			(3ULL << 17)
#define ARM64_REG_ACC_OVRD_disL2Flush4AccSlp_mask		(3ULL << 15)
#define ARM64_REG_ACC_OVRD_disL2Flush4AccSlp_deepsleep		(2ULL << 15)
#define ARM64_REG_ACC_OVRD_ok2PwrDnSRM_mask			(3ULL << 13)
#define ARM64_REG_ACC_OVRD_ok2PwrDnSRM_deepsleep		(3ULL << 13)
#endif

#define ARM64_REG_CYC_OVRD					S3_5_c15_c5_0
#define ARM64_REG_CYC_OVRD_ok2pwrdn_force_up			(2<<24)
#define ARM64_REG_CYC_OVRD_ok2pwrdn_force_down			(3<<24)


#define ARM64_REG_LSU_ERR_STS				S3_3_c15_c0_0
#define ARM64_REG_LSU_ERR_STS_L1DTlbMultiHitEN	(1ULL<<54)

#define ARM64_REG_E_LSU_ERR_STS				S3_3_c15_c2_0

#define ARM64_REG_LSU_ERR_CTL				S3_3_c15_c1_0
#define ARM64_REG_LSU_ERR_CTL_L1DTlbMultiHitEN	(1ULL<<3)

#define ARM64_REG_FED_ERR_STS				S3_4_C15_C0_0

#define ARM64_REG_E_FED_ERR_STS				S3_4_C15_C0_2

#define ARM64_REG_MMU_ERR_STS				S3_6_c15_c0_0

#define ARM64_REG_E_MMU_ERR_STS				s3_6_c15_c2_0

#define ARM64_REG_L2C_ERR_STS				S3_3_c15_c8_0

#define ARM64_REG_L2C_ERR_ADR				S3_3_c15_c9_0

#define ARM64_REG_L2C_ERR_INF				S3_3_c15_c10_0

#define ARM64_REG_MIGSTS_EL1				S3_4_c15_c0_4

#if defined(HAS_KTRR)

#ifdef ASSEMBLER
#define ARM64_REG_KTRR_LOWER_EL1                        S3_4_c15_c2_3
#define ARM64_REG_KTRR_UPPER_EL1                        S3_4_c15_c2_4
#define ARM64_REG_KTRR_LOCK_EL1                         S3_4_c15_c2_2
#else
#define ARM64_REG_KTRR_LOWER_EL1                        "S3_4_c15_c2_3"
#define ARM64_REG_KTRR_UPPER_EL1                        "S3_4_c15_c2_4"
#define ARM64_REG_KTRR_LOCK_EL1                         "S3_4_c15_c2_2"
#endif /* ASSEMBLER */

#endif /* defined (HAS_KTRR) */





#endif	/* APPLE_ARM64_ARCH_FAMILY */





#endif /* ! _PEXPERT_ARM_ARM64_H */
