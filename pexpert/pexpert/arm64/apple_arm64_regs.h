/*
 * Copyright (c) 2012-2015 Apple Inc. All rights reserved.
 */

#ifndef _PEXPERT_ARM64_COMMON_H
#define _PEXPERT_ARM64_COMMON_H

#ifdef ASSEMBLER
#define __MSR_STR(x) x
#else
#define __MSR_STR1(x) #x
#define __MSR_STR(x) __MSR_STR1(x)
#endif

#ifdef APPLE_ARM64_ARCH_FAMILY

#define ARM64_REG_HID0_LoopBuffDisb       (1<<20)
#define ARM64_REG_HID0_AMXCacheFusionDisb (1ULL<<21)
#define ARM64_REG_HID0_ICPrefLimitOneBrn  (1<<25)
#define ARM64_REG_HID0_FetchWidthDisb     (1ULL<<28)
#define ARM64_REG_HID0_PMULLFuseDisable   (1ULL<<33)
#define ARM64_REG_HID0_CacheFusionDisable (1ULL<<36)
#define ARM64_REG_HID0_SamePgPwrOpt       (1ULL<<45)
#define ARM64_REG_HID0_ICPrefDepth_bshift 60
#define ARM64_REG_HID0_ICPrefDepth_bmsk   (7ULL <<ARM64_REG_HID0_ICPrefDepth_bshift)
#define ARM64_REG_HID0_ICPrefDepth_VALUE  (1ULL <<ARM64_REG_HID0_ICPrefDepth_bshift)

#define ARM64_REG_EHID0_nfpRetFwdDisb (1ULL<<45)

#define ARM64_REG_HID1_disCmpBrFusion               (1<<14)
#define ARM64_REG_HID1_forceNexL3ClkOn              (1<<15)
#define ARM64_REG_HID1_rccForceAllIexL3ClksOn       (1<<23)
#define ARM64_REG_HID1_rccDisStallInactiveIexCtl    (1<<24)
#define ARM64_REG_HID1_disLspFlushWithContextSwitch (1<<25)
#define ARM64_REG_HID1_disAESFuseAcrossGrp          (1<<44)
#define ARM64_REG_HID1_disMSRSpecDAIF               (1ULL << 49)
#define ARM64_REG_HID1_trapSMC                      (1ULL << 54)
#define ARM64_REG_HID1_enMDSBStallPipeLineECO       (1ULL << 58)
#define ARM64_REG_HID1_enaBrKillLimit               (1ULL << 60)
#define ARM64_REG_HID1_SpareBit6                    (1ULL << 60)

#define ARM64_REG_EHID1_disMSRSpecDAIF              (1ULL << 30)

#define ARM64_REG_HID2_disMMUmtlbPrefetch (1<<13)
#define ARM64_REG_HID2_ForcePurgeMtb      (1<<17)

#define ARM64_REG_EHID2_ForcePurgeMtb     (1<<17)

#define ARM64_REG_HID3_DisColorOpt                            (1<<2)
#define ARM64_REG_HID3_DisDcZvaCmdOnly                        (1<<25)
#define ARM64_REG_HID3_DisArbFixBifCrd                        (1ULL<<44)
#define ARM64_REG_HID3_DisXmonSnpEvictTriggerL2StarvationMode (1<<54)
#define ARM64_REG_HID3_DevPcieThrottleEna                     (1ULL<<63)

#define ARM64_REG_EHID3_DisColorOpt     (1<<2)
#define ARM64_REG_EHID3_DisDcZvaCmdOnly (1<<25)

#define ARM64_REG_HID4_DisDcMVAOps                      (1<<11)
#define ARM64_REG_HID4_DisSpecLnchRead                  (1<<33)
#define ARM64_REG_HID4_ForceNsOrdLdReqNoOlderLd         (1<<39)
#define ARM64_REG_HID4_CnfCntrThresh_shift              (40)
#define ARM64_REG_HID4_CnfCntrThresh_mask               (0x3ULL << ARM64_REG_HID4_CnfCntrThresh_shift)
#define ARM64_REG_HID4_CnfCntrThresh_VALUE              (0x3ULL << ARM64_REG_HID4_CnfCntrThresh_shift)
#define ARM64_REG_HID4_DisDcSWL2Ops                     (1<<44)
#define ARM64_REG_HID4_EnLfsrStallLoadPipe2Issue        (1<<49)
#define ARM64_REG_HID4_EnLfsrStallStqReplay             (1<<53)
#define ARM64_REG_HID4_disSpecLSRedirect                (1<<9)
#define ARM64_REG_HID4_DisSTNTWidget                    (1<<1)

#define ARM64_REG_HID5_DisHwpLd                 (1<<44)
#define ARM64_REG_HID5_DisHwpSt                 (1<<45)
#define ARM64_REG_HID5_DisFill2cMerge           (1ULL << 61)
#define ARM64_REG_HID5_EnableDnFIFORdStall      (1ULL << 54)
#define ARM64_REG_HID5_DisFullLineWr            (1ULL << 57)
#define ARM64_REG_HID5_CrdEdbSnpRsvd_mask       (3ULL << 14)
#define ARM64_REG_HID5_CrdEdbSnpRsvd_VALUE      (2ULL << 14)
#define ARM64_REG_HID5_CrdPrbSnpRsvd_shift      (0)
#define ARM64_REG_HID5_CrdPrbSnpRsvd_mask       (0xFULL << ARM64_REG_HID5_CrdPrbSnpRsvd_shift)
#define ARM64_REG_HID5_CrdPrbSnpRsvd_VALUE(x)   (x << ARM64_REG_HID5_CrdPrbSnpRsvd_shift)

#define ARM64_REG_EHID5_DisFillByp (1 << 35)

#define ARM64_REG_HID6_UpCrdTknInitC2_shift     (5)
#define ARM64_REG_HID6_UpCrdTknInitC2_mask      (0x1FULL << ARM64_REG_HID6_UpCrdTknInitC2_shift)
#define ARM64_REG_HID6_DisClkDivGating          (1ULL << 55)

#define ARM64_REG_HID7_forceNonSpecTargetedTimerSel_shift              (24)
#define ARM64_REG_HID7_forceNonSpecTargetedTimerSel_mask               (3ULL << ARM64_REG_HID7_forceNonSpecTargetedTimerSel_shift)
#define ARM64_REG_HID7_forceNonSpecTargetedTimerSel_VALUE              (3ULL << ARM64_REG_HID7_forceNonSpecTargetedTimerSel_shift)
#define ARM64_REG_HID7_forceNonSpecIfStepping                          (1ULL << 20)
#define ARM64_REG_HID7_forceNonSpecIfSpecFlushPtrNEBlkRtrPtr           (1ULL << 19)
#define ARM64_REG_HID7_forceNonSpecIfSpecFlushPtrInvalidAndMPValid     (1ULL << 16)
#define ARM64_REG_HID7_disNexFastFmul                                  (1 << 10)
#define ARM64_REG_HID7_disCrossPick2                                   (1ULL << 7)

#define ARM64_REG_HID8_DataSetID0_VALUE    (0xF << 4)
#define ARM64_REG_HID8_DataSetID1_VALUE    (0xF << 8)
#define ARM64_REG_HID8_WkeForceStrictOrder (0x1ULL << 35)
#define ARM64_REG_HID8_DataSetID2_VALUE    (0xF << 56)
#define ARM64_REG_HID8_DataSetID3_VALUE    (0xF << 60)

#define ARM64_REG_HID9_TSOAllowDcZvaWC         (1ULL << 26)
#define ARM64_REG_HID9_TSOSerializeVLDmicroops (1ULL << 29)
#define ARM64_REG_HID9_EnableFixBug51667805    (1ULL << 48)
#define ARM64_REG_HID9_EnableFixBug51667717    (1ULL << 49)
#define ARM64_REG_HID9_EnableFixBug57817908    (1ULL << 50)
#define ARM64_REG_HID9_DisSTNTWidgetForUnalign (1ULL << 52)
#define ARM64_REG_HID9_TSO_ENABLE              (1ULL << 16)
#define ARM64_REG_HID9_EnableFixBug47221499    (1ULL << 54)
#define ARM64_REG_HID9_EnableFixBug58566122    (3ULL << 53)
#define ARM64_REG_HID9_HidEnFix55719865        (1ULL << 55)

#define ARM64_REG_EHID9_DevThrottle2Ena        (1ULL << 5)

#define ARM64_REG_HID10_DisHwpGups (1ULL << 0)

#define ARM64_REG_EHID10_rccDisPwrSavePrfClkOff (1ULL << 19)
#define ARM64_REG_EHID10_ForceWStDrainUc        (1ULL << 32)
#define ARM64_REG_EHID10_DisZVATemporalTSO      (1ULL << 49)

#define ARM64_REG_HID11_DisX64NTLnchOpt      (1ULL << 1)
#define ARM64_REG_HID11_DisFillC1BubOpt      (1ULL << 7)
#define ARM64_REG_HID11_HidEnFixUc55719865   (1ULL << 15)
#define ARM64_REG_HID11_DisFastDrainOpt      (1ULL << 23)
#define ARM64_REG_HID11_DisLDNTWidget        (1ULL << 59)

#define ARM64_REG_EHID11_SmbDrainThresh_mask (3ULL << 40)

#define ARM64_REG_HID13_PreCyc_shift         (14)
#define ARM64_REG_HID13_PreCyc_mask          (0xFULL << ARM64_REG_HID13_PreCyc_shift)
#define ARM64_REG_HID13_PreCyc_VALUE         (0x4ULL << ARM64_REG_HID13_PreCyc_shift)

#define ARM64_REG_HID14_NexSleepTimeOutCyc_shift        (0)
#define ARM64_REG_HID14_NexSleepTimeOutCyc_VALUE        0x7D0ULL

#define ARM64_REG_HID16_leqThrottleAggr      (1ULL << 18)
#define ARM64_REG_HID16_SpareBit0            (1ULL << 56)
#define ARM64_REG_HID16_EnRs4Sec             (1ULL << 57)
#define ARM64_REG_HID16_SpareBit3            (1ULL << 59)
#define ARM64_REG_HID16_DisxPickRs45         (1ULL << 60)
#define ARM64_REG_HID16_EnMPxPick45          (1ULL << 61)
#define ARM64_REG_HID16_EnMPCyc7             (1ULL << 62)
#define ARM64_REG_HID16_SpareBit7            (1ULL << 63)

#define ARM64_REG_HID17_CrdEdbSnpRsvd_shift     (0)
#define ARM64_REG_HID17_CrdEdbSnpRsvd_mask      (0x7ULL << ARM64_REG_HID17_CrdEdbSnpRsvd_shift)
#define ARM64_REG_HID17_CrdEdbSnpRsvd_VALUE     (0x2ULL << ARM64_REG_HID17_CrdEdbSnpRsvd_shift)

#define ARM64_REG_HID18_HVCSpecDisable       (1ULL << 14)
#define ARM64_REG_HID18_SpareBit17           (1ULL << 49)

#define ARM64_REG_HID21_EnLdrexFillRply            (1ULL << 19)
#define ARM64_REG_HID21_LdqRtrWaitForOldStRelCmpl  (1ULL << 33)
#define ARM64_REG_HID21_DisCdpRplyPurgedTrans      (1ULL << 34)

#if defined(APPLETYPHOON) || defined(APPLETWISTER)
#define ARM64_REG_CYC_CFG_skipInit     (1ULL<<30)
#define ARM64_REG_CYC_CFG_deepSleep    (1ULL<<24)
#else /* defined(APPLECYCLONE) || defined(APPLETYPHOON) || defined(APPLETWISTER) */
#define ARM64_REG_ACC_OVRD_enDeepSleep                 (1ULL << 34)
#define ARM64_REG_ACC_OVRD_disPioOnWfiCpu              (1ULL << 32)
#define ARM64_REG_ACC_OVRD_dsblClkDtr                  (1ULL << 29)
#define ARM64_REG_ACC_OVRD_cpmWakeUp_mask              (3ULL << 27)
#define ARM64_REG_ACC_OVRD_cpmWakeUp_force             (3ULL << 27)
#define ARM64_REG_ACC_OVRD_ok2PwrDnCPM_mask            (3ULL << 25)
#define ARM64_REG_ACC_OVRD_ok2PwrDnCPM_deny            (2ULL << 25)
#define ARM64_REG_ACC_OVRD_ok2PwrDnCPM_deepsleep       (3ULL << 25)
#define ARM64_REG_ACC_OVRD_ok2TrDnLnk_mask             (3ULL << 17)
#define ARM64_REG_ACC_OVRD_ok2TrDnLnk_deepsleep        (3ULL << 17)
#define ARM64_REG_ACC_OVRD_disL2Flush4AccSlp_mask      (3ULL << 15)
#define ARM64_REG_ACC_OVRD_disL2Flush4AccSlp_deepsleep (2ULL << 15)
#define ARM64_REG_ACC_OVRD_ok2PwrDnSRM_mask            (3ULL << 13)
#define ARM64_REG_ACC_OVRD_ok2PwrDnSRM_deepsleep       (3ULL << 13)
#endif /* defined(APPLECYCLONE) || defined(APPLETYPHOON) || defined(APPLETWISTER) */

#define ARM64_REG_CYC_OVRD_irq_mask            (3<<22)
#define ARM64_REG_CYC_OVRD_irq_disable         (2<<22)
#define ARM64_REG_CYC_OVRD_fiq_mask            (3<<20)
#define ARM64_REG_CYC_OVRD_fiq_disable         (2<<20)
#define ARM64_REG_CYC_OVRD_ok2pwrdn_force_up   (2<<24)
#define ARM64_REG_CYC_OVRD_ok2pwrdn_force_down (3<<24)
#define ARM64_REG_CYC_OVRD_disWfiRetn          (1<<0)

#if defined(APPLEMONSOON)
#define ARM64_REG_CYC_OVRD_dsblSnoopTime_mask  (3ULL << 30)
#define ARM64_REG_CYC_OVRD_dsblSnoopPTime      (1ULL << 31)  /// Don't fetch the timebase from the P-block
#endif /* APPLEMONSOON */

#define ARM64_REG_LSU_ERR_STS_L1DTlbMultiHitEN (1ULL<<54)
#define ARM64_REG_LSU_ERR_CTL_L1DTlbMultiHitEN (1ULL<<3)


#if defined(HAS_IPI)
#define ARM64_REG_IPI_RR_TYPE_IMMEDIATE (0 << 28)
#define ARM64_REG_IPI_RR_TYPE_RETRACT   (1 << 28)
#define ARM64_REG_IPI_RR_TYPE_DEFERRED  (2 << 28)
#define ARM64_REG_IPI_RR_TYPE_NOWAKE    (3 << 28)
#endif /* defined(HAS_IPI) */


#endif /* APPLE_ARM64_ARCH_FAMILY */

#if defined(HAS_NEX_PG)
#define ARM64_REG_HID13_RstCyc_mask (0xfULL << 60)
#define ARM64_REG_HID13_RstCyc_val  (0xcULL << 60)

#define ARM64_REG_HID14_NexPwgEn    (1ULL << 32)
#endif /* defined(HAS_NEX_PG) */

#define ARM64_REG_EHID20_forceNonSpecTargetedTimerSel_shift     (21)
#define ARM64_REG_EHID20_forceNonSpecTargetedTimerSel_mask      (3ULL << ARM64_REG_EHID20_forceNonSpecTargetedTimerSel_shift)
#define ARM64_REG_EHID20_forceNonSpecTargetedTimerSel_VALUE     (3ULL << ARM64_REG_EHID20_forceNonSpecTargetedTimerSel_shift)
#define ARM64_REG_EHID20_forceNonSpecIfSpecFlushPtrNEBlkRtrPtr  (1ULL << 16)
#define ARM64_REG_EHID20_forceNonSpecIfOldestRedirVldAndOlder   (1ULL << 15)
#define ARM64_REG_EHID20_trapSMC                                (1ULL << 8)
#define ARM64_REG_EHID20_forceNonSpecIfOldestRedirVldAndOlder   (1ULL << 15)

#if defined(HAS_BP_RET)
#define ARM64_REG_ACC_CFG_bdpSlpEn    (1ULL << 2)
#define ARM64_REG_ACC_CFG_btpSlpEn    (1ULL << 3)
#define ARM64_REG_ACC_CFG_bpSlp_mask  3
#define ARM64_REG_ACC_CFG_bpSlp_shift 2
#endif /* defined(HAS_BP_RET) */

#if defined(HAS_VMSA_LOCK)
#define VMSA_LOCK_VBAR_EL1      (1ULL << 0)
#define VMSA_LOCK_SCTLR_EL1     (1ULL << 1)
#define VMSA_LOCK_TCR_EL1       (1ULL << 2)
#define VMSA_LOCK_TTBR0_EL1     (1ULL << 3)
#define VMSA_LOCK_TTBR1_EL1     (1ULL << 4)
#define VMSA_LOCK_SCTLR_M_BIT   (1ULL << 63)
#endif /* HAS_VMSA_LOCK */

#define MPIDR_PNE_SHIFT 16 // pcore not ecore
#define MPIDR_PNE       (1 << MPIDR_PNE_SHIFT)


#define CPU_PIO_CPU_STS_OFFSET               (0x100ULL)
#define CPU_PIO_CPU_STS_cpuRunSt_mask        (0xff)


#ifdef ASSEMBLER

/*
 * arg0: register in which to store result
 *   0=>not a p-core, non-zero=>p-core
 */
.macro ARM64_IS_PCORE
#if defined(APPLEMONSOON) || HAS_CLUSTER
	mrs $0, MPIDR_EL1
	and $0, $0, #(MPIDR_PNE)
#endif /* defined(APPLEMONSOON) || HAS_CLUSTER */
.endmacro

/*
 * reads a special purpose register, using a different msr for e- vs. p-cores
 *   arg0: register indicating the current core type, see ARM64_IS_PCORE
 *   arg1: register in which to store the result of the read
 *   arg2: SPR to use for e-core
 *   arg3: SPR to use for p-core or non-AMP architecture
 */
.macro ARM64_READ_EP_SPR
#if defined(APPLEMONSOON) || HAS_CLUSTER
	cbnz $0, 1f
// e-core
	mrs  $1, $2
	b    2f
// p-core
1:
#endif /* defined(APPLEMONSOON) || HAS_CLUSTER */
	mrs  $1, $3
2:
.endmacro

/*
 * writes a special purpose register, using a different msr for e- vs. p-cores
 * arg0: register indicating the current core type, see ARM64_IS_PCORE
 * arg1: register containing the value to write
 * arg2: SPR to use for e-core
 * arg3: SPR to use for p-core or non-AMP architecture
 */
.macro ARM64_WRITE_EP_SPR
#if defined(APPLEMONSOON) || HAS_CLUSTER
	cbnz $0, 1f
// e-core
	msr  $2, $1
	b    2f
// p-core
1:
#endif /* defined(APPLEMONSOON) || HAS_CLUSTER */
	msr  $3, $1
2:
.endmacro

#endif /* ASSEMBLER */

#endif /* ! _PEXPERT_ARM_ARM64_H */
