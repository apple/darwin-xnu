/*
 * Copyright 2016 Apple, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

inline int R_R0 = 0;
#pragma D binding "1.0" R_R0
inline int R_R1 = 1;
#pragma D binding "1.0" R_R1
inline int R_R2 = 2;
#pragma D binding "1.0" R_R2
inline int R_R3 = 3;
#pragma D binding "1.0" R_R3
inline int R_R4 = 4;
#pragma D binding "1.0" R_R4
inline int R_R5 = 5;
#pragma D binding "1.0" R_R5
inline int R_R6 = 6;
#pragma D binding "1.0" R_R6
inline int R_R7 = 7;
#pragma D binding "1.0" R_R7
inline int R_R8 = 8;
#pragma D binding "1.0" R_R8
inline int R_R9 = 9;
#pragma D binding "1.0" R_R9
inline int R_R10 = 10;
#pragma D binding "1.0" R_R10
inline int R_R11 = 11;
#pragma D binding "1.0" R_R11
inline int R_R12 = 12;
#pragma D binding "1.0" R_R12
inline int R_R13 = 13;
#pragma D binding "1.0" R_R13
inline int R_R14 = 14;
#pragma D binding "1.0" R_R14
inline int R_R15 = 15;
#pragma D binding "1.0" R_R15

/* Apple-specific ABI to use R7 as the framepointer */
inline int R_FP = R_R7;
#pragma D binding "1.0" R_FP

inline int R_SP = R_R13;
#pragma D binding "1.0" R_SP
inline int R_LR = R_R14;
#pragma D binding "1.0" R_LR
inline int R_PC = R_R15;
#pragma D binding "1.0" R_PC
inline int R_CPSR = 16;
#pragma D binding "1.0" R_CPSR

