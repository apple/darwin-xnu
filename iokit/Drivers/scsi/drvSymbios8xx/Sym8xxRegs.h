/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1998 Apple Computer Inc.
 *
 * Symbios8xx Controller.
 *
 */

/* SymBios 8xx register addressing definitions */

#define SCNTL0_SIZE   0x01
#define SCNTL0        0x00000000
#define SCNTL0_INIT   0xCA      /* Scsi control 0 */ 
   /* ARB1  1                  */
   /* ARB0  1 : Full arbitration            */
   /* START 0 : Start sequence            */
   /* WATN  0 : Select with ATN            */
   /* EPC   1 : enable SCSI bus parity checking      */
   /* RES      */
   /* AAP   1 : Assert ATN on SCSI parity error      */
   /* TRG   0 : Target mode. 720 is Initiator      */

#define SCNTL1_SIZE   0x01
#define SCNTL1        0x00000001
#define SCNTL1_INIT   0x00      /* Scsi control 1 */ 
   /* EXC   0 : Extra clock cycle data setup (Sdtr)      */
   /* ADB   0 : Assert SCSI data bus         */
   /* DHP   0 : Target only Disable halt parity error   */
   /* CON   0 : 820 connected to SCSI bus         */
   /* RST   0 : Assert SCSI RST signal         */
   /* AESP  0 : Force bad parity            */
   /* IARB  0 : Immediate arbitration         */
   /* SST   0 : Start SCSI transfer            */

#define SCNTL1_SCSI_RST		0x08	 /* force scsi reset in scntl1 reg */

#define SCNTL2_SIZE   0x01
#define SCNTL2        0x00000002
#define SCNTL2_INIT   0x00      /* Scsi control 2 */ 
   #define    SDU                0x80	/* SDU   0 : SCSI Disconnect Unexpected         */
   #define    CHM                0x40   /* CHM   0 : Chained mode                       */
   #define    SLPMD              0x40   /* SLPMD 0 : SLPAR Mode Bit                     */
   #define    SLPHBEN            0x40   /* SLPHBEN : SLPAR High Byte Enable             */
   #define    WSS                0x08	/* WSS   0 : Wide Scsi Send                     */
   #define    VUE0               0x40   /* VUE0    : Vendor Uniq Enhancements Bit 0     */
   #define    VUE1               0x40   /* VUE1    : Vendor Uniq Enhancements Bit 1     */
   #define    WSR                0x01   /* WSR   0 : Wide Scsi Receive                  */

#define SCNTL3_SIZE   0x01
#define SCNTL3        0x00000003
#define SCNTL3_INIT       	0x03   /* Scsi control 3 for 40Mhz sys clock */
#define SCNTL3_INIT_875   	0x05   /* Scsi control 3 for 80Mhz sys clock */
#define SCNTL3_INIT_875_ULTRA   0x95   /* Scsi control 3 for 80Mhz sys clock */
#define SCNTL3_INIT_875_FAST  	0x35   /* Scsi control 3 for 80Mhz sys clock */
#define SCNTL3_INIT_875_SLOW  	0x55   /* Scsi control 3 for 80Mhz sys clock */
   					/* RES                     */
   #define    SCF                0x70   /* SCF    0 : Sync clock conversion factor 0-2	*/
   #define    EWS                0x08   /* EWS    0 : Enable Wide SCSI (wdtr)		*/
   #define    CCF                0x07   /* CCF    0 : Async clock conversion factor 0-2	*/

#define SCID_SIZE     0x01
#define SCID          0x00000004
#define SCID_INIT     0x40   /* Scsi chip Id */ 
   /* RES                     */
   /* RRE   1 : Enable response to reselection      */
   /* SRE   0 : Disable response to selection       */
   /* RES                     */
   /* ID3   0                                               */
   /* ID2   0                                               */
   /* ID1   0                                               */
   /* ID0   0 : Encoded 53825 chip SCSI Id         */

#define SXFER_SIZE    0x01
#define SXFER         0x00000005
#define SXFER_INIT    0x00   /* Scsi Transfer */ 
   /* TP2   0                  */
   /* TP1   0                  */
   /* TP0   0 : Scsi sync Transfer Period (4)(Sdtr)      */
   /* RES                     */
   /* MO3   0                  */
   /* MO2   0                  */
   /* MO1   0                  */
   /* MO0   0 : Max Scsi Sync ReqAck offset (async) (Sdtr)   */

#define SDID_SIZE     0x01
#define SDID          0x00000006
#define SDID_INIT     0x00   /* Scsi destination Id */ 
   /* RES                                                  */
   /* RES                                                  */
   /* RES                                                  */
   /* RES                                                  */
   /* ID3   0                  */
   /* ID2   0                  */
   /* ID1   0                  */
   /* ID0   0 : Encoded destination Scsi Id         */

#define GPREG_SIZE    0x01
#define GPREG         0x00000007
#define GPREG_INIT    0x00       /* Read/write general purpose */
#define GPIO3         0x08       /* GPIO bit 3 */
   /* RES                                                  */
   /* RES                                                  */
   /* RES                                                  */
   /* GPO    0 : General purpose output         */
   /* GPI3   0                  */
   /* GPI2   0                  */
   /* GPI1   0                  */
   /* GPI0   0 : General purpose inputs         */

#define SFBR_SIZE     0x01
#define SFBR          0x00000008
#define SFBR_INIT     0x00       
   /* SCSI First Byte Received */

#define SOCL_SIZE     0x01
#define SOCL          0x00000009
#define SOCL_INIT     0x00 
   #define    SREQ               0x80	/* REQ   0 : Assert SCSI REQ signal     */
   #define    SACK               0x40   /* ACK   0 :      	 ACK            */
   #define    SBSY               0x20   /* BSY   0 :      	 BSY            */
   #define    SSEL               0x10   /* SEL   0 :      	 SEL            */
   #define    SATN               0x08   /* ATN   0 :      	 ATN            */
   #define    SMSG               0x04   /* MSG   0 :       	 MSG            */
   #define    SC_D               0x02   /* C/D   0 :      	 C/D            */
   #define    SI_O               0x01   /* I/O   0 :      	 I/O            */

#define SSID_SIZE     0x01
#define SSID          0x0000000A /* Read Only */
   /* VAL       Scsi Valid Bit            */
   /* RES                                                  */
   /* RES                                                  */
   /* RES                                                  */
   /* ID3                     */
   /* ID2                     */
   /* ID1                     */
   /* ID0      Encoded Destination Scsi Id         */

#define SBCL_SIZE     0x01
#define SBCL          0x0000000B /* Scsi Bus Control Lines Read only */
   /* REQ                                                  */
   /* ACK                                                  */
   /* BSY                                                  */
   /* SEL                                                  */
   /* ATN                                                  */
   /* MSG                                                  */
   /* C/D                     */
   /* I/O                     */

#define DSTAT_SIZE    0x01
#define DSTAT         0x0000000C /* DMA status Read only */
   #define    DFE                0x80    /* DSTAT DMA FIFO Empty           */
   #define    MDPE               0x40    /* Master Data Parity Error       */
   #define    BF                 0x20    /* Bus Fault                      */
   #define    DABRT              0x10    /* Abort occurred                 */
   #define    SSI                0x08    /* Script Step Interrupt          */
   #define    SIR                0x04    /* Script Interrupt Inst Received */
#ifdef notdef
   #define    WTD                0x02    /* was watchdog timer, now reserved */
#endif /* notdef */
   #define    IID                0x01    /* Illegal Instruction Detected   */

#define SSTAT0_SIZE   0x01
#define SSTAT0        0x0000000D /* SCSI status zero Read only */
    #define    ILF		0x80     /* ILF   SIDL least significant byte full      */
    #define    ORF		0x40     /* ORF   SODR least significant byte full      */
    #define    OLF		0x20     /* OLF   SODL least significant byte full      */
    #define    AIP		0x10     /* AIP   Arbitration in progress            	*/
    #define    LOA		0x08     /* LOA   Lost arbitration            		*/
    #define    WOA		0x04     /* WOA   Won arbitration               	*/
    #define    RSTB		0x02     /* RST   Scsi reset signal            		*/
    #define    SDP0		0x01     /* SDP0  Scsi SDP0 parity signal            	*/

#define SSTAT1_SIZE   0x01
#define SSTAT1        0x0000000E /* SCSI status one Read only */
   /* FF3-0 Bytes or word in the Scsi FIFO         */
   /* SDP   Latched Scsi parity            */
   /* MSG   Scsi phase status            */
   /* C/D                     */
   /* I/O                     */

#define SSTAT2_SIZE   0x01
#define SSTAT2        0x0000000F /* Scsi status two Read only */
    #define    ILF1		0x80    /* ILF1   SIDL most significant byte full	*/
    #define    ORF1		0x40    /* ORF1   SODR   "   "   "   "      		*/
    #define    OLF1		0x20    /* OLF1   SODL   "   "   "   "      		*/
                                        /* RES                     			*/
    #define    SPL1		0x08    /* SPL1   Latched Scsi parity for SIDL15-8      */
    #define    FF4		0x04    /* FIFO Flags Bit 4                     	*/
    #define    LDSC		0x02    /* LDSC   Last disconnect                       */
    #define    SDP1		0x01    /* SDP1   Scsi SDP1 Signal            		*/

#define DSA_SIZE      0x04
#define DSA           0x00000010
#define DSA_INIT      0x00000000 /* Data structure address */

#define ISTAT_SIZE    0x01
#define ISTAT         0x00000014
#define ISTAT_INIT    0x00       /* Interrupt Status   */
   #define    ABRT         0x80    /* Abort Operation      */
   #define    RST          0x40    /* Software reset      */
   #define    SIGP         0x20    /* Signal process      */
   #define    SEM          0x10    /* Semaphore         */
   #define    ISTAT_CON	   0X08	   /* Connected to target. */
   #define    INTF         0x04    /* Interrupt on the fly   */
   #define    SIP          0x02    /* SCSI Interrupt Pending   */
   #define    DIP          0x01    /* DMA Interrupt Pending    */

#define CTEST0_SIZE   0x01
#define CTEST0        0x00000018
#define CTEST0_INIT   0x00       /* Chip test zero (now general purpose, rph) */

#define CTEST1_SIZE   0x01
#define CTEST1        0x00000019 /* Chip test one Read only */
   /* FMT3-0 0 : Byte empty in DMA FIFO         */
   /* FFL3-0 0 : Byte full in DMA FIFO         */

#define CTEST2_SIZE   0x01
#define CTEST2        0x0000001A /* Chip test two Read only */
   /* DDIR   Data transfer direction (1 : Scsi bus -> host)   */
   /* SIGP   Signal process (Clear SIGP ISTAT when read)   */
   /* CIO (read-only, indicates chip configured as I/O space) */
   /* CM  (read-only, indicates configured as memory space) */
   /* RES               */
   /* TEOP   Scsi true end of process         */
   /* DREQ   Data request status            */
   /* DACK   Data acknowledge status            */

#define CTEST3_SIZE   0x01
#define CTEST3        0x0000001B
#define CTEST3_INIT   0x04       /* Chip test  three */
#define CTEST3_INIT_A 0x05       /* Chip test  three for 'A' part */

   #define    VERS         0xf0   /* V3-0  0 : Chip revision level       */
   #define    FLF          0x08   /* FLF   0 : Flush DMA Fifo            */
   #define    CLF          0x04   /* CLF   1 : Clear DMA FIFO    	 */
   #define    FM           0x02   /* FM    0 : Fetch pin mode            */
   #define    WRIE         0x01   /* WRIE  1 : Write and Invalidate Enable, for 825A only!!! */

#define TEMP_SIZE     0x04
#define TEMP          0x0000001C
#define TEMP_INIT     0x00000000 /* Tempory stack */

#define DFIFO_SIZE    0x01
#define DFIFO         0x00000020
#define DFIFO_INIT    0x00       /* DMA FIFO */
   /* upper bit used for 825 'A' part when using large fifo */
   /* BO6-0 0: Byte offset counter            */

#define CTEST4_SIZE   0x01
#define CTEST4        0x00000021 /* Chip test four */
//  #define CTEST4_INIT   0x80 /* Chip test four DISABLE BURST!! */
#define CTEST4_INIT   0x00 /* Chip test four */
   /* BDIS  0 : set for Burst Disable, reset allows burst on data moves */
   /* ZMOD   High impedance mode            */
   /* ZSD    Scsi high impedance mode         */
   /* SRTM   Shadow register test mode         */
/* NOT for bandit!!!! yes for NEW rev of Dumbarton LATER on, not initial!!! */
   /* MPEE  0 : Master Parity Error Enable   Do we want this set????   rph  */
   /* FBL2-0 Fifo byte control            */

#define CTEST5_SIZE   0x01
#define CTEST5        0x00000022
#define CTEST5_INIT   0x00       /* Chip test five */
#define CTEST5_INIT_A 0x00       /* Chip test five 'A' part, upper burst OFF */
#define CTEST5_INIT_A_revB 0x24  /* Chip test five 'A' part, upper burst OFF
				  * also Enable 536 byte fifo */
    #define    ADCK    		0x80 	/* ADCK   0 : Clock address incrementor         	*/
    #define    BBCK    		0x40	/* BBCK   0 : Clock byte counter            		*/
    #define    DFS    		0x20	/* DFS    0 : fifo size - 0=88 1=536 bytes 	  	*/
    #define    MASR    		0x10	/* MASR   0 : Master control for set reset pulses	*/
    #define    DDIR    		0x08	/* DDIR   0 : DMA direction            			*/
    #define    BL2    		0x04	/* BL2    0 : see DMODE bits 6,7 			*/
    #define    BO89    		0x03	/* BO89   0 : upper bits of DFIFO count  		*/

#define CTEST6_SIZE   0x01
#define CTEST6        0x00000023
#define CTEST6_INIT   0x00       /* chip test six */
   /* 7-0   0 : DMA Fifo               */

#define DBC_SIZE      0x04
#define DBC           0x00000024
#define DBC_INIT      0x000000   /* DMA Byte Counter */

#define DCMD_SIZE     0x01
#define DCMD          0x00000027
#define DCMD_INIT     0x00       /* DMA command */

#define DNAD_SIZE     0x04
#define DNAD          0x00000028
#define DNAD_INIT     0x00000000 /* DMA Next Data Address */

#define DSP_SIZE      0x04
#define DSP           0x0000002C
#define DSP_INIT      0x00000000 /* DMA script pointer */

#define DSPS_SIZE     0x04
#define DSPS          0x00000030
#define DSPS_INIT     0x00000000 /* DMA SCRIPTS Pointer Save */

#define SCRATCHA_SIZE 0x04
#define SCRATCHA      0x00000034  
#define SCRATCHA0     0x00000034
#define SCRATCHA1     0x00000035
#define SCRATCHA2     0x00000036
#define SCRATCHA3     0x00000037
#define SCRATCHA_INIT 0x04030201 /* general purpose register */

#define DMODE_SIZE    0x01
#define DMODE         0x00000038
/* 825 bug!!!!! 8 is max!!!!!!!		rph 8-23-94
 */
#define DMODE_INIT    	   0x82  /* DMA mode 8 burst xfers + instruc fetch */
#define DMODE_INIT_A       0x0A  /* DMA mode 32 burst xfers + instruc fetch */
   /* BL1     1 : Burst length, burst size is '8' transfers (4 bytes per) */
   /* BL0     0 : Burst length  */
   /* SIOM    0 : Source I/O-Memory Enable (Memory space is default) */
   /* DIOM    0 : Destination I/O-Memory Enable (Memory space is default) */
   /* ER      1 : Enable Read Line Command,  set for 825'A' part    */
   /* ERM     0 :		*/
   /* BOF     1 : Burst Op Code Fetch Enable, only for 825!!! rph */
   /* MAN     0 : Manual start mode (leave 0 for auto-start with DSP write  */

#define DIEN_SIZE     0x01
#define DIEN          0x00000039
#define DIEN_INIT     0x7D       /* No mask on DMA interrupt */
   /* RES                     */
   /* MDPE  1 : Master Data Parity Error   */
   /* BF    1 : Bus fault               */
   /* ABRT  1 : Aborted               */
   /* SSI   1 : Script step interrupt         */
   /* SIR   1 : Script interrupt instruction received   */
   /* RES          */
   /* IID   1 : Illegal instruction detected      */

#define DWT_SIZE      0x01
#define DWT           0x0000003A
#define DWT_INIT      0xD0       /* DMA watchdog timer to 0xD0*32*BCLK ns*/

#define DCNTL_SIZE    0x01
#define DCNTL         0x0000003B
#define DCNTL_INIT    0x01     /* DMA Control register */
#define DCNTL_INIT_A  0xA1     /* DMA Control register, 'A' part */
   /* CLE  7: Cache Line Size Enable for 'A' part */
   /* PFF  6: pre-fetch flush bit for 'A' part */
   /* PFEN 5: pre-fetch Enable bit for 'A' part */
   /* RES  */ 
   /* RES  */
#define  SSM  0x10      /* 0 : Single step mode       */
   /* IRQM   0 : HW driver type for IRQ pin, default is open drain, ask HW rph*/
#define  STD  0x04      /* 0 : start DMA operation       */
   /* IRQ 1: IRQ disable for 'A' part */
   /* COM   1 : No Compatibility 700            */

#define ADDER_SIZE    0x04
#define ADDER         0x0000003C /* Adder sum output Read only */

#define SIEN_SIZE     0x02
#define SIEN          0x00000040
#define SIEN_INIT_RST_OFF  0x048D  /* SCSI Interrupt enable SIEN0-1  rph */
#define SIEN_INIT          0x048F  /* SCSI Interrupt enable SIEN0-1  rph */
/* SIEN0 */
   /* M/A   1 : Scsi phase mismatch    */
   /* CMP   0 : Function complete      */
   /* SEL   0 : Selected               */
   /* RSL   0 : Reselected             */
   /* SGE   1 : Scsi Gross error       */
   /* UDC   1 : Unexpected disconnect  */
   /* RST   1 : Scsi Reset condition   */
   /* PAR   1 : Scsi Parity error      */

   /* RES                              */
   /* RES                              */
   /* RES                              */
   /* RES                              */
   /* RES                              */
   /* STO   1 : (Re)Selection timeout  */
   /* GEM   0 : General purpose timeout*/
   /* HTH   0 : Handshake timeout      */

#define SIST_SIZE     0x02
#define SIST          0x00000042 /* Scsi interrupt status Read only */
   /* idem SIEN reg               */
   #define    STO		0x0400
   #define    GEN		0x0200
   #define    HTH		0x0100
     
   #define    MA		0x0080
   #define    CMP		0x0040
   #define    SEL		0x0020
   #define    RSL		0x0010
   #define    SGE		0x0008
   #define    UDC		0x0004
   #define    RSTI              0x0002
   #define    PAR               0x0001	

#define SLPAR_SIZE    0x01
#define SLPAR         0x00000044
#define SLPAR_INIT    0x00       /* SCSI longitudinal parity */

#define SWIDE_SIZE    0x01
#define SWIDE         0x00000045 /*  Scsi wide residue data Read only */

#define MACNTL_SIZE   0x01
#define MACNTL        0x00000046
#define MACNTL_INIT   0x00       /* memory access control */
   /* TYP3-0   : Chip Type (read-only)         */
   /* DataWr 0 : Data write Far memory         */
   /* DataRd 0 : Data read far memory         */
   /* Pointer to script fetch 0 : far memory      */
   /* Script fetch 0 : far memory            */

#define GPCNTL_SIZE   0x01
#define GPCNTL        0x00000047
#define GPCNTL_INIT   0x0F       /* General purpose control Cf appendum  ?? */
// #define GPCNTL_INIT   0xCF       /* General purpose control Cf appendum  ?? */
   /* ME        : 0 Master Enable                          */
   /* FE        : 0 Fetch  Enable                          */
   /* RES                                                  */
   /* GPI/O_en4 : 0 GPREG input or output         */
   /* GPI/O_en3 : 1               */
   /* GPI/O_en2 : 1                                        */
   /* GPI/O_en1 : 1                                        */
   /* GPI/O_en0 : 1                                        */

#define STIME0_SIZE   0x01
#define STIME0        0x00000048
#define STIME0_INIT   0x0C       /* Scsi timer register 0 */
   /* HTH3                     */
   /* HTH2                     */
   /* HTH1   0                   */
   /* HTH0   0 : Handshake timer period (disabled)      */
   /* SEL3   1                   */
   /* SEL2   1                  */
   /* SEL1   0                  */
   /* SEL0   0 : Selection timeout period (204.8ms)      */

#define STIME1_SIZE   0x01
#define STIME1        0x00000049
#define STIME1_INIT   0x00       /* Scsi timer register one */
   /* RES                                                  */
   /* RES                                                  */
   /* RES                                                  */
   /* RES                                                  */
   /* GEN3 0                   */
   /* GEN2 0                  */
   /* GEN1 0                  */
   /* GEN0 0 : General purpose timer period (disabled)   */

#define RESPID0_SIZE  0x01
#define RESPID0       0x0000004A
#define RESPID0_INIT  0x00       /* Response Id zero */
   /* ID7 - ID0                  */

#define RESPID1_SIZE  0x01
#define RESPID1       0x0000004B
#define RESPID1_INIT  0x00       /* Response ID one       */
   /* ID15  - ID8                  */

#define STEST0_SIZE   0x01
#define STEST0        0x0000004C /*  Scsi test register zero Read only */
   /* RES                                                  */
   /* RES                                                  */
   /* RES                                                  */
   /* RES                                                  */
   /* SLT Selection response Logic test         */
   /* ART Arbitration priority encoder test      */
   /* SOZ Scsi synchronous offset zero         */
   /* SOM Scsi synchronous offset maximum         */

#define STEST1_SIZE   0x01
#define STEST1        0x0000004D 	/* Scsi test register one Read/Write */
#define STEST1_INIT   0x00
   #define    SCLK		0x80	/* SCLK    0 : 1 = Use PCI Clock 0 = Use SCLK input	*/
   #define    SISIO		0x40	/* SISIO   0 : SCSI Isolation Mode 			*/
   					/* 	   0 :						*/
   					/*	   0 :						*/
   #define    DBLEN		0x08	/* DBLEN   0 : SCLK Doubler Enable			*/
   #define    DBLSEL		0x04	/* DBLSEL  0 : SCLK Doubler Select			*/
   					/* 	   0 :						*/
   					/*	   0 :						*/

#define STEST2_SIZE   0x01
#define STEST2        0x0000004E
#define STEST2_INIT        0x00       /* Scsi Test register two */
#define STEST2_DIFF_INIT   0x20       /* Scsi Test register two */
   #define    SCE		0x80	/* SCE   0 : Scsi control enable            				*/
   #define    ROF		0x40	/* ROF   0 : Reset Scsi offset            				*/
   #define    DIF		0x20	/* DIF   0/1 : SCSI differential mode, set if we detect differential card */
   #define    SLB		0x10	/* SLB   0 : Scsi loopback mode            				*/
   #define    SZM		0x08	/* SZM   0 : SCSI high impedance mode         				*/
   #define    AWS		0x04	/* AWS   0 : Always wide SCSI            				*/
   #define    EXT		0x02	/* EXT   0 : Extend REQ/ACK filtering    NEVER want SET for 'fast'!!!	*/
   #define    LOW		0x01	/* LOW   0 : Scsi low level mode            				*/

#define STEST3_SIZE   0x01
#define STEST3        0x0000004F
#define STEST3_INIT   0x92   /* Scsi test register 3   */
   #define    EAN		0x80	/* EAN   1 : Enable active negation         		*/
   #define    STR		0x40   	/* STR   0 : Scsi FIFO test read            		*/
   #define    HSC		0x20   	/* HSC   0 : Halt Scsi Clock            		*/
   #define    DSI		0x10   	/* DSI   1 : Disable single initiator response      	*/
   					/* RES          					*/
   #define    TTM		0x04   	/* TTM   0 : Timer test mode            		*/
   #define    CSF		0x02   	/* CSF   1 : Clear SCSI FIFO  				*/
   #define    STW		0x01  	/* STW   0 : SCSI FIFO test write         		*/

#define SSIDL_SIZE    0x02
#define SSIDL         0x00000050 /* SCSI input data latch Read only */

#define SODL_SIZE     0x02
#define SODL          0x00000054
#define SODL_INIT     0x0000     /* SCSI Output Data Latch */

#define SBDL_SIZE     0x02
#define SBDL          0x00000058 /* SCSI bus data line Read only */

#define SCRATCHB_SIZE 0x04
#define SCRATCHB      0x0000005C
#define SCRATCHB0     0x0000005C
#define SCRATCHB1     0x0000005D
#define SCRATCHB2     0x0000005E
#define SCRATCHB3     0x0000005F
#define SCRATCHB_INIT 0x00000000 /* general purpose register */

/* ************************* */

/* Miscellaneous defines */
#define CLK_40MHz	    		40
#define CLK_80MHz           		80
#define kResetRecoveryTimeMS		5000

#define kChipIdSym875			0x000f
#define kChipIdSym895			0x000c
#define kChipIdSym896			0x000b
#define kChipIdSym1010			0x0020
