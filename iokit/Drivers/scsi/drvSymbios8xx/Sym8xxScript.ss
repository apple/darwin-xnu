
; Copyright (c) 1997-1999 Apple Computer, Inc. All rights reserved.
;
; @APPLE_LICENSE_HEADER_START@
; 
; The contents of this file constitute Original Code as defined in and
; are subject to the Apple Public Source License Version 1.1 (the
; "License").  You may not use this file except in compliance with the
; License.  Please obtain a copy of the License at
; http://www.apple.com/publicsource and read it before using this file.
; 
; This Original Code and all software distributed under the License are
; distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
; EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
; INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
; License for the specific language governing rights and limitations
; under the License.
; 
; @APPLE_LICENSE_HEADER_END@
;
;   File Ownership:
;
;       DRI:            Mike Johnson
;
;       Other Contact:  Russ Berkoff
;
;       Technology:     SCSI
;
;   Writers:
;
;       (MLJ)   Mike Johnson
;       (RRA)   Rick Auricchio


;       NCR Errata Listing 125 Item 1 : Clear the SCNTL0 start bit
;       when jump to reselect during select (try_reselect)
;
;       NCR Errata Listing 117 Item 4 : Bad parity if odd bytes during
;       wide transfer. Only for DATA OUT in Initiator mode.
;       (Confirm by Manfred Eierle 3rd June 93 not during DATA IN)

    ARCH     825A                ;specifically for 825a and 875 (new instructions)


        ;*****************************************************************
        ;
        ;   Phase codes - These values represent which action is being handled
        ;
        ;*****************************************************************

    ABSOLUTE kphase_DATA_OUT                = 0x00
    ABSOLUTE kphase_DATA_IN                 = 0x01
    ABSOLUTE kphase_COMMAND                 = 0x02
    ABSOLUTE kphase_STATUS                  = 0x03
    ABSOLUTE kphase_MSG_OUT                 = 0x06
    ABSOLUTE kphase_MSG_IN                  = 0x07
    ABSOLUTE kphase_SELECT                  = 0x08
    ABSOLUTE kphase_RESELECT                = 0x09
    ABSOLUTE kphase_ABORT_CURRENT           = 0x0A
    ABSOLUTE kphase_ABORT_MAILBOX           = 0x0B
    ABSOLUTE kphase_CMD_COMPLETE            = 0x0C
    ABSOLUTE kphase_DISCONNECT              = 0x0D
    ABSOLUTE kphase_saveDataPointer         = 0x0E  ; ??? driver work to be done
    ABSOLUTE kphase_restoreDataPointer      = 0x0F  ; ??? driver work to be done


        ;*****************************************************************
        ;   interrupt codes
        ;*****************************************************************

    ABSOLUTE unknown_phase              = 0x00  ; A spurious phase on SCSI Bus
    ABSOLUTE status_error               = 0x01  ; IO completes, but with status error
    ABSOLUTE unexpected_msg             = 0x02  ; An 'unknown' message is in ld_message var
    ABSOLUTE unexpected_ext_msg         = 0x03  ; An 'unknown' extended message in ld_message
    ABSOLUTE wide_32_not_supported      = 0x04  ; The device wants 32 bits data phase
    ABSOLUTE no_msgin_after_reselect    = 0x05  ; No message-in after reselection
    ABSOLUTE reqack_too_large           = 0x06  ; The device answer ReqAck offset is greater than 8
    ABSOLUTE unknown_reselect           = 0x07  ; The valid bit in SFBR reg not set
    ABSOLUTE unallocated_nexus          = 0x08  ; nexus index -> 0xFFFFFFFF
    ABSOLUTE abort_mailbox              = 0x09  ; Abort/BDR mailbox completed
    ABSOLUTE abort_current              = 0x0A  ; Abort/BDR current op completed
    ABSOLUTE unknown_message_out        = 0x0B  ; Unknown phase before message out
    ABSOLUTE unknown_msg_reject         = 0x0C  ; Unknown message reject
    ABSOLUTE negotiateSDTR              = 0x0D  ; Sync negotiation rx'd
    ABSOLUTE negotiateWDTR              = 0x0E  ; Wide negotiation rx'd
    ABSOLUTE sglist_complete            = 0x0F  ; SGList complete


        ;*****************************************************************
        ;
        ; Data structure for T/L/Q Nexus:
        ;
        ;*****************************************************************

    ABSOLUTE TLQ_SCSI_ID    =  0    ;  4 SCSI ID et al for SELECT instruction
    ABSOLUTE TLQ_xferAdr    =  4    ;  4 Physical address of CHMOV instructions
    ABSOLUTE TLQ_MSGOp      =  8    ;  8 Byte count, data adr   -> TLQ_MSGO
    ABSOLUTE TLQ_CDBp       = 16    ;  8 Byte count, data adr   -> TLQ_CDB
    ABSOLUTE TLQ_CDP        = 24    ;  4 Current Data Pointer
    ABSOLUTE TLQ_SDP        = 28    ;  4 Saved   Data Pointer
    ABSOLUTE TLQ_index      = 32    ;  1 index into nexus array
    ABSOLUTE TLQ_xferStarted= 33    ;  1 transfer started flag
    ABSOLUTE TLQ_IWR        = 34    ;  1 flag to Ignore Wide Residue
    ABSOLUTE TLQ_pad        = 35    ;  1 pad byte


        ;*****************************************************************
        ;
        ; ENTRY declarations - Declare entry points for driver
        ;
        ;*****************************************************************

    ENTRY   select_phase
    ENTRY   phase_handler
    ENTRY   issueMessageOut         ; for negotiation and Reject messages
    ENTRY   issueAbort_BDR          ; to immediately Abort or Bus-Device-Reset
    ENTRY   clearACK                ; MsgIn done - clr ACK, jump to phase handler


        ;*****************************************************************
        ;
        ; Define local data structure at start of SCRIPTS.
        ; This structure is allocated by the following nops.
        ;
        ;*****************************************************************
        ;

    RELATIVE local_data     \
        ld_AbortCode                = 4{??}\    ; 1 byte code to Abort or BDR
        ld_zeroes                   = 4{??}\    ; 4 bytes of 0 to clear registers
        ld_status                   = 4{??}\    ; Status byte from target
        ld_counter                  = 4{??}\    ; index into mailbox array
           ld_AbortBdr_mailbox      = 4{??}\    ; Abort/BusDeviceReset mailbox
           ld_IOdone_mailbox        = 4{??}\    ; [ nexus 0 0 semaphore ]
           ld_sched_mlbx_base_adr   = 4{??}\    ; base addr of mailbox array
           ld_mailboxp              = 4{??}\    ; address of current mailbox
        ld_scsi_id                  = 4{??}\    ; ptr to current mailbox
        ld_nexus_array_base         = 4{??}\    ; base address of Nexus pointers
        ld_nexus_index              = 4{??}\    ; index to Nexus pointer
        ld_nexus                    = 4{??}\    ; address of Nexus
           ld_phase_flag            = 4{??}\    ; for debugging
           ld_device_table_base_adr = 4{??}\    ; device configuration table
           ld_scratch               = 4{??}\    ; scratch memory
           ld_unused                = 4{??}\    ; unused
        ld_message                  = 4{??}\    ; buffer for MsgIn bytes
        ld_message4                 = 4{??}\    ; buffer continuation
        ld_pad                      = 4{??}\    ; padding
        ld_size                     = 4{??}     ; size of this structure


PROC BSC_SCRIPT:

        ; *** These NOPs must be at address 0.                          ***
        ; *** This is reserved space for the structure "local_data".    ***
        ; *** The driver inits this area to zero.                       ***

    nop 0       ; ld_AbortCode,             ld_zeroes
    nop 0       ; ld_status,                ld_counter

    nop 0       ; ld_AbortBdr_mailbox,      ld_IOdone_mailbox
    nop 0       ; ld_sched_mlbx_base_adr,   ld_mailboxp

    nop 0       ; ld_scsi_id,               ld_nexus_array_base
    nop 0       ; ld_nexus_index,           ld_nexus

    nop 0       ; ld_phase_flag,            ld_device_table_base_adr
    nop 0       ; ld_scratch,               ld_unused

    nop 0       ; ld_message,               ld_message4
    nop ld_size ; ld_pad,                   ld_size     (Use ld_size or lose it)

    nop sglist_complete     ; use sglist_complete or lose it from gen'd output file

    ;****************************************************************************
    ;
    ; findNexusFromIndex - load DSA with pointer to Nexus given a Nexus index:
    ;
    ;****************************************************************************

findNexusFromIndex:

    load SCRATCHA0, 4, ld_nexus_index       ; load index and leading zeroes
    clear CARRY
    move SCRATCHA0 SHL 0 to SCRATCHA0       ; double the index
    move SCRATCHA1 SHL 0 to SCRATCHA1
    move SCRATCHA0 SHL 0 to SCRATCHA0       ; double again
    move SCRATCHA1 SHL 0 to SCRATCHA1       ; A0 now has index to 4-byte address
    store SCRATCHA0, 4, patchArrayOffset+4  ; *** patch the code
    
    load DSA0, 4, ld_nexus_array_base       ; load base address of array of Nexus pointers
patchArrayOffset:
    load DSA0, 4, DSAREL( 0 )               ; *** patched offset. Load pointer.

    move DSA0 to SFBR                       ; Ensure pointer is not 0xFFFFFFFF
    int unallocated_nexus, if 0xFF          ; Interrupt if NFG

    store DSA0, 4, ld_nexus                 ; Store the Nexus pointer
    return                                  ; end findNexusFromIndex


    ;****************************************************************************
    ;
    ; initContext - Initialize the registers for Sync and Wide using
    ;   values stored in the device configuration table.
    ;   Return with values in SCRATCHB for Select code.
    ;
    ;****************************************************************************

initContext:

    load SCRATCHB0, 4, ld_scsi_id                   ; load 4-bit SCSI ID and zeroes
    clear CARRY
    move SCRATCHB0 SHL SCRATCHB0                    ; * 2
    move SCRATCHB0 SHL SCRATCHB0                    ; * 2 -> UInt32 index
    store SCRATCHB0, 4, patchGetDevConfigOffset+4   ; *** Patch load  code

    load DSA0, 4, ld_device_table_base_adr          ; load base physical addr of tables

patchGetDevConfigOffset:
    load  SCRATCHB0, 4, DSAREL( 0 )                 ; *** Patched table offset ***

        ; SCRATCHB0 = 0
        ; SCRATCHB1 = TP,MO (SXFER bits7-5 bits3-0)
        ; SCRATCHB2 = 0 (position for SCSI ID)
        ; SCRATCHB3 = SCCF,EWS (SCNTL3 bits6-4 bit 3)

    move SCRATCHB1 to SFBR                          ; init SXFER from B1
    move SFBR to SXFER
                                                    ; Init SCNTL3 from B3
    move SCRATCHB3 to SFBR
    move SFBR to SCNTL3
    return                                          ; return with SCRATCHB intact.


    ;*****************************************************************
    ;
    ; Select_phase:
    ;       Clear the SIGP bit.
    ;       Check if any Abort/BusDeviceReset request waiting.
    ;       Nexus is found in the list of 256 mailboxes.
    ;       If current mailbox is empty, jump to reselect_phase.
    ;       SCRIPTS tries to select device.
    ;       If select fails due to reselect, jump to reselect_phase
    ;       Select Timeout handled by driver.
    ;       If select succeeds, clear the mailbox entry
    ;       and increment the mailbox counter.
    ;       Jump to the phase_handler (hopefully for MSG_OUT)
    ;
    ;*****************************************************************

select_phase:

    move CTEST2 | 0x00 to CTEST2           ; Clear SIGP bit from ISTAT reg

        ; Check abort mailbox:

    load SCRATCHA0, 4, ld_AbortBdr_mailbox ; Get AbortBdr mailbox
        ; The Identify byte in byte 0 is also the semaphore
        ; A0 = Identify byte (0xC0 + LUN  N.B. Disconnect allowed)
        ; A1 = Tag, if any
        ; A2 = SCSI ID
        ; A3 = Abort code   Abort=0x06; Abort Tag=0D; Bus Device Reset=0x0C
    move SCRATCHA0 to SFBR                  ; test the semaphore/Identify
    jump rel( AbortMailbox ), if not 0      ; jump if aborting


        ; Get the next IO nexus in the mailboxes circular list.
        ; Calculate current mailbox address as so:
        ;   counter byte index * 4  to get mailbox index
        ;   add base physical address of mailboxes giving current mailbox address

    load SCRATCHA0, 4, ld_counter           ; get 1-byte mailbox counter & 0s
    clear CARRY
    move SCRATCHA0 SHL 0 to SCRATCHA0       ; double it
    move SCRATCHA1 SHL 0 to SCRATCHA1
    move SCRATCHA0 SHL 0 to SCRATCHA0       ; double it again
    move SCRATCHA1 SHL 0 to SCRATCHA1       ; now have a UInt32 index
    store SCRATCHA0, 4, fetchMailbox+4      ; *** patch the load  DSA instruction
    store SCRATCHA0, 4, clear_mailbox+4     ; *** patch the store DSA instruction

    load DSA0, 4, ld_sched_mlbx_base_adr    ; load base physical address of mailboxes

fetchMailbox:
    load  DSA0, 4, DSAREL( 0 )              ; *** Patched offset. Load Nexus address
    store DSA0, 4, ld_nexus                 ; save pointer to current Nexus
    load SCRATCHA0, 4, ld_nexus             ; copy to A0

    move SCRATCHA0 to SFBR                  ; 
    jump rel( next_mailbox ), if 1          ; if low-byte == 0x01 then cancelled mailbox

    move SCRATCHA1 | SFBR to SFBR           ; if non-zero, have implicit semaphore
    move SCRATCHA2 | SFBR to SFBR
    move SCRATCHA3 | SFBR to SFBR
    jump rel( reselect_phase ), if 0        ; go to reselect_phase if empty

        ;*****************************************************************
        ;
        ; Something in mailbox: we have work to do
        ;
        ;*****************************************************************

    move kphase_SELECT to SCRATCHB0             ; set phase indicator
    store SCRATCHB0, 1, ld_phase_flag

    load  SCRATCHB0, 4, ld_zeroes               ; clr the invalid-nexus-index flag
    load  SCRATCHB0, 1, DSAREL( TLQ_index )     ; get index byte from nexus
    store SCRATCHB0, 4, ld_nexus_index          ; save it in local data

    load DSA0, 4, ld_nexus                      ; restore DSA register
    load SCRATCHB2, 1, DSAREL( TLQ_SCSI_ID+2 )  ; get Target's SCSI ID
    move SCRATCHB2 to SFBR
    move SFBR to SCRATCHB0                      ; position it
    store SCRATCHB0, 1, ld_scsi_id              ; save it
    call rel( initContext )                     ; setup Sync/Wide regs in SCRATCHB
    load DSA0, 4, ld_nexus                      ; restore DSA register
    store SCRATCHB1, 1, DSAREL( TLQ_SCSI_ID+1 ) ; SXFER
    store SCRATCHB3, 1, DSAREL( TLQ_SCSI_ID+3 ) ; SCNTL3

        ;********************** select the device ********************************
    SELECT ATN from TLQ_SCSI_ID, rel( try_reselect )    ; ************************
        ;*************************************************************************

        ; looking good - clear the mailbox:

next_mailbox:
    load SCRATCHA0, 4, ld_zeroes            ; zero out scratch register A
    load DSA0, 4, ld_sched_mlbx_base_adr    ; load base physical address of mailboxes
clear_mailbox:
    store SCRATCHA0, 4, DSAREL( 0 )         ; *** Patched offset. Zero the mailbox

        ; Update the index to the mailbox circular list:
    load SCRATCHB0, 1, ld_counter           ; get counter (mailbox index)
    move SCRATCHB0 + 1 to SCRATCHB0         ; add 1
    store SCRATCHB0, 1, ld_counter  ; put it back

    load SCRATCHB0, 1, ld_nexus             ; if low-byte == 0x01 then cancelled mailbox
    move SCRATCHB0 to SFBR
    jump rel( select_phase ), if 1        

;   *** FALL THROUGH TO phase_handler ***


    ;*****************************************************************
    ;
    ;   Phase_handler
    ;       The phase handler script is a dispatcher function of SCSI phase
    ;
    ;*****************************************************************

phase_handler:
    load DSA0, 4, ld_nexus                          ; reload DSA
    jump rel( command_phase ),        when CMD      ; wait for REQ
    jump rel( data_out_phase ),       if DATA_OUT   ; already latched REQ signal
    jump rel( message_out_phase ),    if MSG_OUT
    jump rel( data_in_phase ),        if DATA_IN
    jump rel( status_phase ),         if STATUS
    jump rel( message_in_phase ),     if MSG_IN
    int     unknown_phase


    ;*****************************************************************
    ;
    ; Message-Out phase
    ;
    ;*****************************************************************

message_out_phase:
    move kphase_MSG_OUT to SCRATCHB0                ; Set phase indicator
    store SCRATCHB0, 1, ld_phase_flag

    move from TLQ_MSGOp, when MSG_OUT               ; put out the message(s)
    jump rel( phase_handler )


        ; issueMessageOut - Driver entry point for Sync/Wide negotiation and
        ; to issue message Reject:

issueMessageOut:
    set     ATN                                     ; tell Target we have something to say
    clear   ACK
    jump rel( message_out_phase ),  when MSG_OUT    ; wait for REQ. Jump if msg-out phase.
    jump rel( phase_handler ),      if not MSG_IN   ; jump if weird phase
    move 1, ld_scratch+1,           when   MSG_IN   ; dump the msg byte
    clear ACK                                       ; accept Target's last msg-in byte
    jump rel( issueMessageOut )


    ;*****************************************************************
    ;
    ;   Command phase
    ;
    ;*****************************************************************

command_phase:
    move kphase_COMMAND to SCRATCHB0    ; Set phase indicator
    store SCRATCHB0, 1, ld_phase_flag

    clear ATN                           ; In case we missed the sending nego
    move FROM TLQ_CDBp, when CMD        ; issue the CDB
    jump rel( phase_handler )


    ;*****************************************************************
    ;
    ; Data_out_phase
    ;
    ;*****************************************************************

data_out_phase:
    move kphase_DATA_OUT to SCRATCHB0       ; Set phase indicator
    store SCRATCHB0, 1, ld_phase_flag

    call rel( driverXfer )                  ; call driver-built CHMOV instructions
    jump rel( phase_handler )               ; if all data xfer'd, get next phase

driverXfer:                                 ; get here from data-in code also
    load  SCRATCHA0, 4, DSAREL( TLQ_xferAdr )
    store SCRATCHA0, 4, doItPatch+4         ; *** patch the JUMP address
    move 0xFF to SCRATCHA1
    store SCRATCHA1, 1, DSAREL( TLQ_xferStarted )

doItPatch:
    jump 0x0333                             ; *** patched address



    ;*****************************************************************
    ;
    ; Data_in_phase
    ;   875 sets ATN if bad parity detected.
    ;   Use of CHMOV instructions assures that we properly handle
    ;   a leftover wide byte in the SWIDE or SODL register, depending
    ;   on the data direction. This can happen in either of two conditions:
    ;     1. The Target disconnects at an odd boundary. This is
    ;       extremely unlikely with disk devices.
    ;     2. The client passes either an odd buffer address or
    ;       an odd transfer count. When the Target disconnects (at
    ;       an even boundary, we end up with the extra wide
    ;       byte in SWIDE or SODL. MacOS does this with VM on.
    ;
    ;*****************************************************************

data_in_phase:
    move kphase_DATA_IN to SCRATCHB0        ; Set phase indicator
    store SCRATCHB0, 1, ld_phase_flag

    call rel( driverXfer )                  ; call driver-built CHMOV instructions

    ; The driver gets interrupted if a phase mismatch occurs as when
    ; the Target goes MSG-IN with a Disconnect.
    ; The driver codes either a RETURN if the Scatter/Gather list is complete or
    ; an INT if more Scatter/Gather elements need to be generated.
    ; On the Macintosh, client programs expect extra incoming data to be dumped.
    ; For example, during boot the ROM reads 512 bytes from a 2K-byte-sector CD.

bucket_loop:
    jump rel( phase_handler ), when not DATA_IN ; wait for phase, exit if changed
    CHMOV 1, ld_status, when DATA_IN            ; eat a byte
    jump rel( bucket_loop );                    ; keep dumping bytes


    ;*****************************************************************
    ;
    ; Status phase
    ;
    ;*****************************************************************

status_phase:
    move kphase_STATUS to SCRATCHB0             ; Set phase indicator
    store SCRATCHB0, 1, ld_phase_flag

    move 1, ld_status, when STATUS              ; Read Status byte from bus
    jump rel( phase_handler )


    ;*****************************************************************
    ;
    ; Message-In phase
    ;
    ;*****************************************************************

message_in_phase:
    move kphase_MSG_IN to SCRATCHB0             ; Set phase indicator
    store SCRATCHB0, 1, ld_phase_flag

    move 1, ld_message, when MSG_IN             ; Read byte from bus

    jump rel( cmdComplete ),        if 0x00     ; Command Complete
    jump rel( saveDataPointer ),    if 0x02     ; Save Data Pointer
    jump rel( disconnect_msg ),     if 0x04     ; Disconnect
    jump rel( ignoreWideResidue ),  if 0x23     ; Ignore Wide Residue
    jump rel( restoreDataPointer ), if 0x03     ; Restore Data Pointer
    jump rel( extended_msg ),       if 0x01     ; Extended message
    jump rel( msg_reject ),         if 0x07     ; Message Reject
        ; Identify,                 if 0x80-FF  ; Identify + LUN
        ; simple_queue_tag,         if 0x20     ; Simple Queue Tag
        ; initiate_recovery,        if 0x0F     ; Initiate Recovery
        ; linked_cde_complete,      if 0x0A/0x0B
    int unexpected_msg                          ; unknown

msg_reject:
    int  unknown_msg_reject

clearACK:                                       ; ENTRY point to end negotiation
    clear ACK
    jump rel( phase_handler )



    ;*****************************************************************
    ;
    ; Ignore Wide Residue
    ;
    ;*****************************************************************

ignoreWideResidue:      ; this is a two byte message so snag the 2nd byte here
    clear ACK
    move 1, ld_message+1, when MSG_IN       ; save residue count
    move SFBR to SCRATCHB2                  ; byte is still in SFBR. Position it.
    store SCRATCHB2, 1, DSAREL( TLQ_IWR )   ; Store residue count in Nexus for driver.
    clear ACK
    jump rel( phase_handler )


    ;*****************************************************************
    ;
    ; Extended message
    ;       Accept Wide and Synchronous Data Transfer messages
    ;
    ;*****************************************************************

extended_msg:
    clear ACK
    move 1, ld_message+1, when MSG_IN       ; read msg length byte from bus
    clear ACK
    move 1, ld_message+2, when MSG_IN       ; read ext msg code from bus
    clear ACK
        ; extended_identify,   IF 0x02
        ; modify_data_pointer, if 0x00
    jump rel( sdtr ),   if 0x01             ; jump if SDTR, sync negotiation msg
    jump rel( wdtr ),   if 0x03             ; jump if WDTR, wide negotiation msg
    int unexpected_ext_msg                  ; let driver deal with unknown


    ;*****************************************************************
    ;
    ; Command complete
    ;       The Command-Complete message is sent to indicate that the
    ;       IO operation has completed and valid status has been sent.
    ;       The Target should then disconnect.
    ;       SCRIPTS must spin until the IOdone mailbox is empty.
    ;       Then it sets the IOdone mailbox with the current Nexus.
    ;       The status message is analyzed.
    ;       If status is good, INTF the driver and jump to select_phase.
    ;       If status is NG, save it in the NEXUS and INT the driver.
    ;
    ;*****************************************************************

cmdComplete:
    move kphase_CMD_COMPLETE to SCRATCHB0       ; Set phase indicator
    store SCRATCHB0, 1, ld_phase_flag

    move SCNTL2 & 0X7F to SCNTL2                ; Clr SDU: SCSI Disconnect Unexpected
    clear ACK
    WAIT DISCONNECT

testMbxLp:                                      ; loop until IOdone mailbox empty
    load SCRATCHA0, 4, ld_IOdone_mailbox
    move SCRATCHA3 to SFBR                      ; A3 = semaphore
    jump rel( testMbxLp ), if not 0

        ; Fill in the IOdone mailbox with the following:
        ;   A0 = index to Nexus
        ;   A1 = Status
        ;   A2 = 0
        ;   A3 = semaphore (FF = set)
    load SCRATCHA0, 1, ld_nexus_index       ; A0 = index to Nexus
    load SCRATCHB0, 1, ld_status
    move SCRATCHB0 to SFBR
    move SFBR to SCRATCHA1                  ; A1 = Status
    move 0x00 to SCRATCHA2                  ; A2 = 0
    move 0xFF to SCRATCHA3                  ; A3 = semaphore IOdone mailbox
    store SCRATCHA0, 4, ld_IOdone_mailbox

    move SCRATCHA1 to SFBR                  ; Test the Status of this IO
        ; SFBR = status msg
        ; Test status - If good, Interrupt on the fly and jump to select phase
    intfly 0xFF, if 0 and mask 0xC1         ; mask off reserved bits
    jump rel( select_phase ), if 0 and mask 0xC1
    int     status_error                    ; Status err. Interrupt driver & stop


    ;*****************************************************************
    ;
    ; Disconnect
    ;       The 8xx Accepts the disconnection and jumps to the select_phase
    ;       to check for another IO
    ;
    ;*****************************************************************

disconnect_msg:
    load SCRATCHB0, 1, ld_phase_flag
    move SCRATCHB0 to SFBR
        ; If we got here from reselect just bailout since ld_nexus is
        ; not setup and the code using it is not needed anyway (no data xfer)
    jump rel( bailout ), if kphase_RESELECT

    move kphase_DISCONNECT to SCRATCHB0
    store SCRATCHB0, 1, ld_phase_flag

bailout:
    move 0xFF to SCRATCHB3                  ; invalidate nexus index for driver
    store SCRATCHB3, 1, ld_nexus_index+3
    move SCNTL2 & 0x7F to SCNTL2            ; Clr SDU: SCSI Disconnect Unexpected
    clear ACK
    WAIT DISCONNECT                         ; wait for bus-free
    jump rel( select_phase )                ; go see if more to do


    ;******************************************************************
    ;
    ; ??? mlj - saveDataPointer and restoreDataPointer are incorrect.
    ; ??? They basically do nothing.
    ; Save Data Pointer
    ;
    ;*****************************************************************

saveDataPointer:
    move kphase_saveDataPointer to SCRATCHB0
    store SCRATCHB0, 1, ld_phase_flag
    clear ACK
    jump rel( phase_handler )


    ;******************************************************************
    ;
    ; ??? mlj - saveDataPointer and restoreDataPointer are incorrect.
    ; ??? They basically do nothing.
    ; Restore Data Pointer
    ;       The local values still blocks, still bytes and data address
    ;       must be loaded from the corresponding NEXUS data set.
    ;       This message should followed an IDE (parity error)
    ;
    ;*****************************************************************

restoreDataPointer:
    move kphase_restoreDataPointer to SCRATCHB0
    store SCRATCHB0, 1, ld_phase_flag
    clear ACK
    jump rel( phase_handler )


    ;*****************************************************************
    ;
    ; Synchronous data transfer request or response
    ;
    ;*****************************************************************
sdtr:
    move 2, ld_message+3, when MSG_IN       ; Read period & offset from bus
    int negotiateSDTR


    ;***************************************************************************
    ;
    ; Wide Data Transfer request or response
    ;
    ;***************************************************************************
wdtr:
    move 1, ld_message+3, when MSG_IN       ; get Transfer Width Exponent fm bus
    int  negotiateWDTR


    ;*****************************************************************
    ;
    ; Reselect phase
    ;       The chip waits here either for a Reselection from a Target or
    ;       a SIGP from the driver indicating something in the mailbox.
    ;       If reselected, the script uses the Nexus value which is either
    ;       a Tag or a SCSI ID/LUN combo to lookup the Nexus.
    ;       Then init the SXFER and SCNTL3 registers from the device config table.
    ;
    ;*****************************************************************

try_reselect:                               ; Select failed - probably reselecting
                                            ; Cf NCR Errata Listing 117 Item 1:
    move SCNTL0 & 0xDF to SCNTL0            ; clr Start bit
    move CTEST2 | 0x00 to CTEST2            ; Clear SIGP bit from ISTAT reg

reselect_phase:
    move kphase_RESELECT to SCRATCHB0       ; Set phase indicator
    store SCRATCHB0, 1, ld_phase_flag

    move 0xFF to SCRATCHB3                  ; invalidate nexus index for driver
    store SCRATCHB3, 1, ld_nexus_index+3

        ; wait here for reselect from a Target
        ; or SIGP from the driver

    WAIT RESELECT REL( select_phase )       ; jump if SIGP

        ; Reselected:

    move SSID to SFBR                       ; SSID = [ Valxxx Scsi_id ]
    int unknown_reselect, if 0 and mask 0x7F; Interrupt if VAL bit not set
    move SFBR & 0x0F to SCRATCHB0           ; B0 = Target ID
    store SCRATCHB0, 1, ld_scsi_id          ; save it

    call rel( initContext )                 ; setup sync regs here

    int no_msgin_after_reselect, when not MSG_IN

    move 1, ld_message, when MSG_IN         ; Read Identify byte from bus

        ; if another REQ is asserted, a SimpleQueueTag message should be next

    clear ACK                               ; notify Target: msg byte rx'd
    jump rel( getNextMsg ), when MSG_IN     ; jump if SimpleQueueTag coming

        ; untagged operation:

    move SFBR & 0x07 to SCRATCHA0           ; isolate LUN from Identify byte

    load SCRATCHB0, 1, ld_scsi_id           ; B0 = Target ID
    clear CARRY
    move SCRATCHB0 SHL SFBR                 ; shift left #1
    move SFBR SHL SCRATCHB0                 ; shift left #2
    move SCRATCHB0 SHL SFBR                 ; shift left #3
    move SCRATCHA0 | SFBR to SCRATCHA0      ; form Nexus index = 0b0TTTTLLL

    store SCRATCHA0, 1, ld_nexus_index      ; store as index to Nexus
    jump rel( haveNexusIndex )

        ; should be tagged operation:

getNextMsg:
    move 1, ld_message,  when MSG_IN        ; read message byte from bus
    jump rel( disconnect_msg ), if 0x04     ; if Disconnect, oh well.
    clear ACK
    jump rel( phase_handler ), if not 0x20; Branch if not Queue tag code
        ; get the Queue Tag and save as the nexus index
    move 1, ld_nexus_index, when MSG_IN     ; Nexus index <- Tag from bus
    clear ACK                               ; acknowledge it

haveNexusIndex:
    move 0x00 to SCRATCHB3                  ; clear invalid-nexus-index flag
    store SCRATCHB3, 1, ld_nexus_index+3 
    call rel( findNexusFromIndex )          ; set DSA <- Nexus pointer
    jump rel( phase_handler )               ; start handling phases.


        ;*****************************************************************
        ;
        ; AbortMailbox - Abort (or BusDeviceReset) the mailbox entry.
        ; This is a queued operation - not an immediate
        ; operation as is issueAbort_BDR.
        ;   The Abort message clears all IO processes for the
        ;   selecting Initiator on the specified LUN.
        ;
        ;   The Bus Device Reset message clears all IO processes for
        ;   all Initiators on all LUNs of selected Target.
        ;   It forces a hard reset condition to the selected SCSI device.
        ;
        ;   A0 = Identify byte (0xC0 + LUN  N.B. Disconnect allowed)
        ;   A1 = Tag, if any
        ;   A2 = SCSI ID
        ;   A3 = Abort code Abort=0x06; Abort Tag=0D; Bus Device Reset=0x0C
        ;
        ;   Mailbox not cleared by SCRIPTS so that driver can find SCSI ID when done
        ;   N.B.: Device is Async and Narrow after BDR!!!
        ;   Driver must set the device config table values accordingly.
        ;*****************************************************************

AbortMailbox:
    move kphase_ABORT_MAILBOX to SCRATCHB0      ; Set phase code
    store SCRATCHB0, 1, ld_phase_flag
        
    move 0xFF to SCRATCHB3                      ; invalidate nexus index for driver
    store SCRATCHB3, 1, ld_nexus_index+3

    load  SCRATCHB2, 1, ld_AbortBdr_mailbox+2   ; get SCSI ID
    store SCRATCHB2, 1, AbortSelect+2           ; *** Patch the Select/ATN instruction

AbortSelect:
    SELECT ATN 0, REL( try_reselect )           ; *** Patched SCSI ID

    move SCRATCHA1 to SFBR                      ; check for Tag
    jump rel( taggedAbort ) if not 0x00         ; jump if tagged abort

        ; untagged Abort or BusDeviceReset:

    move SCRATCHA3 to SFBR                      ; position the abort code
    move SFBR to SCRATCHA1
    store SCRATCHA0, 2, ld_scratch              ; Store Identify and Abort msgs
    move 0x00 to SCNTL2                         ; Clr SDU SCSI Disconnect Unexpected
    move 2, ld_scratch , when MSG_OUT           ; emit Identify and Abort messages
    WAIT DISCONNECT
    int abort_mailbox

        ; AbortTag:

taggedAbort:
    move SCRATCHA1 to SFBR                      ; position the Tag
    move SFBR to SCRATCHA2
    move 0x20 to SCRATCHA1                      ; gen SimpleQueueTag code
    store SCRATCHA0, 4, ld_scratch              ; store Identify, SQT, Tag, AbortTag
    move 0x00 to SCNTL2                         ; Clr SDU SCSI Disconnect Unexpected
    move 4, ld_scratch, when MSG_OUT            ; emit all 4 bytes
    WAIT DISCONNECT
    int abort_mailbox


        ;*****************************************************************
        ;
        ; issueAbort_BDR - Abort (or BusDeviceReset) the current operation.
        ; This is an immediate operation - not a queued operation
        ; as is AbortMailbox.
        ;   The Abort message clears all IO processes for the
        ;   selecting Initiator on the specified LUN.
        ;
        ;   The Bus Device Reset message clears all IO processes for
        ;   all Initiators on all LUNs of selected Target.
        ;   It forces a hard reset condition to the selected SCSI device.
        ;
        ;*****************************************************************

issueAbort_BDR:
    move kphase_ABORT_CURRENT to SCRATCHB0      ; Set phase code
    store SCRATCHB0, 1, ld_phase_flag

    move ISTAT & 0x08 to SFBR                   ; see if Target connected to bus
    int abort_current, if 0                     ; interrupt driver if not connected

    SET ATN                                     ; get Target's attention
    load DSA0, 4, ld_nexus                      ; load pointer to Nexus

bucketLoop:
    clear ACK
    jump rel( sendAbortBDR ),   when MSG_OUT    ; wait for REQ. Jump if OK.

    jump rel( BucketInStatus ), if STATUS       ; bit bucket in
    jump rel( BucketInMsg ),    if MSG_IN       ; bit bucket in
    jump rel( BucketInData ),   if DATA_IN      ; bit bucket in

    move 0xAD to SCRATCHA0
    jump rel( BucketOutData ),  if DATA_OUT     ; bit bucket out
    jump rel( BucketOutCmd ),   if CMD          ; bit bucket out
    int unknown_phase                           ; back to driver for harsher measures


BucketInStatus:
    move 1, ld_scratch, when STATUS             ; eat the Status byte
    jump rel( bucketLoop );                     ; keep bit-bucketing bytes

BucketInMsg:
    move 1, ld_scratch, when MSG_IN             ; eat a message byte
    jump rel( bucketLoop );                     ; keep bit-bucketing bytes

BucketInData:
    move 1, ld_scratch, when DATA_IN            ; eat a data byte
    jump rel( bucketLoop );                     ; keep bit-bucketing bytes

BucketOutData:
    move SCRATCHA0 xor 0x73 to SCRATCHA0        ; gen 0xDEAD ...
    store SCRATCHA0, 1, ld_scratch
    move 1, ld_scratch, when DATA_OUT           ; pad a byte out
    jump rel( bucketLoop );                     ; keep bit-bucketing bytes

BucketOutCmd:
    move 0x00 to SCRATCHA0                      ; load Null, TestUnitReady, whatever
    store SCRATCHA0, 1, ld_scratch
    move 1, ld_scratch, when CMD                ; pad a byte out
    jump rel( bucketLoop );                     ; keep bit-bucketing bytes


sendAbortBDR:
    move 0x00 to SCNTL2                         ; Clr SDU SCSI Disconnect Unexpected
    move  1, ld_AbortCode, when MSG_OUT         ; Send Abort(06) or BDR(0C) message
    load  SCRATCHA0, 4, ld_zeroes               ; load 0's
    store SCRATCHA0, 4, ld_AbortCode            ; clear the Abort code
    WAIT DISCONNECT
    int abort_current                           ; went BusFree - tell Driver
