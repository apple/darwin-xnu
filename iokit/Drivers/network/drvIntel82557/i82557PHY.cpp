/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1996 NeXT Software, Inc.  All rights reserved. 
 *
 * i82557PHY.cpp
 *
 */

#include "i82557.h"
#include "i82557PHY.h"

//---------------------------------------------------------------------------
// Function: _logMDIStatus
//
// Purpose:
//   Dump the contents of the MDI status register.

static inline void 
_logMDIStatus(mdi_reg_t reg)
{
	if (reg & MDI_STATUS_T4)
		IOLog("PHY: T4 capable\n");
    if (reg & MDI_STATUS_TX_FD)
		IOLog("PHY: 100Base-TX full duplex capable\n");
    if (reg & MDI_STATUS_TX_HD)
		IOLog("PHY: 100Base-TX half duplex capable\n");
    if (reg & MDI_STATUS_10_FD)
		IOLog("PHY: 10Base-T full duplex capable\n");
    if (reg & MDI_STATUS_10_HD)
		IOLog("PHY: 10Base-T half duplex capable\n");
    if (reg & MDI_STATUS_EXTENDED_CAPABILITY)
		IOLog("PHY: has extended capability registers\n");
    if (reg & MDI_STATUS_JABBER_DETECTED)
		IOLog("PHY: jabberDetect set\n");
    if (reg & MDI_STATUS_AUTONEG_CAPABLE)
		IOLog("PHY: auto negotiation capable\n");
    IOLog("PHY: link is %s\n", (reg & MDI_STATUS_LINK_STATUS) ? "UP" : "DOWN");
    return;
}

//---------------------------------------------------------------------------
// Function: _getModelId
//
// Purpose:
//   Read the MDI ID registers and form a single 32-bit id.

UInt32 Intel82557::_phyGetID()
{
    UInt16	id1, id2;
	_mdiReadPHY(phyAddr, MDI_REG_PHYID_WORD_1, &id1);
	_mdiReadPHY(phyAddr, MDI_REG_PHYID_WORD_2, &id2);
    return ((id2 << 16) | id1);
}

//---------------------------------------------------------------------------
// Function: _phySetMedium
//
// Purpose:
//   Setup the PHY to the medium type given.
//   Returns true on success.

bool Intel82557::_phySetMedium(mediumType_t medium)
{
	mdi_reg_t       status;
	mdi_reg_t       control;
	mediumType_t    phyMedium = medium;
	UInt32          mediumCapableMask;

	// Reset PHY before changing medium selection.
	//
	_phyReset();

	// Get local capability.
	//
	_mdiReadPHY(phyAddr, MDI_REG_STATUS, &status);

	// Create a medium capable mask.
	//
	mediumCapableMask = (status >> 11) & 0x1f;

	// Force the PHY's data rate and duplex settings if the medium type
	// chosen is not AUTO.
	//
	if (phyMedium != MEDIUM_TYPE_AUTO) {
		if ((MEDIUM_TYPE_TO_MASK(phyMedium) & mediumCapableMask) == 0) {
			// Hardware is not capable of selecting the user-selected
			// medium.
			//
			return false;
		}
		else {
			// Medium chosen is valid, go ahead and set PHY.
			//
			bool speed100   = false;
			bool fullDuplex = false;
			
			if ((medium == MEDIUM_TYPE_TX_HD) ||
				(medium == MEDIUM_TYPE_TX_FD) ||
				(medium == MEDIUM_TYPE_T4))
				speed100 = true;

			if ((medium == MEDIUM_TYPE_10_FD) || (medium == MEDIUM_TYPE_TX_FD))
				fullDuplex = true;

			// Disable auto-negotiation function and force speed + duplex.
			//
			IOSleep(300);

			control = ((speed100 ? MDI_CONTROL_100 : 0) |
			           (fullDuplex ? MDI_CONTROL_FULL_DUPLEX : 0));

			_mdiWritePHY(phyAddr, MDI_REG_CONTROL, control);

			VPRINT("%s: user forced %s Mbit/s%s mode\n", getName(),
				speed100 ? "100" : "10",
				fullDuplex ? " full duplex" : "");

			IOSleep(50);
		}
	}
	else {
		// For MEDIUM_TYPE_AUTO, enable and restart auto-negotiation.
		//
		control = MDI_CONTROL_AUTONEG_ENABLE;
		_mdiWritePHY(phyAddr, MDI_REG_CONTROL, control);
		IOSleep(1);
		control |= MDI_CONTROL_RESTART_AUTONEG;
		_mdiWritePHY(phyAddr, MDI_REG_CONTROL, control);
	}

	// Some special bit twiddling for NSC83840.
	//
	if (phyID == PHY_MODEL_NSC83840) {
		/* set-up National Semiconductor 83840 specific registers */
		
		mdi_reg_t	reg;

		VPRINT("%s: setting NSC83840-specific registers\n", getName());
		_mdiReadPHY(phyAddr, NSC83840_REG_PCR, &reg);

		/*
		 * This bit MUST be set, otherwise the card may not transmit at
		 * all in 100Mb/s mode. This is specially true for 82557 cards
		 * with the DP83840 PHY.
		 *
		 * In the NSC documentation, bit 10 of PCS register is labeled
		 * as a reserved bit. What is the real function of this bit?
		 */
		reg |= (NSC83840_PCR_TXREADY | NSC83840_PCR_CIM_DIS);

		_mdiWritePHY(phyAddr, NSC83840_REG_PCR, reg);
	}

	currentMediumType = medium;

	return true;
}

//---------------------------------------------------------------------------
// Function: _phyAddMediumType
//
// Purpose:
//   Add a single medium object to the medium dictionary.
//   Also add the medium object to an array for fast lookup.

bool Intel82557::_phyAddMediumType(UInt32 type, UInt32 speed, UInt32 code)
{	
	IONetworkMedium	* medium;
	bool              ret = false;
	
	medium = IONetworkMedium::medium(type, speed, 0, code);
	if (medium) {
		ret = IONetworkMedium::addMedium(mediumDict, medium);
		if (ret)
			mediumTable[code] = medium;
		medium->release();
	}
	return ret;
}

//---------------------------------------------------------------------------
// Function: _phyPublishMedia
//
// Purpose:
//   Examine the PHY capabilities and advertise all supported medium types.
//
// FIXME: Non PHY medium types are not probed.

#define MBPS 1000000 

void Intel82557::_phyPublishMedia()
{
    mdi_reg_t   status;

	// Read the PHY's media capability.
	//
	_mdiReadPHY(phyAddr, MDI_REG_STATUS, &status);

	_phyAddMediumType(kIOMediumEthernetAuto,
                      0,
                      MEDIUM_TYPE_AUTO);

	if (status & MDI_STATUS_10_HD)
		_phyAddMediumType(kIOMediumEthernet10BaseT | kIOMediumOptionHalfDuplex,
                          10 * MBPS,
                          MEDIUM_TYPE_10_HD);

	if (status & MDI_STATUS_10_FD)
		_phyAddMediumType(kIOMediumEthernet10BaseT | kIOMediumOptionFullDuplex,
                          10 * MBPS,
                          MEDIUM_TYPE_10_FD);

	if (status & MDI_STATUS_TX_HD)
		_phyAddMediumType(
                    kIOMediumEthernet100BaseTX | kIOMediumOptionHalfDuplex,
                    100 * MBPS,
                    MEDIUM_TYPE_TX_HD);

	if (status & MDI_STATUS_TX_FD)
		_phyAddMediumType(
                    kIOMediumEthernet100BaseTX | kIOMediumOptionFullDuplex,
                    100 * MBPS,
                    MEDIUM_TYPE_TX_FD);

	if (status & MDI_STATUS_T4)
		_phyAddMediumType(kIOMediumEthernet100BaseT4,
                          100 * MBPS,
                          MEDIUM_TYPE_T4);
}

//---------------------------------------------------------------------------
// Function: _phyReset
//
// Purpose:
//   Reset the PHY.

#define PHY_RESET_TIMEOUT		100		// ms
#define PHY_RESET_DELAY			10		// ms
#define PHY_POST_RESET_DELAY	300		// us

bool Intel82557::_phyReset()
{
	int 		i = PHY_RESET_TIMEOUT;
	mdi_reg_t	control;

	if (!_mdiReadPHY(phyAddr, MDI_REG_CONTROL, &control))
		return false;
	
	// Set the reset bit in the PHY Control register
	//
	_mdiWritePHY(phyAddr, MDI_REG_CONTROL, control | MDI_CONTROL_RESET);
	
	// Wait till reset process is complete (MDI_CONTROL_RESET returns to zero)
	//
	while (i > 0) {
		if (!_mdiReadPHY(phyAddr, MDI_REG_CONTROL, &control))
			return false;
		if ((control & MDI_CONTROL_RESET) == 0) {
			IODelay(PHY_POST_RESET_DELAY);
			return true;
		}
		IOSleep(PHY_RESET_DELAY);
		i -= PHY_RESET_DELAY;
	}
	return false;
}

//---------------------------------------------------------------------------
// Function: _phyWaitAutoNegotiation
//
// Purpose:
//   Wait until auto-negotiation is complete.

#define PHY_NWAY_TIMEOUT				5000	// ms
#define PHY_NWAY_DELAY					20		// ms

bool Intel82557::_phyWaitAutoNegotiation()
{
	int 		i = PHY_NWAY_TIMEOUT;
	mdi_reg_t	status;
	
	while (i > 0) {
		if (!_mdiReadPHY(phyAddr, MDI_REG_STATUS, &status))
			return false;
		
		if (status & MDI_STATUS_AUTONEG_COMPLETE)
			return true;
		
		IOSleep(PHY_NWAY_DELAY);
		i -= PHY_NWAY_DELAY;
	}
	return false;
}

//---------------------------------------------------------------------------
// Function: _phyProbe
//
// Purpose:
//   Find out which PHY is active.
//
#define AUTONEGOTIATE_TIMEOUT	35

bool Intel82557::_phyProbe()
{
    bool		foundPhy1 = false;
    mdi_reg_t	control;
    mdi_reg_t	status;

    if (phyAddr == PHY_ADDRESS_I82503) {
		VPRINT("%s: overriding to use Intel 82503", getName());
		return true;
    }

    if (phyAddr > 0 && phyAddr < PHY_ADDRESS_MAX) {
		VPRINT("%s: looking for Phy 1 at address %d\n", getName(), phyAddr);
		_mdiReadPHY(phyAddr, MDI_REG_CONTROL, &control);
		_mdiReadPHY(phyAddr, MDI_REG_STATUS, &status);	// do it twice
		_mdiReadPHY(phyAddr, MDI_REG_STATUS, &status);
		if (control == 0xffff || (status == 0 && control == 0)) 
		{
	    	VPRINT("%s: Phy 1 at address %d does not exist\n", getName(),
		   		phyAddr);
		}
		else {
	    	VPRINT("%s: Phy 1 at address %d exists\n", getName(), phyAddr);
	    	foundPhy1 = true;
			if (status & MDI_STATUS_LINK_STATUS) {
				VPRINT("%s: found Phy 1 at address %d with link\n", 
					getName(), phyAddr);
				return true;	// use PHY1
	    	}
		}
    }

	// PHY1 does not exist, or it does not have valid link.
	// Try PHY0 at address 0.
	//
	_mdiReadPHY(PHY_ADDRESS_0, MDI_REG_CONTROL, &control);
	_mdiReadPHY(PHY_ADDRESS_0, MDI_REG_STATUS, &status);

    if (control == 0xffff || (status == 0 && control == 0)) {
		if (phyAddr == 0) { /* if address forced to 0, then fail */
			IOLog("%s: phy0 not detected\n", getName());
			return false;
		}
		if (foundPhy1 == true) {
			VPRINT("%s: no Phy at address 0, using Phy 1 without link\n", 
				getName());
			return true;	// use PHY1 without a valid link
		}
		VPRINT("%s: no Phy at address 0, defaulting to 82503\n", getName());
		phyAddr = PHY_ADDRESS_I82503;
		return true;
    }

	// must isolate PHY1 electrically before using PHY0.
	//
    if (foundPhy1 == true) {
		control = MDI_CONTROL_ISOLATE;
		_mdiWritePHY(phyAddr, MDI_REG_CONTROL, control);
		IOSleep(1);
    }

	// Enable and restart auto-negotiation on PHY0.
	//
    VPRINT("%s: starting auto-negotiation on Phy 0", getName());
    control = MDI_CONTROL_AUTONEG_ENABLE;
	_mdiWritePHY(PHY_ADDRESS_0, MDI_REG_CONTROL, control);
    IOSleep(1);
    control |= MDI_CONTROL_RESTART_AUTONEG;
	_mdiWritePHY(PHY_ADDRESS_0, MDI_REG_CONTROL, control);

	for (int i = 0; i < AUTONEGOTIATE_TIMEOUT; i++) {
		_mdiReadPHY(PHY_ADDRESS_0, MDI_REG_STATUS, &status);
	    if (status & MDI_STATUS_AUTONEG_COMPLETE)
			break;
	    IOSleep(100);
    }
	_mdiReadPHY(PHY_ADDRESS_0, MDI_REG_STATUS, &status);
	_mdiReadPHY(PHY_ADDRESS_0, MDI_REG_STATUS, &status);
	_mdiReadPHY(PHY_ADDRESS_0, MDI_REG_STATUS, &status);
    if ((status & MDI_STATUS_LINK_STATUS) || foundPhy1 == false) {
		VPRINT("%s: using Phy 0 at address 0\n", getName());
		phyAddr = 0;
		return true;
    }

	// Isolate PHY0.
	//
    VPRINT("%s: using Phy 1 without link\n", getName());
    control = MDI_CONTROL_ISOLATE;
	_mdiWritePHY(PHY_ADDRESS_0, MDI_REG_CONTROL, control);
    IOSleep(1);

	// Enable and restart auto-negotiation on PHY1.
	//
    control = MDI_CONTROL_AUTONEG_ENABLE;
	_mdiWritePHY(phyAddr, MDI_REG_CONTROL, control);
    IOSleep(1);
    control |= MDI_CONTROL_RESTART_AUTONEG;
	_mdiWritePHY(phyAddr, MDI_REG_CONTROL, control);

	phyID = _phyGetID();
    VPRINT("%s: PHY model id is 0x%08lx\n", getName(), phyID);
    phyID &= PHY_MODEL_MASK;

    return true;
}

//---------------------------------------------------------------------------
// Function: _phyGetMediumTypeFromBits
//
// Purpose:
//   Return the medium type that correspond to the given specifiers.

mediumType_t Intel82557::_phyGetMediumTypeFromBits(bool rate100,
                                                   bool fullDuplex,
                                                   bool t4)
{
	mediumType_t  mediumType;

	if (t4) {
		mediumType = MEDIUM_TYPE_T4;
	}
	else if (rate100) {
		if (fullDuplex)
			mediumType = MEDIUM_TYPE_TX_FD;
		else
			mediumType = MEDIUM_TYPE_TX_HD;
	}
	else {
		if (fullDuplex)
			mediumType = MEDIUM_TYPE_10_FD;
		else
			mediumType = MEDIUM_TYPE_10_HD;
	}
	
	return mediumType;
}

//---------------------------------------------------------------------------
// Function: _phyGetMediumWithCode
//
// Purpose:
//   Returns the IONetworkMedium object associated with the given type.

IONetworkMedium * Intel82557::_phyGetMediumWithType(UInt32 type)
{
	if (type < MEDIUM_TYPE_INVALID)
		return mediumTable[type];
	else
		return 0;
}

//---------------------------------------------------------------------------
// Function: _phyReportLinkStatus
//
// Purpose:
//   Called periodically to monitor for link changes. When a change
//   is detected, determine the current link and report it to the
//   upper layers by calling IONetworkController::setLinkStatus().

void Intel82557::_phyReportLinkStatus( bool firstPoll = false )
{
    UInt16  phyStatus;
    UInt16  phyStatusChange;

    // Read PHY status register.

    _mdiReadPHY( phyAddr, MDI_REG_STATUS, &phyStatus );

    // Detect a change in the two link related bits.
    // Remember that the link status bit will latch a link fail
    // condition (should not miss a link down event).

    phyStatusChange = ( phyStatusPrev ^ phyStatus ) &
                      ( MDI_STATUS_LINK_STATUS |
                        MDI_STATUS_AUTONEG_COMPLETE );

    if ( phyStatusChange || firstPoll )
    {
        if ( firstPoll )
        {
            // For the initial link status poll, wait a bit, then
            // re-read the status register to clear any latched bits.

            _phyWaitAutoNegotiation();
            _mdiReadPHY( phyAddr, MDI_REG_STATUS, &phyStatus );
            _mdiReadPHY( phyAddr, MDI_REG_STATUS, &phyStatus );
        }

        // IOLog("PhyStatus: %04x\n", phyStatus);

        // Determine the link status.

        if ( ( phyStatus & MDI_STATUS_LINK_STATUS ) &&
             ( phyStatus & MDI_STATUS_AUTONEG_COMPLETE ) )
        {
            // Excellent, link is up.
            
            IONetworkMedium * activeMedium;

            activeMedium = _phyGetMediumWithType( _phyGetActiveMedium() );
            
            setLinkStatus( kIONetworkLinkValid | kIONetworkLinkActive,
                           activeMedium );
            
            // IOLog("link is up %lx\n",
            //      activeMedium ? activeMedium->getType() : 0);
        }
        else
        {
            // Link is down.

            setLinkStatus( kIONetworkLinkValid, 0 );
            
            // IOLog("link is down\n");
        }

        // Save phyStatus for the next run.

        phyStatusPrev = phyStatus;
    }
}

//---------------------------------------------------------------------------
// Function: _phyGetActiveMedium
//
// Purpose:
//   Once the PHY reports that the link is up, this method can be called
//   to return the type of link that was established.

mediumType_t Intel82557::_phyGetActiveMedium()
{
    mdi_reg_t     reg;
    mediumType_t  medium;

    do {
        // For the simple case where the media selection is not
        // automatic (e.g. forced to 100BaseTX).

        if ( currentMediumType != MEDIUM_TYPE_AUTO )
        {
            medium = currentMediumType;
            break;
        }

        // i82553 has a special register for determining the speed and
        // duplex mode settings.

        if ( ( phyID == PHY_MODEL_I82553_A_B ) ||
             ( phyID == PHY_MODEL_I82553_C ) )
        {
            _mdiReadPHY( phyAddr, I82553_REG_SCR, &reg );

            medium = _phyGetMediumTypeFromBits( reg & I82553_SCR_100,
                                                reg & I82553_SCR_FULL_DUPLEX,
                                                reg & I82553_SCR_T4 );
            break;
        }
        else if ( phyID == PHY_MODEL_NSC83840 )
        {
            // For NSC83840, we use the 83840 specific register to determine
            // the link speed and duplex mode setting. Early 83840 devices
            // did not seem to report the remote capabilities when the link
            // partner does not support NWay.

            mdi_reg_t  exp;

            _mdiReadPHY( phyAddr, MDI_REG_ANEX, &exp );

            if ( ( exp & MDI_ANEX_LP_AUTONEGOTIABLE ) == 0 )
            {
                _mdiReadPHY( phyAddr, NSC83840_REG_PAR, &reg );

                medium = _phyGetMediumTypeFromBits(
                             !(reg & NSC83840_PAR_SPEED_10),
                              (reg & NSC83840_PAR_DUPLEX_STAT),
                              0 );
                break;
            }
        }

        // For generic PHY, use the standard PHY registers.
        //	
        // Use the local and remote capability words to determine the
        // current active medium.

        mdi_reg_t	lpa;
        mdi_reg_t	mya;
            
        _mdiReadPHY( phyAddr, MDI_REG_ANLP, &lpa );
        _mdiReadPHY( phyAddr, MDI_REG_ANAR, &mya );
    
        mya &= lpa;	// obtain common capabilities mask.
    
        // Observe PHY medium precedence.

        if ( mya & MDI_ANAR_TX_FD )      medium = MEDIUM_TYPE_TX_FD;
        else if ( mya & MDI_ANAR_T4 )    medium = MEDIUM_TYPE_T4;
        else if ( mya & MDI_ANAR_TX_HD ) medium = MEDIUM_TYPE_TX_HD;
        else if ( mya & MDI_ANAR_10_FD ) medium = MEDIUM_TYPE_10_FD;
        else                             medium = MEDIUM_TYPE_10_HD;
    }
    while ( false );

    return medium;
}
