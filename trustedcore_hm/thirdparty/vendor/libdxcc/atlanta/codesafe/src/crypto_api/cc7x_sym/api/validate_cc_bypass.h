/****************************************************************************
* The confidential and proprietary information contained in this file may    *
* only be used by a person authorised under and to the extent permitted      *
* by a subsisting licensing agreement from ARM Limited or its affiliates.    *
* 	(C) COPYRIGHT [2001-2017] ARM Limited or its affiliates.	     *
*	    ALL RIGHTS RESERVED						     *
* This entire notice must be reproduced on all copies of this file           *
* and copies of this file may only be made by a person if such person is     *
* permitted to do so under the terms of a subsisting license agreement       *
* from ARM Limited or its affiliates.					     *
*****************************************************************************/

#ifndef VALIDATE_CC_BYPASS_H
#define VALIDATE_CC_BYPASS_H

/*!
 * validate DMA object structure
 *
 * \param dmaObj the DMA object
 * \param dataSize Data size given by the user (relevent only for SRAM data)
 *
 * \return 0 on success, (-1) if ( dataSize != dma object data size), (-2) if sram pointer is out of range
 */

int validateParams(uint8_t *data, uint32_t dataSize);


#endif
