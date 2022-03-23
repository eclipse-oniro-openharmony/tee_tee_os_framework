/* **************************************************************
 *  Copyright 2014 (c) Discretix Technologies Ltd.              *
 *  This software is protected by copyright, international      *
 *  treaties and various patents. Any copy, reproduction or     *
 *  otherwise use of this software must be authorized in a      *
 *  license agreement and include this Copyright Notice and any *
 *  other notices specified in the license agreement.           *
 *  Any redistribution in binary form must be authorized in the *
 *  license agreement and include this Copyright Notice and     *
 *  any other notices specified in the license agreement and/or *
 *  in materials provided with the binary distribution.         *
 * ************************************************************* */

#ifndef __SEP_HMAC_DEFS_H__
#define __SEP_HMAC_DEFS_H__

/* this files provides definitions required for HMAC engine drivers
   it is used by both FW driver as well as OEM-CRYS driver.          */
#define HMAC_DECRYPTED_OPAD_CONST_BLOCK 0x601D1102, 0xAD34E4AA, 0xB9351FAA, 0xD7356DF1
#define HMAC_DECRYPTED_IPAD_CONST_BLOCK 0xA8473C7E, 0x2AE67627, 0x50ADFC61, 0xEE6F3117

#define AES_CTR_NO_COUNTER_INC_REG_ADDR 0x4D8

#endif /* __SEP_HMAC_DEFS_H__ */
