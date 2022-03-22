/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef __SEP_HMAC_DEFS_H__
#define __SEP_HMAC_DEFS_H__

/* this files provides definitions required for HMAC engine drivers
   it is used by both FW driver as well as OEM-SaSi driver.          */
#define HMAC_DECRYPTED_OPAD_CONST_BLOCK 0x601D1102, 0xAD34E4AA, 0xB9351FAA, 0xD7356DF1
#define HMAC_DECRYPTED_IPAD_CONST_BLOCK 0xA8473C7E, 0x2AE67627, 0x50ADFC61, 0xEE6F3117

#define AES_CTR_NO_COUNTER_INC_REG_ADDR 0x4D8

#endif /* __SEP_HMAC_DEFS_H__ */
