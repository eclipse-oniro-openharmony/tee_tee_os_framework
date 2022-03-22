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

#ifndef _NVM_DEF_H
#define _NVM_DEF_H

#ifdef __cplusplus
extern "C" {
#endif

/* General definitions */
/* ******************** */

/* message token to sep */
#ifndef HOST_SEP_MSG_TOKEN_HEAD
#define HOST_SEP_MSG_TOKEN_HEAD 0x02558808UL
#endif

/* start address of the shared RAM */
#ifndef DX_SHARED_RAM_START_ADDR
#define DX_SHARED_RAM_START_ADDR 0x60000000
#endif

/* size of the shared RAM */
#ifndef DX_SHARED_RAM_SIZE
#define DX_SHARED_RAM_SIZE 0x4000
#endif

/* ------------------------------
    DEFS from SEPDriver.c
-------------------------------- */
#define SEPDRIVER_START_MESSAGE_TOKEN 0X02558808

#define MAX_NUM_OF_INPUT_RANGES  4
#define MAX_NUM_OF_OUTPUT_RANGES 4

#define DX_CC_INIT_TOKEN                      0x08641326
#define DX_CC_INIT_PRIMARY_TYPE               1
#define DX_CC_INIT_DISABLED_MODULES_TYPE      2
#define DX_CC_INIT_INPUT_INVALID_RANGES_TYPE  3
#define DX_CC_INIT_OUTPUT_INVALID_RANGES_TYPE 4
#define DX_CC_INIT_SW_MINIMUM_VERSION_TYPE    5

#ifdef __cplusplus
}
#endif

#endif
