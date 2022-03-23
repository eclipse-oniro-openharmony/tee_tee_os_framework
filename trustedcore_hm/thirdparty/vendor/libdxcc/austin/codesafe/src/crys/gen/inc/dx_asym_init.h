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

#ifndef DX_ASYM_INIT_H
#define DX_ASYM_INIT_H

#include "crys_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* !
 * Init function for asymmetric code
 *
 * \return DxError_t - DX_OK
 */
DxError_t DX_ASYM_Init(void);

#ifdef __cplusplus
}
#endif

#endif
