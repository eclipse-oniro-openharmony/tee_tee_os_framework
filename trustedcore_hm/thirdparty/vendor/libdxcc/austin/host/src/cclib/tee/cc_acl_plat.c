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
#define DX_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_CCLIB

#include "cc_acl.h"

/* !
 * SEP implementation for applet address accessing rights.
 *
 * \param type redundant
 * \param addr A pointer to check
 * \param size redundant
 *
 * \return DxBool_t Returns true (zero) if applet has sufficient privilges
 *         to access block of memory, false (nonzero) otherwise.
 */
DxBool_t DxCcAcl_IsBuffAccessOk(AccessType_e type, void *addr, size_t size)
{
    return DX_SUCCESS;
}
