/***************************************************************
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
****************************************************************/

 
#ifndef DX_PAL_TYPES_H
#define DX_PAL_TYPES_H

#include "dx_pal_types_plat.h"

#define DX_SUCCESS              0UL
#define DX_FAIL					1UL


/* the minimum and maximum macros */
#ifdef  min
#define CRYS_MIN(a,b) min( a , b )
#else
#define CRYS_MIN( a , b ) ( ( (a) < (b) ) ? (a) : (b) )
#endif

#ifdef max    
#define CRYS_MAX(a,b) max( a , b )
#else
#define CRYS_MAX( a , b ) ( ( (a) > (b) ) ? (a) : (b) )
#endif




#endif
