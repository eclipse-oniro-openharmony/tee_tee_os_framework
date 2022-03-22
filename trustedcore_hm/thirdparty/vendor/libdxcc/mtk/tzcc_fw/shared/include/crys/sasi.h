/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SaSi_H
#define SaSi_H

#include "ssi_pal_types.h"
#include "sasi_error.h"
#include "ssi_aes.h"
#include "sasi_aesccm.h"
#include "sasi_hash.h"
#include "sasi_hmac.h"
#include "sasi_rnd.h"

#ifndef SaSi_NO_DES_SUPPORT
#include "sasi_des.h"
#endif

#include "sasi_rsa_build.h"
#include "sasi_rsa_types.h"
#include "sasi_rsa_schemes.h"
#include "sasi_rsa_prim.h"
#include "sasi_rsa_kg.h"
#include "sasi_ecpki_types.h"
#include "sasi_ecpki_build.h"
#include "sasi_ecpki_kg.h"
#include "sasi_ecpki_ecdsa.h"
#include "sasi_ecpki_dh.h"

#ifndef SaSi_NO_KDF_SUPPORT
#include "sasi_kdf.h"
#endif

#ifndef SaSi_NO_DH_SUPPORT
#include "sasi_dh.h"
#endif

#include "sasi_rnd.h"

#ifdef __cplusplus
extern "C" {
#endif

/* *********************** Defines **************************** */

/* *********************** Enums ****************************** */

/* *********************** Typedefs  ************************** */

/* *********************** Structs  **************************** */

/* *********************** Public Variables ******************** */

/* *********************** Public Functions ******************** */

#ifdef __cplusplus
}
#endif

#endif
