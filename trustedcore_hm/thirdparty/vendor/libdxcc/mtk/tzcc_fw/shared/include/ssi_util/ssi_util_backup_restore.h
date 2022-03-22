/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_UTIL_BACKUP_RESTORE_H
#define _SSI_UTIL_BACKUP_RESTORE_H

/* !
@file
@brief This file contains CryptoCell Util backup and restore functions and definitions.
*/

#ifdef __cplusplus
extern "C" {
#endif

#include "ssi_pal_types.h"
#include "ssi_util_error.h"
#include "ssi_util_defs.h"

/* *****************************************************************************
 *                            DEFINITIONS
 * *************************************************************************** */
/* !
@brief This function performs backup or restore of memory buffer, according to the flag it is given.
It should not be called directly, but only through the SASI_UTIL_RAM_BACKUP and SASI_UTIL_RAM_RESTORE macros.

@return SASI_OK    On success.
@return A non-zero value from ssi_util_error.h on failure.
*/
SaSiError_t SaSi_UtilBackupAndRestore(uint8_t *pSrcBuff,  /* !< [in] Host memory buffer to backup/restore from. */
                                      uint8_t *pDstBuff,  /* !< [out] Host memory buffer for encrypted/decrypted data. */
                                      uint32_t blockSize, /* !< [in] The size of the data to backup/restore (signature
                                                   size not included). Must be < 64KB. */
                                      SaSiBool_t isSramBackup /* !< [in] The operation type:
                                                   <ul><li> SASI_TRUE: backup.</li>
                                                   <ul> SASI_FALSE: restore.</li></ul>  */
);

/* !
@brief This macro is used for power management. Use it upon entry to system-on-chip suspended state,
to perform secure backup of on-chip secure RAM to an off-chip DRAM.
This backed-up data is encrypted and signed with the session key.
The backup must be coupled with a matching restore operation upon wakeup from suspended state.
Restoring must be done to the exact same address that was backed up, with the exact same size that was backed up.
\note
<ul id="noteb"><li>The session key must be initialized prior to using this API.</li>
<li>The backup destination buffer should be 16 bytes bigger than the source buffer, in order to accommodate the
signature.</li></ul>

@return SASI_OK    On success.
@return A non-zero value from ssi_util_error.h on failure.
*/
#define SASI_UTIL_RAM_BACKUP(srcAddr, dstAddr, blockSize) \
    SaSi_UtilBackupAndRestore(srcAddr, dstAddr, blockSize, SASI_TRUE)

/* !
@brief This macro is used for power management. Use it upon wakeup from suspended state,
to restore the data that was backed up upon entry to suspended state.
The source buffer is decrypted and verified with the session key.
The restore operation must match a previous backup operation.
Restoring must be done to the exact same address and with the exact same size that was previously backed up.
\note
<ul id="noteb"><li>The session key cannot be replaced between matching backup and restore operations.</li></ul>

@return SASI_OK    On success.
@return A non-zero value from ssi_util_error.h on failure.
*/
#define SASI_UTIL_RAM_RESTORE(srcAddr, dstAddr, blockSize) \
    SaSi_UtilBackupAndRestore(srcAddr, dstAddr, blockSize, SASI_FALSE)

#ifdef __cplusplus
}
#endif

#endif /* _SSI_UTIL_H */
