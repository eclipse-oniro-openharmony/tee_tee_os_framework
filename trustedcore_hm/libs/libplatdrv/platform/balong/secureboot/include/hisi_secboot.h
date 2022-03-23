#ifndef _HISI_SECBOOT_H_
#define _HISI_SECBOOT_H_

#include "secureboot_basetypes.h"
#include "bootimagesverifier_def.h"
#include "bootimagesverifier_parser.h"
#ifdef __cplusplus
extern "C"
{
#endif

// CryptoCell reset control
// SCPERRSTDIS3  0xfc8020a8  bit15 set to 1£¬the others bits set to 0


/*HI3630: need a always poweron RAM (provisionkey + security_info = 128 bytes)*/
#define	SECBOOT_INVALID_ADDR		(0xFFFFFFFFFFFFFFFF)
#define	SECBOOT_INVALID_VALUE	(0xFFFFFFFF)

#define	SECBOOT_INVALID_KEY1_CERT			(0x000F0001)
#define	SECBOOT_INVALID_KEY1_CERT_TYPE		(0x000F0002)
#define	SECBOOT_INVALID_KEY1_CERT_ADDR		(0x000F0003)
#define	SECBOOT_INVALID_KEY2_CERT			(0x000F0004)
#define	SECBOOT_INVALID_KEY2_CERT_TYPE		(0x000F0005)
#define	SECBOOT_INVALID_CONT_CERT			(0x000F0006)
#define	SECBOOT_INVALID_CONT_CERT_TYPE		(0x000F0007)
#define	SECBOOT_INVALID_CONT_CERT_ADDR		(0x000F0008)

#define	SECBOOT_EMPTY_VALUE		(0x0)
#if defined DX_USE_IN_FASTBOOT
// Discretix CryptoCell hardware base address
#define DX_CC_HW_BASEADDRESS		(0xFF011000)
// Discretix provision key
#define DX_PROVISION_KEY_ADDR		SECBOOT_INVALID_VALUE /* 0xFFFFFFFF is invalid address */
#elif defined DX_USE_IN_XLOADER
// Discretix CryptoCell hardware base address
#define DX_CC_HW_BASEADDRESS		(0xBF011000)
// Discretix provision key
#define DX_PROVISION_KEY_ADDR		SECBOOT_INVALID_VALUE /* 0xFFFFFFFF is invalid address */
#elif defined DX_USE_IN_ONCHIPROM
// Discretix CryptoCell hardware base address
#define DX_CC_HW_BASEADDRESS		(0xBF011000)

#define REG_BASE_LP_RAM			(0x20000)
#define SECURE_ENGINE_STATIC_AREA_ADDRESS	(REG_BASE_LP_RAM + 0x1CF00)
// Discretix provision key
#define DX_PROVISION_KEY_ADDR		(SECURE_ENGINE_STATIC_AREA_ADDRESS + 0x10) /* 0x3cf10~0x3cf50 */
#endif
#define DX_PROVISION_KEY_SIZE		(64) /*HI3630: need a always poweron RAM */

/*HI3630: security information (64 bytes)*/
#define SECURITY_INFO_BASE			(DX_PROVISION_KEY_ADDR + DX_PROVISION_KEY_SIZE)
#define SECURITY_INFO_SIZE			(64) /*HI3630: need a always poweron RAM */

// eda debug addr
#define EDA_DEBUG_REG_BASE			(0x4020A000 + 0x33C)/*sysctrl bakdata10 for EDA debug*/
#define EDA_DEBUG_REG_SIZE			(4) /*(sizeof(uint32_t)*/ /*HI3630: need a always poweron RAM */

#define TWO_LEVEL_SECDBG_IMAGE_SIZE     (1396)
#define THREE_LEVEL_SECDBG_IMAGE_SIZE   (0x840)



/*******************************
 *	Life cycle state definitions
 *******************************/
#define SEB_CHIP_MANUFACTURE_LCS	(0x0)
#define SEB_DEVICE_MANUFACTURE_LCS	(0x1)
#define SEB_SECURITY_DISABLED_LCS	(0x3)
#define SEB_SECURE_LCS				(0x5)
#define SEB_RMA_LCS					(0x7)
#define SEB_SECURITY_INVALID_LCS	(0x8)


/*HI3630: eFuse 1180bit: group(36 * 32bit), offset 0x10000000*/
#define OTP_HASH_VERIFICATION_GROUP     (36)
#define OTP_HASH_GROUP_SIZE             (4)
#define OTP_HASH_VERIFICATION_MASK      (0x10000000)

/*Data struct for SB Certificate package*/
typedef struct _SB_CertPkg_DataStruct{
	uint64_t				KeyCert1_FlashAddr;
	uint64_t				KeyCert2_FlashAddr;
	uint64_t				ConCert_FlashAddr;
} SB_CertPkg_DataStruct;


/* Flash Read function pointer defintion, this function is used inside the secure boot APIs
   To read data from the Flash */
typedef uint32_t (*DxSbFlashReadFunc) (uint64_t flashAddress,	/* Flash address to read from */
				       uint8_t *memDst,	/* memory destination to read the data to */
				       uint32_t sizeToRead,	/* size to read from Flash (in bytes) */
				       void* context);		/* context for user's needs */

uint32_t SEB_SecureInit(uint32_t* workspace_ptr, uint32_t workspaceSize);
uint32_t SEB_FlashRead_RAM(uint64_t flashAddress, uint8_t *memDst, uint32_t sizeToRead, void* context);
uint32_t SEB_FillCertPkg(uint64_t certAddress, SB_CertPkg_DataStruct* SB_CertPkg);
uint32_t SEB_DisableSecurity();
uint32_t SEB_GetLcs(uint32_t *pLcs);
uint32_t SEB_XloaderVerification(SB_CertPkg_DataStruct *SB_CertPkg, uint32_t * workspace_ptr, uint32_t workspaceSize);
uint32_t SEB_SecureVerification(DxSbFlashReadFunc flashRead_func, SB_CertPkg_DataStruct* SB_CertPkg, uint32_t* workspace_ptr, uint32_t workspaceSize);
uint32_t SEB_ImageHashVerification(DxSbFlashReadFunc flashRead_func, void *userContext, uint64_t certAddress, uint32_t *workspace_ptr, uint32_t workspaceSize);
#ifdef CONFIG_MODEM_CHECK_IMAGE_SIZE
uint32_t SEB_VRLChangeSwCompStoreAddr(uint32_t *certPtr, uint64_t address, uint32_t indexOfAddress, unsigned int *content_size);
#else
uint32_t SEB_VRLChangeSwCompStoreAddr(uint32_t *certPtr, uint64_t address, uint32_t indexOfAddress);
#endif
uint32_t SEB_ExtRamBackupAndRestore(uint32_t srcAddr, uint32_t dstAddr, uint32_t blockSize, DxBool_t isSramBackup);
uint32_t SEB_ReadOTPWord(uint32_t otpAddress, uint32_t *otpWord);
uint32_t SEB_BaseVRLVerification(DxSbFlashReadFunc flashReadFunc, void *userContext, SB_CertPkg_DataStruct *SB_CertPkg, uint32_t *pWorkspace, uint32_t workspaceSize);
uint32_t SEB_ParseVrlGetSWComponentData(uint32_t *pCert, DxSbCertParserSwCompsInfo_t *pSwImagesData);
uint32_t SEB_SwNvCounterChk(uint32_t *pCert, uint32_t *version);
uint32_t SEB_SecureDebugVerification(uint32_t *pDebugCertPkg, uint32_t isKeyCertExist, uint32_t *pEnableRmaMode);
uint32_t SEB_ComputeSocId(uint32_t  *socid_buf);
#ifdef __cplusplus
}
#endif

#endif // _HISI_SECBOOT_H_
