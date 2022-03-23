# Project configuration for cc715tee generic host project
set(PROJ_NAME cc715tee)
set(TARGET_DIR cc7x_tee)
set(PROJ_PRD cc7x_tee)
set(HOST_LIBNAME cc7x_teelib)
set(TEE_OS hmos)

# Associated device indentification info.
set(CC_HW_VERSION 0xEF)
set(CC_TEE_HW_INC_DIR hw/tee_include)

# List of targets to build for host/src
set(PROJ_TARGETS cc7x_teelib)
# Number of entries in MLLI table
set(FW_MLLI_TABLE_LEN 128)


# max buffer size for DLLI
set(DLLI_MAX_BUFF_SIZE 128)

#min size for last entry in MLLI
set(MIN_CRYPTO_TAIL_SIZE 32)


# Specific project definitions
# Support incoherent DMA

# Low level driver support
set(FW_ENABLE_AES_DRIVER 1)
set(FW_ENABLE_AEAD_DRIVER 1)
set(FW_ENABLE_DES_DRIVER 1)
set(FW_ENABLE_HASH_DRIVER 1)
set(FW_ENABLE_HMAC_DRIVER 1)
set(FW_ENABLE_BYPASS_DRIVER 1)
set(FW_ENABLE_RSA_DRIVER 1)
set(FW_ENABLE_ECC_DRIVER 1)
set(FW_ENABLE_KDF_DH_DRIVER 1)
set(FW_ENABLE_RND_DRIVER 1)
set(FW_ENABLE_C2_DRIVER 0)


# Specific project definitions for sbromlib
set(CC_CONFIG_SB_INDIRECT_SRAM_ACCESS 1)
# AXI NS bit: 0 for secure, 1 for not secure
set(CC_CONFIG_SB_AXI_NS_BIT 0)
# TEE = Trusted Execution Environment (e.g., TZ)
set(CC_CONFIG_CC_LIB_ENV tee)
set(CC_CONFIG_HASH_SHA_512_SUPPORTED 1)
set(CC_CONFIG_HASH_MD5_SUPPORTED 1)
set(CC_CONFIG_SUPPORT_IOT 0)
set(CC_CONFIG_SUPPORT_PKA_128_32 1)
# If the following flag = 1, then use specific ECC functions
# with SCA protection on program level (different from HW level)
set(CC_CONFIG_SUPPORT_ECC_SCA_SW_PROTECT 0)

# Specific project definitions for supported algorithms
set(CC_CONFIG_CC_RSA_SUPPORT 1)
set(CC_CONFIG_ECC_SUPPORT 1)

# FW images configuration
set(FW_VER_MAJOR 1)
set(FW_VER_MINOR 0)
set(FW_VER_PATCH 0)

#CCSW sets miminum key size for RSA SW key generation
# valid values: 512, 1024, 2048, 3072, 4096
set(CC_SOFT_KEYGEN_SIZE 0)

# definitions for TRNG
# TRNG mode: 0 for FE TRNG, 1 for TRNG90B, 2 for SWEE TRNG
set(CC_CONFIG_TRNG_MODE 0)

#indicates whether the project supports FIPS
set(CC_CONFIG_SUPPORT_FIPS 0)

