
TARGET_LIBS = cc_715tee

CC_SOFT_KEYGEN_SIZE ?= 0


ifeq ($(DEBUG),1)
SOURCES_cc_715tee += cc_pal_log.c
endif

ifeq ($(PKA_DEBUG),1)
CFLAGS += -DPKA_DEBUG
SOURCES_cc_715tee += pki_dbg.c
endif

ifeq ($(TEE_OS),$(filter $(TEE_OS),cc_linux linux64))
SOURCES_cc_715tee += bget.c
endif
ifeq ($(TEE_OS),secure_os)
SOURCES_cc_715tee += bget.c
endif
ifeq ($(TEE_OS),hmos)
SOURCES_cc_715tee += bget.c
endif

ifeq ($(TEE_OS),optee)
ifndef OPTEE_OS_DIR
$(error OPTEE_OS_DIR is undefined)
endif
CFLAGS += -DARM64=1
ifeq ($(DEBUG),1)
CFLAGS += -DCFG_TEE_CORE_DEBUG=1
else
CFLAGS += -DCFG_TEE_CORE_DEBUG=0
endif
INCDIRS_EXTRA += $(OPTEE_OS_DIR)/core/include 
INCDIRS_EXTRA += $(OPTEE_OS_DIR)/core/include/mm
INCDIRS_EXTRA += $(OPTEE_OS_DIR)/core/include/kernel
INCDIRS_EXTRA += $(OPTEE_OS_DIR)/core/arch/arm/include
INCDIRS_EXTRA += $(OPTEE_OS_DIR)/core/arch/arm/tee
INCDIRS_EXTRA += $(OPTEE_OS_DIR)/lib/libutils/ext/include
INCDIRS_EXTRA += $(OPTEE_OS_DIR)/lib/libutils/isoc/include
INCDIRS_EXTRA += $(OPTEE_OS_DIR)/lib/libutee/include
INCDIRS_EXTRA += $(OPTEE_OS_DIR)/lib/libmpa/include
SOURCES_cc_715tee += tee_cc_provider.c
VPATH += $(HOST_SRCDIR)/optee $(HOST_SRCDIR)/hal/optee
endif #optee

ifeq ($(TEE_OS),linux64)
INCDIRS_EXTRA += $(HOST_SRCDIR)/pal/$(TEE_OS)/driver
endif

# no generation in sw => max generation in hw
CFLAGS += -DCC_KEYGEN_MAX_SIZE=$(CC_RSA_MAX_KEY_GENERATION_SIZE_BITS)

	
ifeq ($(LIB_PERF),1)
VPATH += $(HOST_SRCDIR)/pal
CFLAGS += -DLIB_PERF
SOURCES_cc_715tee += cc_pal_perf_plat.c
endif

CFLAGS += -DCC_HW_VERSION=$(CC_HW_VERSION)

# TEE sources
SOURCES_cc_715tee += cc_util_hw_key.c cc_lib.c cc_hal.c completion_plat.c hw_queue_plat.c cc_pal.c cc_pal_dma.c
SOURCES_cc_715tee += cc_pal_memmap.c mlli_plat.c cc_context_relocation.c cc_pal_mutex.c cc_pal_barrier.c cc_util_pm.c

# CC APIs sources
SOURCES_cc_715tee += cc_aes.c cc_hash.c cc_hmac.c cc_des.c cc_aesccm.c
SOURCES_cc_715tee += sym_adaptor_driver.c hw_queue.c cc_plat.c

# Symmetric HW driver sources
SOURCES_cc_715tee += bypass.c cipher.c hash.c hmac.c aead.c mlli.c sym_crypto_driver.c

#util
SOURCES_cc_715tee += cc_util_cmac.c cc_util.c cc_util_key_derivation.c cc_util_oem_asset.c cc_util_stimer.c cc_util_rpmb.c cc_util_rpmb_adaptor.c
SOURCES_cc_715tee += cc_util_backup_restore.c

# Asymmetric sources 
SOURCES_cc_715tee += cc_common_math.c cc_common_conv_endian.c

#RSA
SOURCES_cc_715tee += cc_rsa_info.c cc_rsa_build.c
SOURCES_cc_715tee += cc_rsa_oaep.c cc_rsa_schemes.c cc_rsa_schemes_priv_enc.c cc_rsa_pkcs_ver15_util.c cc_rsa_pss21_util.c cc_rsa_prim.c cc_rsa_verify.c
SOURCES_cc_715tee += cc_rsa_kg.c cc_rsa_sign.c 
SOURCES_cc_715tee += cc_dh.c cc_dh_kg.c cc_kdf.c 
SOURCES_cc_715tee += cc_rsa_build_priv.c

#ECC (Canonic)
SOURCES_cc_715tee += cc_ecpki_info.c
SOURCES_cc_715tee += cc_ecpki_build_publ.c cc_ecpki_build_priv.c cc_ecdsa_verify.c cc_ecdsa_sign.c 
SOURCES_cc_715tee += cc_ecpki_kg.c cc_ecdh.c ec_wrst_genkey.c cc_ecies.c

# random files
SOURCES_cc_715tee += cc_rnd.c llf_rnd.c cc_rng_plat.c
ifeq ($(CC_CONFIG_TRNG_MODE),0)
        # Slow TRNG
        $(info Slow TRNG: CC_CONFIG_TRNG_MODE=$(CC_CONFIG_TRNG_MODE))
        SOURCES_cc_715tee += llf_rnd_fetrng.c
	CFLAGS_EXTRA += -DCC_CONFIG_TRNG_MODE=$(CC_CONFIG_TRNG_MODE)
else ifeq ($(CC_CONFIG_TRNG_MODE),1)
        # TRNG90B
        $(info TRNG90B: CC_CONFIG_TRNG_MODE=$(CC_CONFIG_TRNG_MODE))
        SOURCES_cc_715tee += llf_rnd_trng90b.c
	CFLAGS_EXTRA += -DCC_CONFIG_TRNG_MODE=$(CC_CONFIG_TRNG_MODE)
else ifeq ($(CC_CONFIG_TRNG_MODE),2)
        # Fast TRNG
        $(info Fast TRNG: CC_CONFIG_TRNG_MODE=$(CC_CONFIG_TRNG_MODE))
        SOURCES_cc_715tee += llf_rnd_sweetrng.c
	CFLAGS_EXTRA += -DCC_CONFIG_TRNG_MODE=$(CC_CONFIG_TRNG_MODE)
else
        $(error illegal TRNG: CC_CONFIG_TRNG_MODE=$(CC_CONFIG_TRNG_MODE))
endif

SOURCES_cc_715tee += pka.c pki_modular_arithmetic.c 
SOURCES_cc_715tee += rsa_public.c rsa_private.c pki.c rsa_genkey.c
SOURCES_cc_715tee += pka_ec_wrst.c pka_ec_wrst_dsa_verify.c  
SOURCES_cc_715tee += ec_wrst.c ec_wrst_dsa.c   cc_ecpki_domain.c 
SOURCES_cc_715tee +=  cc_ecpki_domain_secp160k1.c cc_ecpki_domain_secp160r1.c cc_ecpki_domain_secp160r2.c cc_ecpki_domain_secp192r1.c 
SOURCES_cc_715tee +=  cc_ecpki_domain_secp192k1.c cc_ecpki_domain_secp224r1.c cc_ecpki_domain_secp224k1.c cc_ecpki_domain_secp256r1.c 
SOURCES_cc_715tee +=  cc_ecpki_domain_secp256k1.c cc_ecpki_domain_secp384r1.c cc_ecpki_domain_secp521r1.c 
ifeq ($(CC_CONFIG_SUPPORT_ECC_SCA_SW_PROTECT), 1)
	SOURCES_cc_715tee += pka_ec_wrst_smul_scap.c
else 
	SOURCES_cc_715tee += pka_ec_wrst_smul_no_scap.c 
endif

#FIPS
ifeq ($(CC_CONFIG_SUPPORT_FIPS), 1)
	CFLAGS_EXTRA += -DCC_SUPPORT_FIPS
	SOURCES_cc_715tee +=  cc_fips.c  cc_fips_local.c cc_fips_sym.c cc_pal_fips.c
	SOURCES_cc_715tee +=  cc_fips_ecc.c cc_fips_rsa.c cc_fips_dh.c cc_fips_prng.c
endif


INCDIRS_EXTRA += $(SHARED_INCDIR)/crypto_api/$(PROJ_PRD)

PUBLIC_INCLUDES += $(HOST_SRCDIR)/cc7x_teelib/cc_util_hw_key.h
PUBLIC_INCLUDES += $(HOST_SRCDIR)/cc7x_teelib/cc_lib.h
PUBLIC_INCLUDES += $(SHARED_INCDIR)/cc_util/cc_util_key_derivation.h

# Include directories
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crypto_api/cc7x_sym/driver $(CODESAFE_SRCDIR)/crypto_api/cc7x_sym/api $(CODESAFE_SRCDIR)/crypto_api/driver
INCDIRS_EXTRA += $(SHARED_INCDIR) $(SHARED_INCDIR)/pal $(SHARED_INCDIR)/pal/$(TEE_OS) $(HOST_SRCDIR)/hal $(HOST_SRCDIR)/pal  $(HOST_SRCDIR)/pal/$(TEE_OS)
INCDIRS_EXTRA += $(SHARED_INCDIR)/trng/
INCDIRS_EXTRA += $(SHARED_DIR)/$(CC_TEE_HW_INC_DIR)
INCDIRS_EXTRA += $(SHARED_INCDIR)/crypto_api $(CODESAFE_SRCDIR)/crypto_api/common $(CODESAFE_SRCDIR)/crypto_api/gen
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crypto_api/rsa $(CODESAFE_SRCDIR)/crypto_api/ec_wrst $(CODESAFE_SRCDIR)/crypto_api/ec_wrst/ecc_domains
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crypto_api/gen $(SHARED_INCDIR)/cc_util 
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crypto_api/pki/rsa $(CODESAFE_SRCDIR)/crypto_api/pki/ec_wrst $(CODESAFE_SRCDIR)/crypto_api/pki/common
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crypto_api/rnd_dma $(CODESAFE_SRCDIR)/crypto_api/rnd_dma/local $(HOST_SRCDIR)/cc7x_teelib
INCDIRS_EXTRA += $(SHARED_INCDIR)/proj/$(PROJ_PRD)
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crypto_api/fips

CFLAGS_EXTRA += -DCC_SUPPORT_PKA_128_32
ifeq ($(CC_CONFIG_SUPPORT_ECC_SCA_SW_PROTECT), 1)
	CFLAGS_EXTRA += -DCC_SUPPORT_ECC_SCA_SW_PROTECT
endif




ifeq ($(CROSS_COMPILE),arm-dsm-)
CFLAGS += -DARM_DSM
endif

# We should flatten the components source trees to avoid long search paths...

VPATH += $(HOST_SRCDIR)/hal/$(PROJ_PRD) $(CODESAFE_SRCDIR)/crypto_api/cc7x_sym/driver $(CODESAFE_SRCDIR)/crypto_api/cc7x_sym/api $(CODESAFE_SRCDIR)/crypto_api/rsa $(CODESAFE_SRCDIR)/crypto_api/kdf \
$(CODESAFE_SRCDIR)/crypto_api/dh $(CODESAFE_SRCDIR)/crypto_api/common  $(CODESAFE_SRCDIR)/crypto_api/ec_wrst $(CODESAFE_SRCDIR)/crypto_api/ec_wrst/ecc_domains \
$(CODESAFE_SRCDIR)/crypto_api/gen $(HOST_SRCDIR)/pal/$(TEE_OS) $(HOST_SRCDIR)/utils
VPATH += $(SHARED_SRCDIR)/proj/$(PROJ_PRD)

#RND vpath
VPATH += $(CODESAFE_SRCDIR)/crypto_api/rnd_dma $(HOST_SRCDIR)/cc7x_teelib 
#ECC vpath
VPATH += $(CODESAFE_SRCDIR)/crypto_api/pki/rsa $(CODESAFE_SRCDIR)/crypto_api/pki/ec_wrst $(CODESAFE_SRCDIR)/crypto_api/pki/common
#FIPS vpath
VPATH += $(CODESAFE_SRCDIR)/crypto_api/fips

CFLAGS_EXTRA += -DFW_VER_MAJOR=$(FW_VER_MAJOR) -DFW_VER_MINOR=$(FW_VER_MINOR) -DFW_VER_PATCH=$(FW_VER_PATCH)
CFLAGS_EXTRA += -DCC_TEE -DDLLI_MAX_BUFF_SIZE=$(DLLI_MAX_BUFF_SIZE) -DDX_SEC_TIMER_TEST_ENV 
CFLAGS_EXTRA += -DFW_MLLI_TABLE_LEN=$(FW_MLLI_TABLE_LEN) -DCC_SUPPORT_SHA=512 -DMIN_CRYPTO_TAIL_SIZE=$(MIN_CRYPTO_TAIL_SIZE)
# List of drivers to enable/disable
DRIVERS = AES DES HASH HMAC AEAD ECC RSA BYPASS KDF_DH C2
CFLAGS_EXTRA += $(foreach driver,$(DRIVERS),$(if $(FW_ENABLE_$(driver)_DRIVER),-DENABLE_$(driver)_DRIVER=$(FW_ENABLE_$(driver)_DRIVER)))
ifeq ($(CC_CONFIG_HASH_SHA_512_SUPPORTED),1)
	CFLAGS_EXTRA += -DCC_CONFIG_HASH_SHA_512_SUPPORTED -DCC_CTX_SIZE_LOG2=8
endif

ifeq ($(CC_CONFIG_HASH_MD5_SUPPORTED),1)
	CFLAGS_EXTRA += -DCC_CONFIG_HASH_MD5_SUPPORTED
endif


ifeq ($(CC_CONFIG_TEST_48BIT_DMA_ADDR),1)
CFLAGS_EXTRA += -DCC_DMA_48BIT_SIM
endif

# define flag for non supported RND_DMA
ifeq ($(CC_CONFIG_RND_TEST_MODE),CC_RND_TEST_MODE)
CFLAGS_EXTRA += -DCC_RND_TEST_MODE
endif

# PKI debug flags - not supported with multi thread 
#ifeq ($(DEBUG), 1)
#CFLAGS_EXTRA += -DLLF_PKI_PKA_DEBUG 
#CFLAGS_EXTRA += -DRSA_KG_NO_RND 
#endif


