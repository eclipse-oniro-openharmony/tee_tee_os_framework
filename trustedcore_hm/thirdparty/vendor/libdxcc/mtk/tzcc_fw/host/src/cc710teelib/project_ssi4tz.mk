
TARGET_LIBS = cc_710tee

DX_SOFT_KEYGEN_SIZE ?= 0


ifeq ($(DEBUG),1)
SOURCES_cc_710tee += ssi_pal_log.c
endif

ifeq ($(PKA_DEBUG),1)
CFLAGS += -DPKA_DEBUG
SOURCES_cc_710tee += pka_dbg.c
endif

ifeq ($(OS),dx_linux)
SOURCES_cc_710tee += bget.c
endif

ifeq ($(OS),hmos)
SOURCES_cc_710tee += bget.c
endif

ifeq ($(SSI4OPTEE),1)
VPATH += $(HOST_PROJ_ROOT)/src/optee_provider/tee
SOURCES_cc_710tee += tee_ssi_provider.c
CFLAGS_EXTRA += -DCFG_TEE_CORE_DEBUG=0

OPTEE_OS_EXISTS = $(wildcard $(OPTEE_OS))
$(info OPTEE_OS=$(OPTEE_OS), OPTEE_OS_EXISTS=$(OPTEE_OS_EXISTS))
LINARO_INCLUDE_EXISTS = $(wildcard $(LINARO_INCLUDE))
$(info LINARO_INCLUDE=$(LINARO_INCLUDE), LINARO_INCLUDE_EXISTS=$(LINARO_INCLUDE_EXISTS))

ifeq ($(OPTEE_OS_EXISTS),)

ifeq ($(LINARO_INCLUDE_EXISTS),)
$(error OPTEE_OS is not configured correctly or doesnt point to the right location. for this reason build package has failed.please configure it in proj.cfg and try again.)
else
INCDIRS_EXTRA += $(LINARO_INCLUDE)
$(info PLEASE NOTE THAT YOU ARE NOT COMPILING WITH REAL LINARO_OPTEE. to do so, please configure OPTEE_OS in proj.cfg so it points to the real location of optee_os folder in linaro product)
endif

else
INCDIRS_EXTRA += $(OPTEE_OS)/lib/libutils/isoc/include $(OPTEE_OS)/core/include/kernel $(OPTEE_OS)/lib/libutils/ext/include $(OPTEE_OS)/lib/libutee/include $(OPTEE_OS)/core/include $(OPTEE_OS)/core/arch/arm/include $(OPTEE_OS)/core/include/mm $(OPTEE_OS)/lib/libmpa/include
endif
endif

# no generation in sw => max generation in hw
CFLAGS += -DDX_SaSi_KEYGEN_MAX_SIZE=$(SaSi_RSA_MAX_KEY_GENERATION_SIZE_BITS)

	
ifeq ($(LIB_PERF),1)
VPATH += $(HOST_SRCDIR)/pal
CFLAGS += -DLIB_PERF
SOURCES_cc_710tee += ssi_pal_perf_plat.c
endif

CFLAGS += -DCC_HW_VERSION=$(CC_HW_VERSION)

# ssi4tz sources
SOURCES_cc_710tee += sns_silib.c ssi_hal.c completion_plat.c hw_queue_plat.c dma_buffer.c ssi_pal.c ssi_pal_dma.c
SOURCES_cc_710tee += ssi_pal_memmap.c mlli_plat.c sasi_context_relocation.c ssi_pal_mutex.c ssi_pal_barrier.c

# SaSi APIs sources
SOURCES_cc_710tee += ssi_aes.c sasi_hash.c sasi_hmac.c sasi_des.c sasi_aesccm.c
SOURCES_cc_710tee += sym_adaptor_driver.c hw_queue.c cc_plat.c

# Symmetric HW driver sources
SOURCES_cc_710tee += bypass.c cipher.c hash.c hmac.c aead.c mlli.c sym_crypto_driver.c

#util
SOURCES_cc_710tee += ssi_util_cmac.c ssi_util.c ssi_util_key_derivation.c ssi_util_oem_asset.c ssi_util_stimer.c ssi_util_rpmb.c ssi_util_rpmb_adaptor.c
SOURCES_cc_710tee += ssi_util_backup_restore.c ssi_util_ccm.c

# Asymmetric sources 
SOURCES_cc_710tee += sasi_common_math.c sasi_common_conv_endian.c

#RSA
SOURCES_cc_710tee += ssi_rsa_info.c sasi_rsa_build.c
SOURCES_cc_710tee += sasi_rsa_oaep.c sasi_rsa_schemes.c sasi_rsa_pkcs_ver15_util.c sasi_rsa_pss21_util.c sasi_rsa_prim.c sasi_rsa_verify.c
SOURCES_cc_710tee += sasi_rsa_kg.c sasi_rsa_sign.c 
SOURCES_cc_710tee += sasi_dh.c sasi_dh_kg.c sasi_kdf.c 

#ECC (Canonic)
SOURCES_cc_710tee += ssi_ecpki_info.c
SOURCES_cc_710tee += sasi_ecpki_build_publ.c sasi_ecpki_build_priv.c sasi_ecdsa_verify.c sasi_ecdsa_sign.c 
SOURCES_cc_710tee += sasi_ecpki_kg.c sasi_ecdh.c sasi_ecies.c llf_ecpki_genkey.c

# random files
SOURCES_cc_710tee += sasi_rnd.c llf_rnd.c ssi_rng_plat.c
$(info SSI_CONFIG_TRNG_MODE is $(SSI_CONFIG_TRNG_MODE) TRUSTEDCORE_CHIP_CHOOSE is $(TRUSTEDCORE_CHIP_CHOOSE))
ifeq ($(SSI_CONFIG_TRNG_MODE),0)
        # Slow TRNG
        $(info Slow TRNG: SSI_CONFIG_TRNG_MODE=$(SSI_CONFIG_TRNG_MODE))
        SOURCES_cc_710tee += llf_rnd_fetrng.c
	CFLAGS_EXTRA += -DSSI_CONFIG_TRNG_MODE=$(SSI_CONFIG_TRNG_MODE)
else ifeq ($(SSI_CONFIG_TRNG_MODE),1)
        # TRNG90B
        $(info TRNG90B: SSI_CONFIG_TRNG_MODE=$(SSI_CONFIG_TRNG_MODE))
        SOURCES_cc_710tee += llf_rnd_trng90b.c
	CFLAGS_EXTRA += -DSSI_CONFIG_TRNG_MODE=$(SSI_CONFIG_TRNG_MODE)
else ifeq ($(SSI_CONFIG_TRNG_MODE),2)
        # Fast TRNG
        $(info Fast TRNG: SSI_CONFIG_TRNG_MODE=$(SSI_CONFIG_TRNG_MODE))
        SOURCES_cc_710tee += llf_rnd_sweetrng.c
        SOURCES_cc_710tee += mtk_trng_dx.c
	CFLAGS_EXTRA += -DSSI_CONFIG_TRNG_MODE=$(SSI_CONFIG_TRNG_MODE)
else
        $(error illegal TRNG: SSI_CONFIG_TRNG_MODE=$(SSI_CONFIG_TRNG_MODE))
endif

SOURCES_cc_710tee += pka.c pka_modular_arithmetic.c 
SOURCES_cc_710tee += llf_rsa_public.c llf_rsa_private.c llf_pka.c llf_rsa_genkey.c
SOURCES_cc_710tee += pka_ecc.c pka_ecc_point.c pka_ecdsa_verify.c  
SOURCES_cc_710tee += llf_ecc.c llf_ecdsa_verify.c   sasi_ecpki_domain.c 
SOURCES_cc_710tee += llf_ecdsa_sign.c 
SOURCES_cc_710tee +=  ssi_ecpki_domain_secp160k1.c ssi_ecpki_domain_secp160r1.c ssi_ecpki_domain_secp160r2.c ssi_ecpki_domain_secp192r1.c 
SOURCES_cc_710tee +=  ssi_ecpki_domain_secp192k1.c ssi_ecpki_domain_secp224r1.c ssi_ecpki_domain_secp224k1.c ssi_ecpki_domain_secp256r1.c 
SOURCES_cc_710tee +=  ssi_ecpki_domain_secp256k1.c ssi_ecpki_domain_secp384r1.c ssi_ecpki_domain_secp521r1.c 
ifeq ($(DX_CONFIG_SUPPORT_ECC_SCA_SW_PROTECT), 1)
	SOURCES_cc_710tee += pka_ecc_scalar_mult_scap.c
else 
	SOURCES_cc_710tee += pka_ecc_scalar_mult_no_scap.c 
endif

#FIPS
ifeq ($(DX_CONFIG_SUPPORT_FIPS), 1)
	CFLAGS_EXTRA += -DSSI_SUPPORT_FIPS
	SOURCES_cc_710tee +=  sasi_fips.c  sasi_fips_local.c sasi_fips_sym.c ssi_pal_fips.c
	SOURCES_cc_710tee +=  sasi_fips_ecc.c sasi_fips_rsa.c sasi_fips_dh.c sasi_fips_prng.c
endif


INCDIRS_EXTRA += $(SHARED_INCDIR)/crys/$(PROJ_PRD)

# case of secure key package generator
ifeq ($(DX_CONFIG_SECURE_KEY_PACKAGE_SUPPORTED),1)

CRYPTO_FW_BASE = svn://subversion/DX/ip/fw/crypto_fw
SOURCES_cc_710tee += secure_key_gen.c
INCDIRS_EXTRA += $(ROM_RELEASE_DIR)/include

# Fetch selected ROM release based on given ROM_TAG configuration
$(ROM_RELEASE_DIR):
	$(if $(DEP_ROM_TAG),,$(error DEP_ROM_TAG is undefined. ROM release must be installed manually.))
	@$(ECHO) Installing cc441p-rom headers from $(CRYPTO_FW_BASE)/$(DEP_ROM_TAG)/sep/rom/include
	@$(call exec_logged,svn export $(CRYPTO_FW_BASE)/$(DEP_ROM_TAG)/sep/rom/include $(ROM_RELEASE_DIR)/include)
	@$(call exec_logged,svn export $(CRYPTO_FW_BASE)/$(DEP_ROM_TAG)/sep/rom/proj.cfg $(ROM_RELEASE_DIR)/proj.cfg)

PUBLIC_INCLUDES = $(ROM_RELEASE_DIR)/include/secure_key_defs.h $(HOST_LIBDIR)/secure_key_gen.h 
PUBLIC_INCLUDES += $(HOST_LIBDIR)/sns_silib.h
PUBLIC_INCLUDES += $(SHARED_INCDIR)/ssi_util/ssi_util_key_derivation.h
$(ROM_RELEASE_DIR)/include/secure_key_defs.h: $(ROM_RELEASE_DIR)
endif

# Include directories
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crys/sym/driver $(CODESAFE_SRCDIR)/crys/sym/api $(CODESAFE_SRCDIR)/crys/driver
INCDIRS_EXTRA += $(SHARED_INCDIR) $(SHARED_INCDIR)/pal $(SHARED_INCDIR)/pal/$(OS) $(HOST_SRCDIR)/hal $(HOST_SRCDIR)/pal  $(HOST_SRCDIR)/pal/$(OS)
INCDIRS_EXTRA += $(SHARED_INCDIR)/trng/
INCDIRS_EXTRA += $(SHARED_DIR)/hw/include
INCDIRS_EXTRA += $(SHARED_INCDIR)/crys $(CODESAFE_SRCDIR)/crys/common $(CODESAFE_SRCDIR)/crys/gen
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crys/rsa $(CODESAFE_SRCDIR)/crys/ecc $(CODESAFE_SRCDIR)/crys/ecc/ecc_domains
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crys/gen $(SHARED_INCDIR)/ssi_util 
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crys/pki/rsa $(CODESAFE_SRCDIR)/crys/pki/ecc $(CODESAFE_SRCDIR)/crys/pki/pka
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crys/rnd_dma $(CODESAFE_SRCDIR)/crys/rnd_dma/local $(HOST_LIBDIR)
INCDIRS_EXTRA += $(SHARED_INCDIR)/proj/$(PROJ_DIR)
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crys/fips

CFLAGS_EXTRA += -DSSI_SUPPORT_PKA_128_32
ifeq ($(DX_CONFIG_SUPPORT_ECC_SCA_SW_PROTECT), 1)
	CFLAGS_EXTRA += -DSSI_SUPPORT_ECC_SCA_SW_PROTECT
endif




ifeq ($(CROSS_COMPILE),arm-dsm-)
CFLAGS += -DARM_DSM
endif

# We should flatten the components source trees to avoid long search paths...

VPATH += $(HOST_SRCDIR)/hal/$(PROJ_PRD) $(CODESAFE_SRCDIR)/crys/sym/driver $(CODESAFE_SRCDIR)/crys/sym/api $(CODESAFE_SRCDIR)/crys/rsa $(CODESAFE_SRCDIR)/crys/kdf \
$(CODESAFE_SRCDIR)/crys/dh $(CODESAFE_SRCDIR)/crys/common  $(CODESAFE_SRCDIR)/crys/ecc $(CODESAFE_SRCDIR)/crys/ecc/ecc_domains \
$(CODESAFE_SRCDIR)/crys/gen $(HOST_SRCDIR)/pal/$(OS) $(HOST_SRCDIR)/utils
VPATH += $(SHARED_SRCDIR)/proj/$(PROJ_DIR)

#RND vpath
VPATH += $(CODESAFE_SRCDIR)/crys/rnd_dma $(HOST_LIBDIR) 
#ECC vpath
VPATH += $(CODESAFE_SRCDIR)/crys/pki/rsa $(CODESAFE_SRCDIR)/crys/pki/ecc $(CODESAFE_SRCDIR)/crys/pki/pka
#FIPS vpath
VPATH += $(CODESAFE_SRCDIR)/crys/fips

CFLAGS_EXTRA += -DFW_VER_MAJOR=$(FW_VER_MAJOR) -DFW_VER_MINOR=$(FW_VER_MINOR) -DFW_VER_PATCH=$(FW_VER_PATCH)
CFLAGS_EXTRA += -DDX_CC_TEE -DMAX_NUM_HW_QUEUES=$(FW_MAX_NUM_HW_QUEUES) -DDLLI_MAX_BUFF_SIZE=$(DLLI_MAX_BUFF_SIZE) -DDX_SEC_TIMER_TEST_ENV 
CFLAGS_EXTRA += -DFW_MLLI_TABLE_LEN=$(FW_MLLI_TABLE_LEN) -DSEP_SUPPORT_SHA=512 -DMIN_CRYPTO_TAIL_SIZE=$(MIN_CRYPTO_TAIL_SIZE)
# List of drivers to enable/disable
DRIVERS = AES DES HASH HMAC AEAD ECC RSA BYPASS KDF_DH C2
CFLAGS_EXTRA += $(foreach driver,$(DRIVERS),$(if $(FW_ENABLE_$(driver)_DRIVER),-DENABLE_$(driver)_DRIVER=$(FW_ENABLE_$(driver)_DRIVER)))
CFLAGS_EXTRA += -DSaSi_RND_SEM_DISABLE -DSaSi_PKA_INDIRECT_SRAM_ACCESS_MODE -DSaSi_NO_SaSi_COMBINED_SUPPORT
ifeq ($(DX_CONFIG_HASH_SHA_512_SUPPORTED),1)
	CFLAGS_EXTRA += -DDX_CONFIG_HASH_SHA_512_SUPPORTED -DSEP_CTX_SIZE_LOG2=8
endif

ifeq ($(DX_CONFIG_HASH_MD5_SUPPORTED),1)
	CFLAGS_EXTRA += -DDX_CONFIG_HASH_MD5_SUPPORTED
endif

ifeq ($(DX_CONFIG_RSA_PRIV_KEY_CRT_SUPPORTED),1)
	CFLAGS_EXTRA += -DDX_CONFIG_RSA_PRIV_KEY_CRT_SUPPORTED
endif

ifeq ($(DX_CONFIG_TEST_48BIT_DMA_ADDR),1)
CFLAGS_EXTRA += -DDX_DMA_48BIT_SIM
endif

# define flag for non supported RND_DMA
ifeq ($(DX_CONFIG_RND_TEST_MODE),DX_RND_TEST_MODE)
CFLAGS_EXTRA += -DDX_RND_TEST_MODE
endif
# PKI debug flags - not supported with multi thread 
#ifeq ($(DEBUG), 1)
#CFLAGS_EXTRA += -DLLF_PKI_PKA_DEBUG 
#CFLAGS_EXTRA += -DRSA_KG_NO_RND 
#endif


