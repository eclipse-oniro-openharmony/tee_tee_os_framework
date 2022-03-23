HOST_PROJ_ROOT ?= $(shell pwd)/../../..
include $(HOST_PROJ_ROOT)/Makefile.defs

SOFTCRYS_DIR ?= $(HOST_PROJ_ROOT)/src/softcrys

TARGET_LIBS = dx_cc7

DX_SOFT_KEYGEN_SIZE ?= 0

#cclib7 local sources
SOURCES_dx_cc7 = dx_cclib.c dx_hal.c cc_acl_plat.c completion_plat.c hw_queue_plat.c dma_buffer.c dx_pal.c dx_pal_dma.c  dx_pal_memmap.c mlli_plat.c crys_context_relocation.c  dx_pal_mutex.c
SOURCES_dx_cc7 += dx_pal_barrier.c
ifeq ($(DEBUG),1)
SOURCES_dx_cc7 += dx_pal_log.c
CFLAGS_EXTRA += -DTEE_DEBUG
endif
ifeq ($(OS),secure_os)
SOURCES_dx_cc7 += bget.c
endif


ifneq ($(DX_SOFT_KEYGEN_SIZE),0)
	CFLAGS += -DDX_SOFT_KEYGEN -DDX_SOFT_KEYGEN_SIZE=$(DX_SOFT_KEYGEN_SIZE) -DDX_CRYS_KEYGEN_MAX_SIZE=$(CRYS_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS)
	SOURCES_dx_cc7 += ccsw_crys_rsa_kg.c 
	SOURCES_dx_cc7 += sw_llf_pki_genkey.c sw_llf_pki_rsa.c 
	SOURCES_dx_cc7 += llf_pki_util_exp.c llf_pki_util_invmod.c llf_pki_util_monmul_32x32.c llf_pki_util_rmul.c 
	SOURCES_dx_cc7 += llf_pki_util_exp_crt.c llf_pki_util_div.c 
	INCDIRS_EXTRA += $(SOFTCRYS_DIR)/pki $(CODESAFE_SRCDIR)/crys/rsa/ccsw_rsa
	vpath %.c = $(CODESAFE_SRCDIR)/crys/rsa/ccsw_rsa   $(SOFTCRYS_DIR)/pki
else
# in this case no generation in sw => max generation in hw
	CFLAGS += -DDX_CRYS_KEYGEN_MAX_SIZE=$(CRYS_RSA_MAX_KEY_GENERATION_HW_SIZE_BITS)
endif 

	
ifeq ($(LIB_PERF),1)
vpath %.c $(HOST_PROJ_ROOT)/src/pal
CFLAGS += -DLIB_PERF
SOURCES_dx_cc7 += dx_pal_perf_plat.c
endif

CFLAGS += -DCC_HW_VERSION=$(CC_HW_VERSION) 

# CRYS APIs sources
SOURCES_dx_cc7 += crys_aes.c crys_hash.c crys_hmac.c crys_des.c crys_aesccm.c crys_bypass.c

SOURCES_dx_cc7 += sym_adaptor_driver.c hw_queue.c key_buffer.c validate_crys_bypass_plat.c cc_plat.c
# Symmetric HW driver sources
SOURCES_dx_cc7 += bypass.c cipher.c hash.c hmac.c aead.c mlli.c sym_crypto_driver.c
# Asymmetric sources 
SOURCES_dx_cc7 += crys_rsa_build.c crys_ccm.c crys_common_math.c crys_common_conv_endian.c dx_asym_init.c
SOURCES_dx_cc7 += crys_rsa_oaep.c crys_rsa_pkcs_ver15_util.c crys_rsa_pss21_util.c crys_rsa_prim.c crys_rsa_verify.c crys_rsa_kg.c crys_rsa_sign.c crys_ecpki_build.c crys_ecpki_kg.c 
SOURCES_dx_cc7 += crys_ecdh.c crys_ecdsa_sign.c crys_ecdsa_verify.c
SOURCES_dx_cc7 += crys_kdf.c crys_dh.c crys_dh_kg.c dx_util.c dx_util_oem_asset.c dx_util_stimer.c dx_util_rpmb.c dx_util_rpmb_adaptor.c
# random files
SOURCES_dx_cc7 += crys_rnd.c llf_rnd.c 
ifeq ($(DX_CONFIG_RND_ENGINE),rnd_nodma) 
SOURCES_dx_cc7 += llf_aes_restrict.c  llf_rnd_cf_port.c 
else
SOURCES_dx_cc7 += dx_rng_plat.c
endif

ifeq ($(DX_CONFIG_PKA_ENGINE),sw)
	# SW implementation
	SOURCES_dx_cc7 += llf_pki_expcrt.c llf_pki_genkey.c llf_pki_rsa.c llf_pki_selftest.c llf_pki_util_div.c llf_pki_util_exp.c \
			     llf_pki_util_rmul.c llf_pki_util_monmul_16x16_c.c llf_pki_util_invmod.c \
			     llf_ecpki_domains.c llf_ecpki_ecdsa.c llf_ecpki_export.c llf_ecpki_genkey.c llf_ecpki_modular_arithmetic.c llf_ecpki_ec_arithmetic.c
else
	# hw implementation
	SOURCES_dx_cc7 += llf_pki_pka.c llf_pki_exp.c llf_pki_genkey.c llf_pki_genkey_x931_find_prime.c llf_pki_rsa.c \
			      llf_ecpki_export.c llf_ecpki_version.c llf_ecpki_domains.c llf_ecpki_ec_arithmetic.c llf_ecpki_ecdsa.c llf_ecpki_genkey.c llf_ecpki_modular_arithmetic.c
endif


#Files for SB on runtime


SOURCES_dx_cc7 +=crypto_driver.c crypto_driver_adaptor.c secureboot_base_func.c util.c bootimagesverifier_swcomp.c bootimagesverifier_parser.c bootimagesverifier_base_single.c 
SOURCES_dx_cc7 +=  nvm_mng.c  sbrt_management_api.c
#sb_otp_api.c


# case of secure key package generator
ifeq ($(DX_CONFIG_SECURE_KEY_PACKAGE_SUPPORTED),1)

CRYPTO_FW_BASE = svn://subversion/DX/ip/fw/crypto_fw

SOURCES_dx_cc7 += secure_key_gen.c
$(BUILDDIR)/secure_key_gen$(OBJEXT): $(ROM_RELEASE_DIR)

INCDIRS_EXTRA += $(ROM_RELEASE_DIR)/include

# Fetch selected ROM release based on given ROM_TAG configuration
$(ROM_RELEASE_DIR):
	$(if $(DEP_ROM_TAG),,$(error DEP_ROM_TAG is undefined. ROM release must be installed manually.))
	@$(ECHO) Installing cc441p-rom headers from $(CRYPTO_FW_BASE)/$(DEP_ROM_TAG)/sep/rom/include
	@$(call exec_logged,svn export $(CRYPTO_FW_BASE)/$(DEP_ROM_TAG)/sep/rom/include $(ROM_RELEASE_DIR)/include)
	@$(call exec_logged,svn export $(CRYPTO_FW_BASE)/$(DEP_ROM_TAG)/sep/rom/proj.cfg $(ROM_RELEASE_DIR)/proj.cfg)

PUBLIC_INCLUDES = $(ROM_RELEASE_DIR)/include/secure_key_defs.h secure_key_gen.h  
$(ROM_RELEASE_DIR)/include/secure_key_defs.h: $(ROM_RELEASE_DIR)

endif

# Include directories
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crys/sym/driver $(CODESAFE_SRCDIR)/crys/sym/api $(CODESAFE_SRCDIR)/crys/driver
INCDIRS_EXTRA += $(SHARED_INCDIR) $(SHARED_INCDIR)/pal $(SHARED_INCDIR)/pal/$(OS) $(HOST_PROJ_ROOT)/src/hal $(HOST_PROJ_ROOT)/src/pal  $(HOST_PROJ_ROOT)/src/pal/$(OS)
INCDIRS_EXTRA += $(SHARED_DIR)/hw/include
INCDIRS_EXTRA += $(SHARED_INCDIR)/crys $(CODESAFE_SRCDIR)/crys/common/inc $(CODESAFE_SRCDIR)/crys/gen/inc
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crys/rsa/crys_rsa/inc $(CODESAFE_SRCDIR)/crys/kdf/inc $(CODESAFE_SRCDIR)/crys/dh/inc $(CODESAFE_SRCDIR)/crys/common/inc $(CODESAFE_SRCDIR)/crys/ccm/inc
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crys/ecc/crys_ecc/ecc_common/inc $(CODESAFE_SRCDIR)/crys/gen/inc
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crys/gen/inc $(SHARED_INCDIR)/dx_util
ifeq ($(DX_CONFIG_PKA_ENGINE),sw)
	INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crys/rsa/llf_pki_sw/inc $(CODESAFE_SRCDIR)/crys/ecc/llf_pki_ec_sw/inc
else
	INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crys/rsa/llf_pki/inc $(CODESAFE_SRCDIR)/crys/ecc/llf_pki_ec/inc
endif
ifeq ($(DX_CONFIG_RND_ENGINE),rnd_nodma)
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crys/rnd/crys_rnd/inc $(CODESAFE_SRCDIR)/crys/rnd/llf_rnd/inc 
else
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/crys/rnd_dma $(HOST_PROJ_ROOT)/src/cclib
endif
#Files for SB on runtime

INCDIRS_EXTRA += $(SHARED_INCDIR)/pal $(SHARED_INCDIR)/pal/$(OS) $(CODESAFE_SRCDIR)/runtime_secure_boot/secure_boot_gen 
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/runtime_secure_boot/crypto_driver $(CODESAFE_SRCDIR)/runtime_secure_boot/platform/nvm/nvm_mng $(CODESAFE_SRCDIR)/runtime_secure_boot/platform/hal
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/runtime_secure_boot/platform/nvm $(CODESAFE_SRCDIR)/runtime_secure_boot/gen $(CODESAFE_SRCDIR)/runtime_secure_boot/util 
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/runtime_secure_boot/boot_images_verifier $(CODESAFE_SRCDIR)/runtime_secure_boot/sw_revocation_manager $(SHARED_DIR)/hw/include
INCDIRS_EXTRA += $(HOST_PROJ_ROOT)/src/cclib/tee $(HOST_PROJ_ROOT)/src/hal $(CODESAFE_SRCDIR)/crys/sym/driver $(SHARED_DIR)/include/sbrom
INCDIRS_EXTRA += $(CODESAFE_SRCDIR)/runtime_secure_boot/vrl_verifier
INCDIRS_EXTRA += $(HOST_PROJ_ROOT)/src/sb_runtime  $(CODESAFE_SRCDIR)/runtime_secure_boot/platform/pal



# Add "cclib" dir. for common header files
INCDIRS_EXTRA += ..

PUBLIC_INCLUDES += ../dx_cclib.h $(CODESAFE_SRCDIR)/crys/sym/driver/key_object.h  $(CODESAFE_SRCDIR)/runtime_secure_boot/vrl_verifier/bootimagesverifier_api.h
PUBLIC_INCLUDES += $(CODESAFE_SRCDIR)/runtime_secure_boot/secure_boot_gen/secureboot_defs.h $(CODESAFE_SRCDIR)/runtime_secure_boot/vrl_verifier/bootimagesverifier_def.h
PUBLIC_INCLUDES += $(CODESAFE_SRCDIR)/runtime_secure_boot/vrl_verifier/bootimagesverifier_error.h $(CODESAFE_SRCDIR)/runtime_secure_boot/secure_boot_gen/secureboot_error.h
PUBLIC_INCLUDES += $(HOST_PROJ_ROOT)/src/hal/dx_hal_plat.h $(HOST_PROJ_ROOT)/src/cclib/tee/sbrt_management_error.h

ifeq ($(CROSS_COMPILE),arm-dsm-)
CFLAGS += -DARM_DSM
INCDIRS_EXTRA +=  $(HOST_PROJ_ROOT)/src/cclib
endif

# We should flatten the components source trees to avoid long search paths...
vpath %.c   $(HOST_PROJ_ROOT)/src/hal $(CODESAFE_SRCDIR)/crys/sym/driver $(CODESAFE_SRCDIR)/crys/sym/api $(CODESAFE_SRCDIR)/crys/rsa/crys_rsa/src $(CODESAFE_SRCDIR)/crys/kdf/src \
$(CODESAFE_SRCDIR)/crys/dh/src $(CODESAFE_SRCDIR)/crys/common/src $(CODESAFE_SRCDIR)/crys/ccm/src $(CODESAFE_SRCDIR)/crys/ecc/crys_ecc/ecc_common/src \
$(CODESAFE_SRCDIR)/crys/ecc/crys_ecc/ecdh/src $(CODESAFE_SRCDIR)/crys/ecc/crys_ecc/ecdsa/src $(CODESAFE_SRCDIR)/crys/ecc/crys_ecc/ec_elgamal/src \
$(CODESAFE_SRCDIR)/crys/gen/src $(CODESAFE_SRCDIR)/crys/gen/src $(HOST_PROJ_ROOT)/src/pal/$(OS) 
ifeq ($(DX_CONFIG_PKA_ENGINE),sw)
vpath %.c = $(CODESAFE_SRCDIR)/crys/rsa/llf_pki_sw/src $(CODESAFE_SRCDIR)/crys/ecc/llf_pki_ec_sw/src
else
vpath %.c = $(CODESAFE_SRCDIR)/crys/rsa/llf_pki/src $(CODESAFE_SRCDIR)/crys/ecc/llf_pki_ec/src
endif

#RND vpath
ifeq ($(DX_CONFIG_RND_ENGINE),rnd_nodma)
vpath %.c = $(CODESAFE_SRCDIR)/crys/rnd/crys_rnd/src $(CODESAFE_SRCDIR)/crys/rnd/llf_rnd/src 
else
vpath %.c = $(CODESAFE_SRCDIR)/crys/rnd_dma $(HOST_PROJ_ROOT)/src/cclib/tee $(HOST_PROJ_ROOT)/src/cclib
endif

CFLAGS_EXTRA += -DFW_VER_MAJOR=$(FW_VER_MAJOR) -DFW_VER_MINOR=$(FW_VER_MINOR) -DFW_VER_PATCH=$(FW_VER_PATCH)
CFLAGS_EXTRA += -DDX_CC_TEE -DMAX_NUM_HW_QUEUES=$(FW_MAX_NUM_HW_QUEUES) -DDLLI_MAX_BUFF_SIZE=$(DLLI_MAX_BUFF_SIZE) -DDX_SEC_TIMER_TEST_ENV 
CFLAGS_EXTRA += -DFW_MLLI_TABLE_LEN=$(FW_MLLI_TABLE_LEN) -DSEP_SUPPORT_SHA=512 -DMIN_CRYPTO_TAIL_SIZE=$(MIN_CRYPTO_TAIL_SIZE) -DDEBUG_OAEP_SEED=0 -DCRYS_RSA_SIGN_USE_TEMP_SALT=0
# List of drivers to enable/disable
DRIVERS = AES DES HASH HMAC RC4 AEAD ECC RSA BYPASS COMBINED KDF_DH C2
CFLAGS_EXTRA += $(foreach driver,$(DRIVERS),$(if $(FW_ENABLE_$(driver)_DRIVER),-DENABLE_$(driver)_DRIVER=$(FW_ENABLE_$(driver)_DRIVER)))
CFLAGS_EXTRA += -DCRYS_NO_FIPS_SUPPORT -DCRYS_NO_RSA_SELF_TEST_SUPPORT -DCRYS_RND_SEM_DISABLE -DCRYS_PKA_INDIRECT_SRAM_ACCESS_MODE -DCRYS_NO_CRYS_COMBINED_SUPPORT
ifeq ($(DX_CONFIG_HASH_SHA_512_SUPPORTED),1)
	CFLAGS_EXTRA += -DDX_CONFIG_HASH_SHA_512_SUPPORTED -DSEP_CTX_SIZE_LOG2=8
endif

ifeq ($(DX_CONFIG_HASH_MD5_SUPPORTED),1)
	CFLAGS_EXTRA += -DDX_CONFIG_HASH_MD5_SUPPORTED
endif

ifeq ($(DX_CONFIG_TEST_48BIT_DMA_ADDR),1)
CFLAGS_EXTRA += -DDX_DMA_48BIT_SIM=1
else
CFLAGS_EXTRA += -DDX_DMA_48BIT_SIM=0
endif

# define flag for non supported RND_DMA
ifeq ($(DX_CONFIG_RND_ENGINE),rnd_nodma)
CFLAGS_EXTRA += -DCRYS_NO_RND_DMA_SUPPORT
endif
ifeq ($(DX_CONFIG_RND_TEST_MODE),DX_RND_TEST_MODE)
CFLAGS_EXTRA += -DDX_RND_TEST_MODE
endif

# PKI debug flags - not supported with multi thread 
#ifeq ($(DEBUG), 1)
#CFLAGS_EXTRA += -DLLF_PKI_PKA_DEBUG 
#CFLAGS_EXTRA += -DRSA_KG_NO_RND 
#endif



ifeq ($(DX_CONFIG_SB_ADDITIONAL_DATA_SUPPORTED),1)
     CFLAGS_EXTRA += -DDX_SB_ADDITIONAL_DATA_SUPPORTED
endif
ifeq ($(DX_CONFIG_OTP_SW_VERSION_NOT_SUPPORTED),1)
     CFLAGS_EXTRA += -DDX_OTP_SW_VERSION_NOT_SUPPORTED
endif
ifeq ($(DX_CONFIG_SB_DOUBLE_BUFFER_MAX_SIZE_IN_BYTES),)
    #default
    DX_CONFIG_SB_DOUBLE_BUFFER_MAX_SIZE_IN_BYTES = 8192
endif

CFLAGS_EXTRA += -DCC_HW_VERSION=$(CC_HW_VERSION)

CFLAGS_EXTRA += -DDX_SB_CERT_VERSION_MAJOR=$(DX_CONFIG_SB_CERT_VERSION_MAJOR)
CFLAGS_EXTRA += -DDX_SB_CERT_VERSION_MINOR=$(DX_CONFIG_SB_CERT_VERSION_MINOR) -DSEP_SUPPORT_SHA=512

CFLAGS_EXTRA += -DDX_DOUBLE_BUFFER_MAX_SIZE_IN_BYTES=$(DX_CONFIG_SB_DOUBLE_BUFFER_MAX_SIZE_IN_BYTES)



# We should flatten the components source trees to avoid long search paths...
vpath %.c $(HOST_PROJ_ROOT)/src/sb_runtime $(CODESAFE_SRCDIR)/runtime_secure_boot/vrl_verifier $(CODESAFE_SRCDIR)/runtime_secure_boot/platform/hal/hal_host $(CODESAFE_SRCDIR)/runtime_secure_boot/platform/nvm/nvm_mng $(CODESAFE_SRCDIR)/runtime_secure_boot/secure_boot_gen $(CODESAFE_SRCDIR)/runtime_secure_boot/crypto_driver $(CODESAFE_SRCDIR)/runtime_secure_boot/util $(CODESAFE_SRCDIR)/runtime_secure_boot/gen  $(CODESAFE_SRCDIR)/runtime_secure_boot/platform/pal 





include $(HOST_PROJ_ROOT)/Makefile.rules

