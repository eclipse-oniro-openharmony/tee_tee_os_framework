inc-flags += -DARM_CPU_CORTEX_A15=1

inc-flags += -I$(SOURCE_DIR)/pal/include \
	    -I$(SOURCE_DIR)/pal/src

libdxcc_c_files += \
	pal/src/bget.c			\
	pal/src/dx_pal.c		\
	pal/src/dx_pal_log.c		\
	pal/src/dx_pal_barrier.c	\
	pal/src/dx_pal_memmap.c		\
	pal/src/dx_pal_dma.c		\
	pal/src/dx_pal_mutex.c		\
	pal/src/dx_pal_hmsyscall.c

#-c
#-fno-omit-frame-pointer
#-Wall
#-O0
#-g3

inc-flags += -I$(SOURCE_DIR)/austin/host/src/softcrys/pki	\
	-I$(SOURCE_DIR)/austin/codesafe/src/crys/rsa/ccsw_rsa	\
	-I$(SOURCE_DIR)/austin/host/src/cclib/tee/public-rom/include	\
	-I$(SOURCE_DIR)/austin/codesafe/src/crys/sym/driver	\
	-I$(SOURCE_DIR)/austin/codesafe/src/crys/sym/api	\
	-I$(SOURCE_DIR)/austin/codesafe/src/crys/driver	\
	-I$(SOURCE_DIR)/austin/shared/include	\
	-I$(SOURCE_DIR)/austin/shared/include/pal	\
	-I$(SOURCE_DIR)/austin/host/src/hal	\
	-I$(SOURCE_DIR)/austin/host/src/pal	\
	-I$(SOURCE_DIR)/austin/shared/hw/include	\
	-I$(SOURCE_DIR)/austin/shared/include/crys	\
	-I$(SOURCE_DIR)/austin/codesafe/src/crys/common/inc	\
	-I$(SOURCE_DIR)/austin/codesafe/src/crys/gen/inc	\
	-I$(SOURCE_DIR)/austin/codesafe/src/crys/rsa/crys_rsa/inc	\
	-I$(SOURCE_DIR)/austin/codesafe/src/crys/kdf/inc	\
	-I$(SOURCE_DIR)/austin/codesafe/src/crys/dh/inc	\
	-I$(SOURCE_DIR)/austin/codesafe/src/crys/common/inc	\
	-I$(SOURCE_DIR)/austin/codesafe/src/crys/ccm/inc	\
	-I$(SOURCE_DIR)/austin/codesafe/src/crys/ecc/crys_ecc/ecc_common/inc	\
	-I$(SOURCE_DIR)/austin/codesafe/src/crys/gen/inc	\
	-I$(SOURCE_DIR)/austin/codesafe/src/crys/gen/inc	\
	-I$(SOURCE_DIR)/austin/shared/include/dx_util	\
	-I$(SOURCE_DIR)/austin/codesafe/src/crys/rsa/llf_pki/inc	\
	-I$(SOURCE_DIR)/austin/codesafe/src/crys/ecc/llf_pki_ec/inc	\
	-I$(SOURCE_DIR)/austin/codesafe/src/crys/rnd_dma	\
	-I$(SOURCE_DIR)/austin/host/src/cclib	\
	-I$(SOURCE_DIR)/austin/shared/include/pal	\
	-I$(SOURCE_DIR)/austin/codesafe/src/runtime_secure_boot/secure_boot_gen	\
	-I$(SOURCE_DIR)/austin/codesafe/src/runtime_secure_boot/crypto_driver	\
	-I$(SOURCE_DIR)/austin/codesafe/src/runtime_secure_boot/platform/nvm/nvm_mng	\
	-I$(SOURCE_DIR)/austin/codesafe/src/runtime_secure_boot/platform/hal	\
	-I$(SOURCE_DIR)/austin/codesafe/src/runtime_secure_boot/platform/nvm	\
	-I$(SOURCE_DIR)/austin/codesafe/src/runtime_secure_boot/gen	\
	-I$(SOURCE_DIR)/austin/codesafe/src/runtime_secure_boot/util	\
	-I$(SOURCE_DIR)/austin/codesafe/src/runtime_secure_boot/boot_images_verifier	\
	-I$(SOURCE_DIR)/austin/codesafe/src/runtime_secure_boot/sw_revocation_manager	\
	-I$(SOURCE_DIR)/austin/shared/hw/include	\
	-I$(SOURCE_DIR)/austin/host/src/cclib/tee	\
	-I$(SOURCE_DIR)/austin/host/src/hal	\
	-I$(SOURCE_DIR)/austin/codesafe/src/crys/sym/driver	\
	-I$(SOURCE_DIR)/austin/shared/include/sbrom	\
	-I$(SOURCE_DIR)/austin/codesafe/src/runtime_secure_boot/vrl_verifier	\
	-I$(SOURCE_DIR)/austin/host/src/sb_runtime	\
	-I$(SOURCE_DIR)/austin/codesafe/src/runtime_secure_boot/platform/pal	\
	-I$(SOURCE_DIR)/austin/shared/include	\
	-I$(SOURCE_DIR)/austin/shared/include/pal	\
	-I$(SOURCE_DIR)/austin/shared/include/proj/cc63	\
	-I$(SOURCE_DIR)/austin/host/include
ifeq ($(CONFIG_ARM32_FLUSH_CACHE), true)
inc-flags += -DCONFIG_ARM32_FLUSH_CACHE
endif

inc-flags += -DDX_CONFIG_HASH_XOR_SUPPORTED -DDX_SOFT_KEYGEN -DDX_SOFT_KEYGEN_SIZE=3072 -DDX_CRYS_KEYGEN_MAX_SIZE= -DCC_HW_VERSION=0xBF -DLITTLE__ENDIAN -DHASLONGLONG -D__arm64__ -DDEBUG -DDX_CC_SRAM_INDIRECT_ACCESS -DTEE_DEBUG -DFW_VER_MAJOR=1 -DFW_VER_MINOR=0 -DFW_VER_PATCH=0 -DDX_CC_TEE -DMAX_NUM_HW_QUEUES=1 -DDLLI_MAX_BUFF_SIZE=128 -DDX_SEC_TIMER_TEST_ENV -DFW_MLLI_TABLE_LEN=128 -DSEP_SUPPORT_SHA=512 -DMIN_CRYPTO_TAIL_SIZE=32 -DDEBUG_OAEP_SEED=0 -DCRYS_RSA_SIGN_USE_TEMP_SALT=0 -DENABLE_AES_DRIVER=1 -DENABLE_DES_DRIVER=1 -DENABLE_HASH_DRIVER=1 -DENABLE_HMAC_DRIVER=1 -DENABLE_RC4_DRIVER=0 -DENABLE_AEAD_DRIVER=1 -DENABLE_ECC_DRIVER=1 -DENABLE_RSA_DRIVER=1 -DENABLE_BYPASS_DRIVER=1 -DENABLE_COMBINED_DRIVER=0 -DENABLE_KDF_DH_DRIVER=1 -DENABLE_C2_DRIVER=0 -DCRYS_NO_FIPS_SUPPORT -DCRYS_NO_RSA_SELF_TEST_SUPPORT -DCRYS_RND_SEM_DISABLE -DCRYS_PKA_INDIRECT_SRAM_ACCESS_MODE -DCRYS_NO_CRYS_COMBINED_SUPPORT -DDX_CONFIG_HASH_SHA_512_SUPPORTED -DSEP_CTX_SIZE_LOG2=8 -DDX_CONFIG_HASH_MD5_SUPPORTED -DDX_DMA_48BIT_SIM=0 -DDX_SB_ADDITIONAL_DATA_SUPPORTED -DCC_HW_VERSION=0xBF -DDX_SB_CERT_VERSION_MAJOR=1 -DDX_SB_CERT_VERSION_MINOR=0 -DSEP_SUPPORT_SHA=512 -DDX_DOUBLE_BUFFER_MAX_SIZE_IN_BYTES=8192


libdxcc_c_files += \
	austin/host/src/cclib/tee/bypass.c  \
	austin/host/src/cclib/tee/cc_acl_plat.c  \
	austin/host/src/cclib/tee/cc_plat.c  \
	austin/host/src/cclib/tee/completion_plat.c  \
	austin/host/src/cclib/tee/dma_buffer.c  \
	austin/host/src/cclib/tee/dx_cclib.c  \
	austin/host/src/cclib/tee/dx_rng_plat.c  \
	austin/host/src/cclib/tee/dx_util.c  \
	austin/host/src/cclib/tee/dx_util_oem_asset.c  \
	austin/host/src/cclib/tee/dx_util_rpmb_adaptor.c  \
	austin/host/src/cclib/tee/dx_util_rpmb.c  \
	austin/host/src/cclib/tee/dx_util_stimer.c  \
	austin/host/src/cclib/tee/hw_queue_plat.c  \
	austin/host/src/cclib/tee/key_buffer.c  \
	austin/host/src/cclib/tee/mlli_plat.c  \
	austin/host/src/cclib/tee/sbrt_management_api.c  \
	austin/host/src/cclib/tee/secure_key_gen.c  \
	austin/host/src/cclib/tee/sym_adaptor_driver.c  \
	austin/host/src/cclib/tee/validate_crys_bypass_plat.c  \
	austin/codesafe/src/crys/ccm/src/crys_ccm.c  \
	austin/codesafe/src/crys/common/src/crys_common_conv_endian.c  \
	austin/codesafe/src/crys/common/src/crys_common_math.c  \
	austin/codesafe/src/crys/dh/src/crys_dh.c  \
	austin/codesafe/src/crys/dh/src/crys_dh_kg.c  \
	austin/codesafe/src/crys/ecc/crys_ecc/ecc_common/src/crys_ecpki_build.c  \
	austin/codesafe/src/crys/ecc/crys_ecc/ecc_common/src/crys_ecpki_kg.c  \
	austin/codesafe/src/crys/ecc/crys_ecc/ecdh/src/crys_ecdh.c  \
	austin/codesafe/src/crys/ecc/crys_ecc/ecdsa/src/crys_ecdsa_sign.c  \
	austin/codesafe/src/crys/ecc/crys_ecc/ecdsa/src/crys_ecdsa_verify.c  \
	austin/codesafe/src/crys/ecc/llf_pki_ec/src/llf_ecpki_domains.c  \
	austin/codesafe/src/crys/ecc/llf_pki_ec/src/llf_ecpki_ec_arithmetic.c  \
	austin/codesafe/src/crys/ecc/llf_pki_ec/src/llf_ecpki_ecdsa.c  \
	austin/codesafe/src/crys/ecc/llf_pki_ec/src/llf_ecpki_export.c  \
	austin/codesafe/src/crys/ecc/llf_pki_ec/src/llf_ecpki_genkey.c  \
	austin/codesafe/src/crys/ecc/llf_pki_ec/src/llf_ecpki_modular_arithmetic.c  \
	austin/codesafe/src/crys/ecc/llf_pki_ec/src/llf_ecpki_version.c  \
	austin/codesafe/src/crys/gen/src/dx_asym_init.c  \
	austin/codesafe/src/crys/kdf/src/crys_kdf.c  \
	austin/codesafe/src/crys/rnd_dma/crys_rnd.c  \
	austin/codesafe/src/crys/rnd_dma/llf_rnd.c  \
	austin/codesafe/src/crys/rsa/ccsw_rsa/ccsw_crys_rsa_kg.c  \
	austin/codesafe/src/crys/rsa/crys_rsa/src/crys_rsa_build.c  \
	austin/codesafe/src/crys/rsa/crys_rsa/src/crys_rsa_kg.c  \
	austin/codesafe/src/crys/rsa/crys_rsa/src/crys_rsa_oaep.c  \
	austin/codesafe/src/crys/rsa/crys_rsa/src/crys_rsa_pkcs_ver15_util.c  \
	austin/codesafe/src/crys/rsa/crys_rsa/src/crys_rsa_prim.c  \
	austin/codesafe/src/crys/rsa/crys_rsa/src/crys_rsa_pss21_util.c  \
	austin/codesafe/src/crys/rsa/crys_rsa/src/crys_rsa_sign.c  \
	austin/codesafe/src/crys/rsa/crys_rsa/src/crys_rsa_verify.c  \
	austin/codesafe/src/crys/rsa/llf_pki/src/llf_pki_exp.c  \
	austin/codesafe/src/crys/rsa/llf_pki/src/llf_pki_genkey.c  \
	austin/codesafe/src/crys/rsa/llf_pki/src/llf_pki_genkey_x931_find_prime.c  \
	austin/codesafe/src/crys/rsa/llf_pki/src/llf_pki_pka.c  \
	austin/codesafe/src/crys/rsa/llf_pki/src/llf_pki_rsa.c  \
	austin/codesafe/src/crys/sym/api/crys_aes.c  \
	austin/codesafe/src/crys/sym/api/crys_aesccm.c  \
	austin/codesafe/src/crys/sym/api/crys_bypass.c  \
	austin/codesafe/src/crys/sym/api/crys_des.c  \
	austin/codesafe/src/crys/sym/api/crys_hash.c  \
	austin/codesafe/src/crys/sym/api/crys_hmac.c  \
	austin/codesafe/src/crys/sym/driver/aead.c  \
	austin/codesafe/src/crys/sym/driver/cipher.c  \
	austin/codesafe/src/crys/sym/driver/hash.c  \
	austin/codesafe/src/crys/sym/driver/hmac.c  \
	austin/codesafe/src/crys/sym/driver/hw_queue.c  \
	austin/codesafe/src/crys/sym/driver/mlli.c  \
	austin/codesafe/src/crys/sym/driver/sym_crypto_driver.c  \
	austin/codesafe/src/runtime_secure_boot/crypto_driver/crypto_driver_adaptor.c  \
	austin/codesafe/src/runtime_secure_boot/crypto_driver/crypto_driver.c  \
	austin/codesafe/src/runtime_secure_boot/platform/nvm/nvm_mng/nvm_mng.c  \
	austin/codesafe/src/runtime_secure_boot/secure_boot_gen/secureboot_base_func.c  \
	austin/codesafe/src/runtime_secure_boot/util/util.c  \
	austin/codesafe/src/runtime_secure_boot/vrl_verifier/bootimagesverifier_base_single.c  \
	austin/codesafe/src/runtime_secure_boot/vrl_verifier/bootimagesverifier_parser.c  \
	austin/codesafe/src/runtime_secure_boot/vrl_verifier/bootimagesverifier_swcomp.c  \
	austin/host/src/cclib/crys_context_relocation.c  \
	austin/host/src/hal/dx_hal.c  \
	austin/host/src/softcrys/pki/llf_pki_util_div.c  \
	austin/host/src/softcrys/pki/llf_pki_util_exp.c  \
	austin/host/src/softcrys/pki/llf_pki_util_exp_crt.c  \
	austin/host/src/softcrys/pki/llf_pki_util_invmod.c  \
	austin/host/src/softcrys/pki/llf_pki_util_monmul_32x32.c  \
	austin/host/src/softcrys/pki/llf_pki_util_rmul.c  \
	austin/host/src/softcrys/pki/sw_llf_pki_genkey.c  \
	austin/host/src/softcrys/pki/sw_llf_pki_rsa.c
