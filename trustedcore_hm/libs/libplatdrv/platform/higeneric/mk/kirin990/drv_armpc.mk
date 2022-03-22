#NPU //hi3690 enable compile
ifneq ($(chip_type),cs2)
AP_PLAT_HEAD_PATH:= $(SOURCE_DIR)/../../../../../../../vendor/hisi/ap/platform/kirin990
else
AP_PLAT_HEAD_PATH:= $(SOURCE_DIR)/../../../../../../../vendor/hisi/ap/platform/kirin990_cs2
endif

#modem start
BALONG_TOPDIR := $(SOURCE_DIR)/../../../../../../../vendor/hisi

inc-flags += -I$(BALONG_TOPDIR)/modem/config/product/$(OBB_PRODUCT_NAME)/config
#modem end
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secmem/include
inc-flags += -I$(AP_PLAT_HEAD_PATH)
inc-flags += -I$(NPU_DRIVER_INC_PATH)
$(warning AP_PLAT_HEAD_PATH $(AP_PLAT_HEAD_PATH))

# c++
USE_GNU_CXX = y
inc-flags += -I$(TOPDIR)/thirdparty/opensource/libbz_hm/src
LIBS += bz_hm

inc-flags += -I$(SOURCE_DIR)/platform \
	    -I$(SOURCE_DIR)/platform/common/include
ifneq ($(chip_type),cs2)
inc-flags += -I$(SOURCE_DIR)/platform/kirin/include/platform/kirin990
inc-flags += -DWITH_CHIP_CS
else
inc-flags += -DWITH_CHIP_CS2
inc-flags += -I$(SOURCE_DIR)/platform/kirin/include/platform/kirin990_cs2
inc-flags += -DMODEM_SOCP_3_0
endif

# i2c
inc-flags += -I$(SOURCE_DIR)/platform/kirin/i2c
CFILES += platform/kirin/i2c/i2c.c
# I3C
inc-flags += -I$(SOURCE_DIR)/platform/kirin/i3c
CFILES += platform/kirin/i3c/i3c.c
# spi
CFILES += platform/kirin/spi/spi.c

#ipc_mailbox
inc-flags += -DCONFIG_HISI_MAILBOX
inc-flags += -I$(SOURCE_DIR)/platform/common/include/mailbox
CFILES += platform/kirin/mailbox/ipc_mailbox.c

# gpio
CFILES += platform/kirin/gpio/gpio.c

# dma
CFILES += platform/kirin/dma/dma.c

# tzpc
inc-flags += -I$(SOURCE_DIR)/platform/common/tzpc
CFILES += platform/common/tzpc/tzpc_cfg.c

# oemkey
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/oemkey/oemkey_driver.mk


# tzarch
inc-flags += -I$(SOURCE_DIR)/platform/kirin/tzarch/include

# hisi_hwspinlock
CFILES += platform/kirin/seccfg/hisi_hwspinlock.c

# secmem
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secmem/include
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secmem/driver/sec
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secmem/driver/include

# secsvm
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secsvm/include
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secsvm/driver/

# secmem_ddr
COMPILE_SEC_DDR_TEST := false
inc-flags += -DCONFIG_HISI_DDR_AUTO_FSGT
inc-flags += -DCONFIG_HISI_DDR_SEC_CFC
inc-flags += -DCONFIG_HISI_DDR_SEC_HIFI_RESET
inc-flags += -DCONFIG_HISI_DDR_CA_RD
CFILES += platform/kirin/secmem/driver/sec/kirin990_ddr_autofsgt_proxy_secure_os.c
CFILES += platform/kirin/secmem/driver/sec/kirin990/sec_region.c
CFILES += platform/kirin/secmem/driver/sec/kirin990/tzmp2.c
ifeq ($(COMPILE_SEC_DDR_TEST),true)
CFILES += platform/kirin/secmem/driver/sec/kirin990/sec_region_test.c
inc-flags += -DCONFIG_HISI_SEC_DDR_TEST
endif


# ddr seccfg
ifeq ($(chip_type),es)
inc-flags += -DKIRIN990_DDR_ES
endif

# isp
inc-flags += -DCONFIG_SUPPORT_ISP_LOAD
inc-flags += -I$(SOURCE_DIR)/platform/common/include/isp
inc-flags += -I$(SOURCE_DIR)/platform/kirin/isp/kirin990
ifneq ($(product_type), armpc)
CFILES += platform/kirin/isp/kirin990/hisp.c
endif

# ivp
inc-flags += -I$(SOURCE_DIR)/platform/common/include/ivp
CFILES += platform/kirin/ivp/hivp.c

ifeq ($(CONFIG_DX_ENABLE), true)
# ccdriver_lib
ifneq ($(product_type), armpc)
inc-flags += -DCONFIG_USE_DUAL_ENGINE
endif
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api/cc7x_tee
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/proj/cc7x_tee
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/host/src/cc7x_teelib
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/pal
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/cc_util
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/codesafe/src/crypto_api
inc-flags += -I$(SOURCE_DIR)/platform/kirin/ccdriver_lib/include
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/pal/hmos
inc-flags += -I$(SOURCE_DIR)/platform/common/cc_driver
inc-flags += -I$(SOURCE_DIR)/platform/common/cc_driver/cc712
CFILES += platform/common/cc_driver/cc712/cc_driver_adapt.c \
		  platform/common/cc_driver/cc_driver_hal.c \
		  platform/kirin/ccdriver_lib/cc_power.c \
		  platform/kirin/ccdriver_lib/cc_adapt.c \

ifneq ($(product_type), armpc)
CFILES += platform/kirin/ccdriver_lib/eps_adapt.c \
		  platform/kirin/ccdriver_lib/eps_driver_hal.c
endif

# eima2.0+rootscan
CFILES += platform/kirin/antiroot/nonsecure_hasher.c
endif

inc-flags += -I$(SOURCE_DIR)/platform/kirin/modem/icc \
	    -I$(SOURCE_DIR)/platform/kirin/modem/include
ifeq ($(WITH_MODEM), true)

CFILES += platform/kirin/modem/adp/adp_icc.c \
	  platform/kirin/modem/adp/bsp_modem_call.c \
	  platform/kirin/modem/adp/bsp_param_cfg.c \
	  platform/kirin/modem/adp/bsp_secboot_adp.c

ICC_CFILES = platform/kirin/modem/icc/ipc_core.c \
	  platform/kirin/modem/icc/icc_core.c \
	  platform/kirin/modem/icc/icc_debug.c \
	  platform/kirin/modem/icc/icc_secos.c

CFILES += $(ICC_CFILES)

# modem trng
inc-flags += -DCONFIG_MODEM_TRNG
CFILES += platform/kirin/modem/trng/trng_seed.c
endif

# secureboot
inc-flags += -DWITH_IMAGE_LOAD_SUPPORT \
	    -DCONFIG_DYNAMIC_MMAP_ADDR
inc-flags += -DCONFIG_CHECK_PTN_NAME
inc-flags += -DCONFIG_CHECK_PLATFORM_INFO

inc-flags += -I$(SOURCE_DIR)/platform/kirin/secureboot \
	    -I$(SOURCE_DIR)/platform/kirin/secureboot/include \
	    -I$(SOURCE_DIR)/platform/common/include/ivp

CFILES += platform/kirin/secureboot/secureboot.c \
	  platform/kirin/secureboot/secboot.c \
	  platform/kirin/secureboot/process_hifi_info.c \
	  platform/kirin/secureboot/process_isp_info.c \
	  platform/kirin/secureboot/zlib/adler32.c \
	  platform/kirin/secureboot/zlib/inffast.c \
	  platform/kirin/secureboot/zlib/inflate.c \
	  platform/kirin/secureboot/zlib/inftrees.c \
	  platform/kirin/secureboot/zlib/uncompr.c \
	  platform/kirin/secureboot/zlib/zutil.c

ifeq ($(WITH_MODEM), true)
CFILES += platform/kirin/secureboot/process_modem_info.c

ifeq ($(chip_type), cs2)
CFILES += platform/kirin/secureboot/hisi_secboot_modem_aslr.c \
	  platform/kirin/secureboot/hisi_secboot_modem_patch.c
#536使用新的mloader和对应的冷补丁
inc-flags += -DCONFIG_MLOADER
inc-flags += -DCONFIG_MODEM_COLD_PATCH
#536开始有5g core
inc-flags += -DCONFIG_MODEM_ASLR_5G_CORE
else
#phoenix使用老的loadm和老的冷补丁
inc-flags += -DCONFIG_COLD_PATCH
endif

CFILES += platform/kirin/modem/adp/sec_modem_dump.c
else
CFILES += platform/kirin/modem/adp/bsp_modem_stub.c
CFILES += platform/kirin/secureboot/process_modem_info_stub.c
endif

ifneq ($(product_type), armpc)
CFILES  +=  \
          platform/kirin/secureboot/process_ivp_info.c
inc-flags += -DCONFIG_HISI_NVIM_SEC
inc-flags += -DCONFIG_HISI_IVP_SEC_IMAGE
endif

#modem_cold_patch
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secureboot/bspatch/ \
	    -I$(SOURCE_DIR)/platform/kirin/secureboot/bspatch/include \
	    -I$(SOURCE_DIR)/platform/kirin/secureboot/bspatch/include/bsdiff
platdrv_cpp_files += platform/kirin/secureboot/bspatch/bspatch.cpp \
	  platform/kirin/secureboot/bspatch/buffer_file.cpp \
	  platform/kirin/secureboot/bspatch/extents.cpp \
	  platform/kirin/secureboot/bspatch/extents_file.cpp \
	  platform/kirin/secureboot/bspatch/file.cpp \
	  platform/kirin/secureboot/bspatch/memory_file.cpp \
	  platform/kirin/secureboot/bspatch/sink_file.cpp \
	  platform/kirin/secureboot/bspatch/secure_bspatch.cpp

# hifi
inc-flags += -DCONFIG_SUPPORT_HIFI_LOAD
inc-flags += -I$(SOURCE_DIR)/platform/common/include/hifi
CFILES += platform/kirin/hifi/hifi_reload.c

# touchscheen
inc-flags += -I$(SOURCE_DIR)/platform/common/touchscreen		\
	    -I$(SOURCE_DIR)/platform/common/touchscreen/panel	\
	    -I$(SOURCE_DIR)/platform/kirin/touchscreen \
		-I$(SOURCE_DIR)/platform/common/tui

# fingerprint
CFILES += platform/kirin/fingerprint/src/tee_fingerprint.c

# inse
inc-flags += -DSE_VENDOR_HISEE
inc-flags += -DCONFIG_HISEE_IPC_SUPPORT_BIGDATA
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/hisee
CFILES += \
		  platform/kirin/eSE/hisee/hisee.c \
		  platform/kirin/eSE/hisee/ipc_a.c \
		  platform/kirin/eSE/hisee/ipc_msg.c

# Encrypted Image Incremental Update Service(eiius)
inc-flags += -DCONFIG_HISI_EIIUS
CFILES += platform/kirin/secureboot/eiius_interface.c

ifneq ($(cust_config), cust_modem_asan)
inc-flags += -DCONFIG_MODEM_BALONG_ASLR
endif
# face_recognize
ifneq ($(product_type), armpc)
inc-flags += -DSWING_SUPPORTED
CFILES += platform/kirin/face_recognize/tee_face_recognize.c
endif

inc-flags += -I$(SOURCE_DIR)/platform/kirin/
inc-flags += -I$(SOURCE_DIR)/platform/kirin/include/

# p61
inc-flags += -DSE_SUPPORT_ST
inc-flags += -DSE_VENDOR_NXP
inc-flags += -DHISI_TEE
inc-flags += -DSE_SUPPORT_MULTISE
inc-flags += -DSE_SUPPORT_SN110
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/p61
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/p61/inc
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/p61/lib
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/p73
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/t1
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/p73/inc
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/p73/pal
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/p73/common
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/p73/lib
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/p73/spm
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/p73/utils
inc-flags += -I$(SOURCE_DIR)/platform/kirin/eSE/p73/pal/spi

CFILES += platform/kirin/eSE/p61/p61.c
CFILES += platform/kirin/eSE/p61/lib/phNxpEse_Api_p61.c
CFILES += platform/kirin/eSE/p61/lib/phNxpEse_Api_hisi_p61.c
CFILES += platform/kirin/eSE/p61/lib/phNxpEseDataMgr_p61.c
CFILES += platform/kirin/eSE/p61/lib/phNxpEseProto7816_3_p61.c
CFILES += platform/kirin/eSE/t1/t1.c
CFILES += platform/kirin/eSE/p73/p73.c
CFILES += platform/kirin/eSE/p73/pal/spi/phNxpEsePal_spi.c
CFILES += platform/kirin/eSE/p73/pal/phNxpEsePal.c
CFILES += platform/kirin/eSE/p73/lib/phNxpEse_Api.c
CFILES += platform/kirin/eSE/p73/lib/phNxpEse_Api_hisi.c
CFILES += platform/kirin/eSE/p73/lib/phNxpEse_Apdu_Api.c
CFILES += platform/kirin/eSE/p73/lib/phNxpEseDataMgr.c
CFILES += platform/kirin/eSE/p73/lib/phNxpEseProto7816_3.c
CFILES += platform/kirin/eSE/p73/utils/ese_config_hisi.c
CFILES += platform/kirin/eSE/p73/utils/ringbuffer.c

# hieps
ifeq ($(FEATURE_HISI_HIEPS), true)
ifeq ($(CONFIG_DX_ENABLE), true)
    export SEC_DFT_ENABLE := $(WITH_ENG_VERSION)
    export SEC_PRODUCT = $(TARGET_BOARD_PLATFORM)
    export PROJECT_ROOT_DIR = $(SOURCE_DIR)
    include $(SOURCE_DIR)/platform/kirin/hieps/Makefile
    SEC_CFILES := $(patsubst $(SOURCE_DIR)/%,%,$(SEC_CFILES))
    $(info HIEPS SEC_INCS = $(SEC_INCS) -I$(SOURCE_DIR)/platform/kirin/hieps/include)
    $(info HIEPS SEC_CFLAGS = $(SEC_CFLAGS))
    $(info HIEPS SEC_CFILES = $(SEC_CFILES))
    CFILES += $(SEC_CFILES)

    CFILES := $(addprefix $(TOPDIR)/libs/libplatdrv/,$(CFILES))
    inc-flags += $(SEC_INCS) \
                -I$(SOURCE_DIR)/platform/kirin/hieps/include
    c-flags += $(SEC_CFLAGS)
ifeq ($(chip_type), cs2)
inc-flags += -DCONFIG_HIEPS_BYPASS_TEST
endif

endif
endif

# teeos shared memmory
CFILES += $(SOURCE_DIR)/platform/kirin/tee_sharedmem/bl2_sharedmem.c
inc-flags += -I$(SOURCE_DIR)/platform/kirin/tee_sharedmem

