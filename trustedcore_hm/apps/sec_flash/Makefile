# Target is a TA app
TARGET := sec_flash.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)
ifeq ($(CONFIG_HISI_SECFLASH),true)
sec_flash_c_files += $(wildcard src/*.c)
c-flags += -DCONFIG_HISI_SECFLASH
c-flags += -DCC_DRIVER=1 -Wall
c-flags += -DSECFLASH_PARTITION_HIGH_HALF_ENABLE
else
sec_flash_c_files += src/sec_flash_msg.c src/msp/secflash_sa_comm.c

c-flags += -DSUPPORT_DYN_SECFLASH
c-flags += -DHISI_MSP_SECFLASH
c-flags += -DCONFIG_HISI_MSPC
c-flags += -Wextra -Wdate-time -Wfloat-equal -Wshadow -Wformat=2 -O2
endif

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE),boringssl)
c-flags += -DBORINGSSL_ENABLE
endif

# Libraries
LIBS := teeagentcommon${TARG}

inc-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon/src/
inc-flags += -I$(TOPDIR)/libs/libsec_flash_client_a32/include
inc-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include
inc-flags += -I$(TOPDIR)/libs/libmspcore/include
inc-flags += -I$(TOPDIR)/vendor/higeneric/libvendor_shared/src

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE), boringssl)
inc-flags += -I$(PREBUILD_HEADER)/boringssl
endif

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE), openssl)
inc-flags += -I$(PREBUILD_HEADER)/openssl
endif

include $(TOPDIR)/mk/ta-common.mk

ifeq ($(CONFIG_DYNLINK),y)
TA_LDFLAGS += -e tee_task_entry
endif
