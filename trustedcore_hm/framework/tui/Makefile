# tui compile rule, modified by t00292236
# Copyright Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.

DRIVER := tui${TARG}.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

include $(TOPDIR)/mk/var.mk

tui_c_files += $(wildcard src/*.c)

# Libraries
LIBS := tui_internal${TARG}

inc-flags += -I$(TOPDIR)/libs/libthp_common/include

ifeq ($(TARGET_BOARD_PLATFORM), baltimore)
LIBS += thp_afe_baltimore${TARG}
endif

ifeq ($(TARGET_BOARD_PLATFORM), baltimore)
$(shell cp $(LIBS_DIR)/libthp_afe_baltimore/libs/libtsa.a $(OUTPUTDIR)/aarch64/libs)
$(shell cp $(LIBS_DIR)/libthp_afe_baltimore/libs/libthp_afe_hal_st.a $(OUTPUTDIR)/aarch64/libs)
$(shell cp $(LIBS_DIR)/libthp_afe_baltimore/libs/libthp_afe_hal_goodix.a $(OUTPUTDIR)/aarch64/libs)
$(shell cp $(LIBS_DIR)/libthp_afe_baltimore_a32/libs/libtsa_a32.a $(OUTPUTDIR)/arm/libs)
$(shell cp $(LIBS_DIR)/libthp_afe_baltimore_a32/libs/libthp_afe_hal_st_a32.a $(OUTPUTDIR)/arm/libs)
$(shell cp $(LIBS_DIR)/libthp_afe_baltimore_a32/libs/libthp_afe_hal_goodix_a32.a $(OUTPUTDIR)/arm/libs)
DRV_LDFLAGS += -L$(LIBS_DIR)/libthp_afe_baltimore/libs
LIBS += thp_afe_hal_goodix${TARG} tsa${TARG} thp_afe_hal_st${TARG}
endif

ifeq ($(CONFIG_DYNLINK),y)
DRV_LDFLAGS += -e tee_task_entry
endif

SVC_PARTITIAL_LINK = y
include $(TOPDIR)/mk/svc-common.mk

