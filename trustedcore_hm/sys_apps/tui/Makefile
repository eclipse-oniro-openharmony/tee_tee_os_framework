# tui compile rule, modified by DuJie dujie7@huawei.com
# Copyright Huawei Technologies Co., Ltd. 2010-2020. All rights reserved.

TARGET := tui.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

tui_c_files += $(wildcard src/*.c)

flags += -I$(TOPDIR)/sys_apps/tui/src/

# Libraries
LIBS := tui_internal_a32
ifeq ($(TARGET_BOARD_PLATFORM), kirin980)
LIBS += thp_afe
endif
ifeq ($(TARGET_BOARD_PLATFORM), kirin970)
LIBS +=	thp_afe_970
endif

ifeq ($(TARGET_BOARD_PLATFORM), kirin710)
LIBS +=	thp_afe_710
endif

ifeq ($(TARGET_BOARD_PLATFORM), hi3660)
LIBS +=	thp_afe_3660_6250
endif
ifeq ($(TARGET_BOARD_PLATFORM), hi6250)
LIBS +=	thp_afe_3660_6250
endif
ifeq ($(TARGET_BOARD_PLATFORM), orlando)
LIBS +=	thp_afe_orlando
endif
ifeq ($(TARGET_BOARD_PLATFORM), kirin990)
LIBS +=	thp_afe_990
endif
ifeq ($(TARGET_BOARD_PLATFORM), denver)
LIBS += thp_afe_denver
endif

ifeq ($(TARGET_BOARD_PLATFORM), baltimore)
LIBS += thp_afe_baltimore${TARG}
endif

ifeq ($(TARGET_BOARD_PLATFORM), mt6885)

endif

include $(TOPDIR)/mk/ta-common.mk
INCLUDE_PATH += $(DDK_INCLUDE_PATH_COMMON)
$(warning info is printing)
$(warning $(DDK_INCLUDE_PATH_COMMON))
TA_LDFLAGS := -r -d -T$(TOPDIR)/mk/ta_link.ld
TA_LDFLAGS += -L$(LIB_DIR)
TA_LDFLAGS += -L$(PREBUILD_ARCH_PLAT_LIBS) $(LINK_LIBS)
ifeq ($(TARGET_BOARD_PLATFORM), kirin970)
TA_LDFLAGS += -L$(LIBS_DIR)/libthp_afe_970/libs -lafehal_jdi_new -lthp_afe_hal_emily_snps -lthp_afe_hal_nova -ltsa
endif
ifeq ($(TARGET_BOARD_PLATFORM), kirin980)
TA_LDFLAGS += -L$(LIBS_DIR)/libthp_afe/libs -lthp_afe_hal_hima_nova -lthp_afe_hal_hima_syns -lthp_afe_hal_goodix -lthp_afe_hal_solomon -ltsa -lthp_afe_hal_himax -lthp_afe_hal_yale_focal -lthp_afe_hal_yale_nova -lthp_afe_hal_yale_snps -lthp_afe_hal_b141_goodix -lthp_afe_hal_tui_for085_goodix
endif
ifeq ($(TARGET_BOARD_PLATFORM), kirin990)
TA_LDFLAGS += -L$(LIBS_DIR)/libthp_afe_990/libs -lthp_afe_hal_waltz_snps -lthp_afe_hal_waltz_nova -lthp_afe_hal_oxford_snps -lthp_afe_hal_oxford_nova -lthp_afe_hal_edin_snps -lthp_afe_hal_edin_goodix -ltsa
endif

ifeq ($(TARGET_BOARD_PLATFORM), denver)
TA_LDFLAGS += -L$(LIBS_DIR)/libthp_afe_denver/libs -lthp_afe_hal_goodix -lthp_afe_hal_snps -lthp_afe_hal_cindy_nova -lthp_afe_hal_cindy_syna -lthp_afe_hal_20x_snps -lthp_afe_hal_b20x_goodix -ltsa
endif
ifeq ($(TARGET_BOARD_PLATFORM), kirin710)
TA_LDFLAGS += -L$(LIBS_DIR)/libthp_afe_710/libs -lthp_afe_hal_hp_nova -lthp_afe_hal_hp_td4320 -lthp_afe_hal_hp_td4330 -ltsa
endif
ifeq ($(TARGET_BOARD_PLATFORM), orlando)
TA_LDFLAGS += -L$(LIBS_DIR)/libthp_afe_orlando/libs -lthp_afe_hal_saipan_snps -lthp_afe_hal_saipan_nova -lthp_afe_hal_saipan_focal -ltsa -lthp_afe_hal_b141_goodix -lthp_afe_hal_yale_snps -lthp_afe_hal_yale_nova
endif

ifeq ($(TARGET_BOARD_PLATFORM), baltimore)
TA_LDFLAGS += -L$(LIBS_DIR)/libthp_afe_baltimore_a32/libs -lthp_afe_hal_goodix -ltsa -lthp_afe_hal_st -lthp_afe_hal_dp167_goodix
endif

ifeq ($(TARGET_BOARD_PLATFORM), mt6885)
TA_LDFLAGS += -L$(LIBS_DIR)/libthp_afe_mtk6885/libs
endif
#TA_LDFLAGS:=$(filter-out -pie,$(TA_LDFLAGS))
#TA_LDFLAGS:=$(filter-out --gc-sections,$(TA_LDFLAGS))
