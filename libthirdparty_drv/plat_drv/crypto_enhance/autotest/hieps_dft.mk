#########################################################
# module initialize
#########################################################
MODULE_DIR := $(call module-dir)
MODULE_LIB-y := libhieps_autotest.a

#########################################################
# module configure
#########################################################
MODULE_CFLAGS := \
	-DFEATURE_HIEPS_AUTOTEST \
	-DFEATURE_PLATFORM_NAME=\"$(SEC_PRODUCT)\" -DFEATURE_CHIP_TYPE=\"$(SEC_CHIP_TYPE)\"

MODULE_INCLUDES := \
    -I$(MODULE_DIR) \
	-I$(MODULE_DIR)/framework

MODULE_COBJS-y := \
	framework/hat_entry.o \
	framework/hat_framework.o \
	config/hat_pack.o

SOURCE_HAT_PACK := $(addprefix $(TOPDIR)/libs/libplatdrv/,$(patsubst $(PROJECT_ROOT_DIR)/%,%,$(MODULE_DIR)/config/hat_pack.c))
$(SOURCE_HAT_PACK): hat_force
	python $(SEC_ROOT_DIR)/autotest/hat_pack.py "gen_code" "$(SEC_PRODUCT)"

hat_force:

#########################################################
# module make
#########################################################
$(eval $(call module-make))
