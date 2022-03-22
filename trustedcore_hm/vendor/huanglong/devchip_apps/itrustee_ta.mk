TA_DIR = $(notdir $(shell pwd))

$(info ========TA_DIR = $(TA_DIR))

$(TA_DIR)_c_files += $(c_files)

flags += -DTEE_PARAM_TYPE_NSSMMU_HAND_INPUT=0x9
flags += -DTEE_PARAM_TYPE_SECSMMU_HAND_INPUT=0xa
flags += -DTEE_PARAM_TYPE_PHYS_HAND_INPUT=0xb

c-flags += -I$(TOPDIR)/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/include \
           -I$(TOPDIR)/vendor/huanglong/libdevchip_api/include \
           -I$(TOPDIR)/vendor/huanglong/libdevchip_api/ta_al/itrustee

# Libraries
LIBS += devchip_api$(TARG)

include $(TOPDIR)/mk/ta-common.mk
