#########################################################
# Environment initialize
#########################################################
HI_PROJECT  := mspe
HI_PLATFORM := teeos
HI_TARGET   := libcrypto
HI_CHIP_VER ?= $(if $(chip_type),$(TARGET_BOARD_PLATFORM)_$(chip_type),$(TARGET_BOARD_PLATFORM)_cs)
HI_DFT_ENABLE ?= $(if $(filter $(TARGET_BUILD_VARIANT),user),false,true)
include $(dir $(lastword $(MAKEFILE_LIST)))build/set_env.mk
