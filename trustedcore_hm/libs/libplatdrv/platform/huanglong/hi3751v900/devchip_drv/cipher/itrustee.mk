#drv_incs  :=
#drv_srcs  :=
#drv_flags :=

include $(TOPDIR)/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/cipher/build.mak

#drv_flags += -DHI_CIPHER_MODE_ECB_DISABLE
drv_flags += -DHI_SHA1_DISABLE
drv_flags += -DHI_SHA224_DISABLE

drv_flags += $(CIPHER_CFLAGS)
drv_incs  += $(CIPHER_INC)
drv_srcs  += $(OBJS:%.o=%.c)

drv_incs += ../../libdevchip_api/include
drv_incs += ../../libdevchip_api//cipher

drv_incs += cenc include tee/include

drv_incs += ../../../../../../../thirdparty/vendor/libdxcc/pal/include
drv_incs += ../../../../../../../thirdparty/vendor/libdxcc/austin/shared/include/crys
drv_incs += ../../../../../../../thirdparty/vendor/libdxcc/austin/shared/include/pal
drv_incs += ../../../../../../../thirdparty/vendor/libdxcc/austin/shared/include/dx_util
drv_incs += ../../../../../../../thirdparty/vendor/libdxcc/austin/codesafe/src/crys/common/inc
drv_incs += ../../../../../../../thirdparty/vendor/libdxcc/austin/codesafe/src/crys/rsa/crys_rsa/inc
drv_incs += ../../../../../../../thirdparty/vendor/libdxcc/austin/codesafe/src/crys/rnd_dma
drv_incs += ../../../../../../../thirdparty/vendor/libdxcc/austin/codesafe/src/crys/ecc/crys_ecc/ecc_common/inc

