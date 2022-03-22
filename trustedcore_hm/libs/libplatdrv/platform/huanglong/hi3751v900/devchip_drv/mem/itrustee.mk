#drv_incs  :=
#drv_srcs  :=
#drv_flags :=

drv_incs += . \
            ./include \
            sec_mmz/include

drv_srcs += init.c

ifeq ($(strip $(CFG_HI_TEE_SEC_MMZ_SUPPORT)), y)
drv_srcs += sec_mmz/media_mem.c \
            sec_mmz/mmz_intf.c \
            sec_mmz/mmz_ext.c \
            sec_mmz/mmz_user.c
endif

ifeq ($(strip $(CFG_HI_TEE_SMMU_SUPPORT)), y)
drv_incs += hi_smmu/include
drv_srcs += hi_smmu/hi_smmu_intf.c \
            hi_smmu/bitmap.c \
            hi_smmu/hi_smmu.c \
            hi_smmu/hi_smmu_common.c \
            hi_smmu/hi_smmu_mem.c \
	    hi_smmu/hi_smmu_test.c
#drv_incs += hi_smmu/include

endif


