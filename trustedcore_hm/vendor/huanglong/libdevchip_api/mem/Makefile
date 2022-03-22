
#api_incs  :=
#api_srcs  :=
#api_flags :=

api_incs += include/
ifeq ($(CFG_HI_TEE_SMMU_SUPPORT), y)
api_srcs += hi_tee_mem.c
endif

ifeq ($(CFG_HI_TEE_SEC_MMZ_SUPPORT), y)
api_srcs += hi_tee_mmz.c
endif
