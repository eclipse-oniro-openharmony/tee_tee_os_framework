export CONFIG_TA_32BIT := true
export CONFIG_TA_64BIT := false
export CONFIG_SSA_64BIT := false
export CONFIG_GTASK_64BIT := false
#export CONFIG_DRV_TIMER_64BIT := false
#export CONFIG_IPC_SEC_ENABLE := true
#export CONFIG_TRNG_ENABLE := true
export CONFIG_HUK_SERVICE_32BIT := true
export CONFIG_TA_SIGN_KEY_CBG := true
#export CONFIG_SE_SERVICE_32BIT :=true
export CONFIG_NO_ZIP_IMAGE := true
export CONFIG_PERMSRV_64BIT := false
export CONFIG_BOOT_ARGS_TRANSFER := true
#export CONFIG_NO_PLATCFG_EMBEDDED := true
export CONFIG_NO_VENDOR_LIB_EMBEDDED := true
export CONFIG_DYN_SRV_MULTI_THREAD_DISABLE := true
export CONFIG_TEE_MISC_DRIVER_64BIT := false
export ENABLE_TA_LOAD_WHITE_BOX_KEY :=true

#set hisi_drv to BLOCKLIST with no -Werror
#BLOCKLIST += ipc/sec
#export BLOCKLIST

boot-fs-files-y += $(PREBUILD_APPS)/taloader.elf

