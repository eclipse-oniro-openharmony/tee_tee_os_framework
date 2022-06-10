# extra-flags is for export.txt and extern.txt of libteec_share
ifeq ($(CONFIG_KEYMASTER_64BIT), true)
	flags += -DTEE_SUPPORT_KEYMASTER_64BIT
else ifeq ($(CONFIG_KEYMASTER_32BIT), true)
	flags += -DTEE_SUPPORT_KEYMASTER_32BIT
endif

ifeq ($(CONFIG_SSA_64BIT), true)
flags += -DTEE_SUPPORT_SSA_64BIT
endif
ifeq ($(CONFIG_SSA_64BIT), false)
flags += -DTEE_SUPPORT_SSA_32BIT
endif

ifdef CONFIG_PERMSRV_64BIT
ifeq ($(CONFIG_PERMSRV_64BIT), true)
flags += -DTEE_SUPPORT_PERM_64BIT
else
flags += -DTEE_SUPPORT_PERM_32BIT
endif
endif

ifeq ($(CONFIG_CLOUD_CA_PUB_KEY), true)
flags += -DIT_PRODUCT_CA_PUB_KEY
endif

ifeq ($(CONFIG_CLOUD_SIGN_PUB_KEY), true)
flags += -DCLOUD_SIGN_PUB_KEY
endif

ifeq ($(CONFIG_PUBKEY_SHAREMEM), true)
flags += -DCONFIG_PUBKEY_SHAREMEM
endif

ifeq ($(CONFIG_TA_LOCAL_SIGN), true)
flags += -DTA_LOCAL_SIGN
endif

# keywest branch
#flags += -DKEYWEST_SIGN_PUB_KEY
#flags += -DTA_LOCAL_SIGN
#keywest branch end

ifeq ($(CONFIG_SEM), true)
flags += -DTEE_SUPPORT_SEM
endif

ifeq ($(CONFIG_SE_SERVICE_64BIT), true)
flags += -DTEE_SUPPORT_SE_SERVICE_64BIT
endif
ifeq ($(CONFIG_SE_SERVICE_32BIT), true)
flags += -DTEE_SUPPORT_SE_SERVICE_32BIT
endif

ifeq ($(CONFIG_HUK_SERVICE_64BIT), true)
flags += -DTEE_SUPPORT_HUK_SERVICE_64BIT
endif

ifeq ($(CONFIG_HUK_SERVICE_32BIT), true)
flags += -DTEE_SUPPORT_HUK_SERVICE_32BIT
endif

ifeq ($(CONFIG_MSP), true)
flags += -DTEE_SUPPORT_MSP
endif

ifeq ($(CONFIG_GATEKEEPER_64BIT), true)
flags += -DTEE_SUPPORT_GATEKEEPER_64BIT
endif

ifeq ($(CONFIG_GATEKEEPER_32BIT), true)
flags += -DTEE_SUPPORT_GATEKEEPER_32BIT
endif

ifeq ($(CONFIG_ANTIROOT), true)
flags += -DTEE_SUPPORT_ANTIROOT
endif

ifeq ($(CONFIG_DX_ENABLE), true)
flags += -DDX_ENABLE
endif

ifeq ($(CONFIG_KMS), true)
flags += -DTEE_SUPPORT_KMS
endif

ifeq ($(CONFIG_PLATDRV_64BIT), true)
flags += -DTEE_SUPPORT_PLATDRV_64BIT
endif

ifeq ($(CONFIG_PLATDRV_64BIT), false)
flags += -DTEE_SUPPORT_PLATDRV_32BIT
endif

ifeq ($(CONFIG_TEE_DRV_SERVER_64BIT), true)
flags += -DTEE_SUPPORT_DRV_SERVER_64BIT
endif

ifeq ($(CONFIG_TEE_DRV_SERVER_64BIT), false)
flags += -DTEE_SUPPORT_DRV_SERVER_32BIT
endif

ifeq ($(CONFIG_TEST_INNER_SERVICE_64BIT), true)
flags += -DTEST_INNER_SERVICE_64BIT
endif

ifeq ($(CONFIG_TEST_INNER_SERVICE_32BIT), true)
flags += -DTEST_INNER_SERVICE_32BIT
endif

ifeq ($(CONFIG_DYN_SRV_MULTI_THREAD_DISABLE), true)
flags += -DDYN_SRV_MULTI_THREAD_DISABLE
endif
