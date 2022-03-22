flags += -DTEE_SUPPORT_ATTESTATION_TA
flags += -DTEE_SUPPORT_TZMP2
flags += -DTEE_SUPPORT_HIVCODEC

ifeq ($(CONFIG_DRIVER_DYN_MOD), true)
flags += -DCONFIG_DRIVER_DYN_MOD
endif

ifeq ($(CONFIG_CRYPTO_AGENT), true)
flags += -DTEE_SUPPORT_CRYPTO_AGENT
endif

ifeq ($(WITH_ENG_VERSION),true)
flags += -DVCODEC_ENG_VERSION
asflags += -DVCODEC_ENG_VERSION
else
flags := $(filter-out -DVCODEC_ENG_VERSION,$(flags))
asflags := $(filter-out -DVCODEC_ENG_VERSION,$(asflags))
endif
# for arm pc
ifeq ($(strip $(product_type)), armpc)
inc-flags += -DCONFIG_NO_MODEM
export WITH_MODEM := false

#for P+B
else ifeq ($(strip $(extra_modem)), hi9500_udp)
inc-flags += -DCONFIG_NO_MODEM
export WITH_MODEM := false

# for singleAP
else ifeq ($(CFG_VENDOR_MINI_AP), true)
inc-flags += -DCONFIG_NO_MODEM
export WITH_MODEM := false

else
export WITH_MODEM := true
endif

