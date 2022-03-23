flags += -DTEE_SUPPORT_ATTESTATION_TA
flags += -DTEE_SUPPORT_HIVCODEC
flags += -DTEE_SUPPORT_TZMP2
ifeq ($(WITH_ENG_VERSION),true)
flags += -DVCODEC_ENG_VERSION
asflags += -DVCODEC_ENG_VERSION
else
flags := $(filter-out -DVCODEC_ENG_VERSION,$(flags))
asflags := $(filter-out -DVCODEC_ENG_VERSION,$(asflags))
endif

# for singleAP
ifeq ($(CFG_VENDOR_MINI_AP), true)
inc-flags += -DCONFIG_NO_MODEM
export WITH_MODEM := false

else
export WITH_MODEM := true
endif
