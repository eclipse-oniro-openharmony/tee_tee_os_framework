# burbank
LIBS += dx_burbank_sbrom
platdrv_LDFLAGS += -L$(SOURCE_DIR)/platform/kirin/ccdriver_lib

ifeq ($(WITH_MODEM), true)
platdrv_LDFLAGS += -L$(SOURCE_DIR)/../../output/arm/libs --whole-archive -lsec_modem --no-whole-archive
endif

ifeq ($(FEATURE_HISI_MSP_ENGINE_LIBCRYPTO), true)
LIBS += $(patsubst lib%.a,%,$(notdir $(HI_OUT_LIBSECENG)))
platdrv_LDFLAGS += -L$(dir $(HI_OUT_LIBSECENG))
endif

