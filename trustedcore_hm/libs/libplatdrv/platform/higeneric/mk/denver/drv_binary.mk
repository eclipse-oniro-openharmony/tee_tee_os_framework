# denver
LIBS += dx_denver_sbrom
platdrv_LDFLAGS += -L$(SOURCE_DIR)/platform/kirin/ccdriver_lib

ifeq ($(WITH_MODEM), true)
platdrv_LDFLAGS += -L$(SOURCE_DIR)/../../output/arm/libs --whole-archive -lsec_modem --no-whole-archive
endif
