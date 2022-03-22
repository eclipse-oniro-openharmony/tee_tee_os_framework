# hi6250
LIBS += dx_cc63_sbrom
platdrv_LDFLAGS += -L$(SOURCE_DIR)/platform/kirin/ccdriver_lib
LIBS += sec_decoder
platdrv_LDFLAGS += -L$(SOURCE_DIR)/platform/kirin/vcodec/hi_vcodec/hi3670
