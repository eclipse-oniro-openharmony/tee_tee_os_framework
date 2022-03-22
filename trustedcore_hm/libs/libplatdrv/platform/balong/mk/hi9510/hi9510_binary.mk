ifeq ($(CONFIG_DX_ENABLE), true)
#llvm cannot parse these binaries
LIBS += dx_9500_sbrom dx_9500_dmpu
platdrv_LDFLAGS += -L$(SOURCE_DIR)/platform/balong/ccdriver_lib/hi9500
endif
