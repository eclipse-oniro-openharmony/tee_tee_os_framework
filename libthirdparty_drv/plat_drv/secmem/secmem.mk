
inc-flags += -DTEE_SUPPORT_TZMP2
inc-flags += -DCONFIG_HISI_SION_RECYCLE
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secmem/include
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secmem/driver/sec
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secmem/driver/include
CFILES += platform/kirin/secmem/driver/sion/sion.c \
	  platform/kirin/secmem/driver/iommu/siommu.c \
	  platform/kirin/secmem/driver/lib/genalloc.c \
	  platform/kirin/secmem/driver/lib/bitmap.c \
	  platform/kirin/secmem/driver/sion/sion_recycling.c

ifeq ($(WITH_ENG_VERSION), true)
CFILES += platform/kirin/secmem/driver/sion/sion_test.c
endif

