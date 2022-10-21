MODULE := libssa${TARG}.a

CFILES   := $(wildcard src/*.c)
CPPFLAGS += -I$(TEELIB)/libssa/include
CPPFLAGS += -I$(TEELIB)/libteemem/include
CPPFLAGS += -I$(TEELIB)/libcrypto_hal/include
CPPFLAGS += -I$(TEELIB)/libcrypto/include
CPPFLAGS += -I$(TEELIB)/libteeos/src/tee
CPPFLAGS += -I$(TEELIB)/libtimer/include
CPPFLAGS += -I$(TEELIB)/libteeos/include/legacy
CPPFLAGS += -I$(TEELIB)/libteeos/include
CPPFLAGS += -I$(TEELIB)/libteeos/include/tee # tee_inner_uuid.h
CPPFLAGS += -I$(TEELIB)/libteeagentcommon_client/include
CPPFLAGS += -I$(TEELIB)/libhuk/include

CFLAGS += -DOPENSSL_ENABLE
A32_CFLAGS += -DOPENSSL_ENABLE

include $(BUILD_LIB)/lib-common.mk
