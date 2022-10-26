MODULE := libhuk${TARG}.a

CFILES += $(wildcard src/tee_huk_derive_key.c)
CFILES += $(wildcard src/tee_huk_get_device_id.c)
CFILES += $(wildcard src/huk_service_msg_call.c)

CPPFLAGS += -I$(TEELIB)/libhuk/include
CPPFLAGS += -I$(TEELIB)/libhuk/src/huk_service
CPPFLAGS += -I$(TEELIB)/libteemem/include
CPPFLAGS += -I$(TEELIB)/libtimer/include
CPPFLAGS += -I$(TEELIB)/libteeconfig/include
CPPFLAGS += -I$(TEELIB)/libteeconfig/include/TEE_ext
CPPFLAGS += -I$(TEELIB)/libteeos/include
CPPFLAGS += -I$(TEELIB)/libteeos/include/tee
CPPFLAGS += -I$(TEELIB)/libteeos/include/legacy
CPPFLAGS += -I$(TEELIB)/libteeos/src/tee
CPPFLAGS += -I$(TEELIB)/libcrypto/include
CPPFLAGS += -I$(TEELIB)/libssa/include

include $(TOPDIR)/mk/lib-common.mk
