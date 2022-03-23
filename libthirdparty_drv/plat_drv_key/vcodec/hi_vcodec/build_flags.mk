LOCAL_CFLAGS += -fno-omit-frame-pointer -fno-builtin-fwrite
LOCAL_CFLAGS += -fstack-protector-all -Wstack-protector

#add for enum size may different in different toolchain
LOCAL_CFLAGS += -fno-short-enums -fno-exceptions -fno-unwind-tables
LOCAL_ASFLAGS += -fno-short-enums -fno-exceptions -fno-unwind-tables
LOCAL_CXX_STL := none

ifeq ($(strip $(LPAE_SUPPORT)), true)
    LOCAL_CFLAGS += -DARM_PAE
    LOCAL_ASFLAGS += -DARM_PAE
    TRUSTEDCORE_LOCAL_CFLAGS += -DARM_PAE
    TRUSTEDCORE_LOCAL_ASFLAGS += -DARM_PAE
endif
