-include $(PREBUILD_DIR)/headers/.config

ifdef CONFIG_KASAN
    c-flags += -fsanitize=kernel-address -fasan-shadow-offset=$(CONFIG_APP_MMGR_LAYOUT_PROCESS_SIZE_32) --param=asan-stack=1 --param=asan-globals=1
ifeq ($(ARCH),arm)
    LIBS += asan_a32
else
    LIBS += asan
endif
endif
