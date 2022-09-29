ifeq ($(CONFIG_LLVM_CFI),y)

ifeq ($(CONFIG_LLVM_LTO),y)
tee-sanitize-cfi := -fsanitize=cfi -fno-sanitize-cfi-cross-dso
else
$(info use cfi $(tee-sanitize-cfi) please set CONFIG_LLVM_LTO)
endif

## can't support -fno-sanitize-trap=cfi -fsanitize-recover=cfi
ifeq ($(findstring fvisibility=hidden,$(flags)),)
apps-sanitize-cfi += -fvisibility=default
endif

ifeq ($(ARCH),aarch64)
cfi-no-icall := libswcrypto_engine.a tarunner.elf libtimer.a libcrypto_hal.a libteeos.a libpermission_service.a libtaentry.a \
	libcrypto.a

ifneq ($(filter $(cfi-no-icall),$(MODULE)), )
apps-sanitize-cfi += -fno-sanitize=cfi-icall
endif

ifneq ($(filter $(cfi-no-icall),$(DRIVER)), )
apps-sanitize-cfi += -fno-sanitize=cfi-icall
endif

else #32bit

ifeq ($(PLATFORM_NAME),mtk)
cfi-no-icall := libswcrypto_engine_a32.a tarunner_a32.elf libtimer_a32.a libcrypto_hal_a32.a 
else
cfi-no-icall := libswcrypto_engine_a32.a tarunner_a32.elf libtimer_a32.a libcrypto_hal_a32.a libdrv_frame_a32.a libteeos_a32.a \
	libpermission_service_a32.a libtaentry_a32.a libcrypto_a32.a
endif

no-cfi:=

ifneq ($(filter $(cfi-no-icall),$(MODULE)), )
apps-sanitize-cfi += -fno-sanitize=cfi-icall
endif

ifneq ($(filter $(cfi-no-icall),$(DRIVER)), )
apps-sanitize-cfi += -fno-sanitize=cfi-icall
endif

ifneq ($(filter $(cfi-no-icall),$(TARGET)), )
apps-sanitize-cfi += -fno-sanitize=cfi-icall
endif

ifneq ($(filter $(no-cfi),$(MODULE)), )
apps-sanitize-cfi :=
endif

ifneq ($(filter $(no-cfi),$(DRIVER)), )
apps-sanitize-cfi :=
endif

ifneq ($(filter $(no-cfi),$(TARGET)), )
apps-sanitize-cfi :=
endif

endif#aarch64

flags += $(apps-sanitize-cfi)
$(info inapps $(DRIVER)$(MODULE)$(TARGET) use $(apps-sanitize-cfi))
endif #CONFIG_LLVM_CFI
