# Targets

SOURCE_DIR := $(ELFLOADER_SOURCE_ROOT)

ELFLOADER_SOURCE_ROOT := $(TOPDIR)/kernel/elfloader

ELFLOADER_ROOT_PATH := $(CURDIR)
ifeq ($(CONFIG_ARCH_AARCH32), y)
	TARGET_IS_ARM32:=y
	ARCH := arm
else
	ARCH := aarch64
endif

include $(TOPDIR)/mk/var.mk
include $(TOPDIR)/mk/plat.mk

include $(TOPDIR)/mk/toolchain.mk
include $(PREBUILD_DIR)/headers/autoconf.h
include $(TOPDIR)/mk/arch_config.mk

include $(TOPDIR)/platform/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/product_config.mk

HM_BUILD_TIME_STR := "unknown"
HM_BUILD_COMMIT_STR := "unknown"
_BIN_DATE = $(shell which date)
ifneq ($(_BIN_DATE),)
    HM_BUILD_TIME_STR := $(shell date -u "+%Y-%m-%d-%H-%M-%S")
endif
_BIN_GIT = $(shell which git)
ifneq ($(_BIN_GIT),)
    HM_BUILD_COMMIT_STR := $(shell git rev-parse --short HEAD 2>/dev/null)
    ifeq ($(HM_BUILD_COMMIT_STR),)
        HM_BUILD_COMMIT_STR := "unknown"
    endif
endif

ifeq ($(__ARM_64__), y)
TYPE_SUFFIX:=64
else
ifeq ($(__ARM_32__), y)
TYPE_SUFFIX:=32
else
$(error TYPE_SUFFIX Cannot be determined)
endif
endif

# Build the source files
CFILES   := $(patsubst $(ELFLOADER_SOURCE_ROOT)/%,%,$(wildcard $(ELFLOADER_SOURCE_ROOT)/src/*.c))
CFILES   += $(patsubst $(ELFLOADER_SOURCE_ROOT)/%,%,$(wildcard $(ELFLOADER_SOURCE_ROOT)/src/arch-arm/*.c))
CFILES   += $(patsubst $(ELFLOADER_SOURCE_ROOT)/%,%,$(wildcard $(ELFLOADER_SOURCE_ROOT)/src/arch-arm/$(TYPE_SUFFIX)/*.c))

ASMFILES := $(patsubst $(ELFLOADER_SOURCE_ROOT)/%,%,$(wildcard $(ELFLOADER_SOURCE_ROOT)/src/plat/*.S))
ASMFILES += $(patsubst $(ELFLOADER_SOURCE_ROOT)/%,%,$(wildcard $(ELFLOADER_SOURCE_ROOT)/src/arch-arm/*.S))
ASMFILES += $(patsubst $(ELFLOADER_SOURCE_ROOT)/%,%,$(wildcard $(ELFLOADER_SOURCE_ROOT)/src/arch-arm/$(TYPE_SUFFIX)/*.S))

ELFLOADER_DIRECTORY := $(ELFLOADER_SOURCE_ROOT)/src
ELFLOADER_DIRECTORY += $(ELFLOADER_SOURCE_ROOT)/src/arch-arm
ELFLOADER_DIRECTORY += $(ELFLOADER_SOURCE_ROOT)/src/arch-arm/$(TYPE_SUFFIX)
ELFLOADER_DIRECTORY += $(ELFLOADER_SOURCE_ROOT)/src/plat

NK_CFLAGS += -D_XOPEN_SOURCE=700

# We will reuse some of the general functionalities in kernel
INCLUDE_DIRS := $(TOPDIR)/kernel/elfloader/include/arch-arm/
INCLUDE_DIRS += $(TOPDIR)/kernel/elfloader/include/arch-arm/$(TYPE_SUFFIX)/
INCLUDE_DIRS += $(TOPDIR)/kernel/elfloader/include/
INCLUDE_DIRS += $(TOPDIR)/kernel/libuart/
INCLUDE_DIRS += $(TOPDIR)/kernel/elfloader/include/plat/
INCLUDE_DIRS += $(PREBUILD_HEADER)/zlib
INCLUDE_DIRS += $(HDR_L_DIR)/
INCLUDE_DIRS += $(PREBUILD_HEADER)/
INCLUDE_DIRS += $(PREBUILD_HEADER)/sys/
INCLUDE_DIRS += $(PREBUILD_HEADER)/sys/hmapi
INCLUDE_DIRS += $(PREBUILD_HEADER)/ddk/hmapi/
INCLUDE_DIRS += $(TOPDIR)/sys_libs/libelf/include/
INCLUDE_DIRS += $(TOPDIR)/sys_libs/libcpio/include
INCLUDE_DIRS += $(PREBUILD_HEADER)/kernel/include
INCLUDE_DIRS += ${PREBUILD_HEADER}/kernel/include/plat/uapi
INCLUDE_DIRS += ${PREBUILD_HEADER}/kernel/include/plat
INCLUDE_DIRS += ${PREBUILD_HEADER}/kernel/include/arch/arm/arch/$(TYPE_SUFFIX)
INCLUDE_DIRS += ${PREBUILD_HEADER}/kernel/include/arch/arm
INCLUDE_DIRS += ${PREBUILD_HEADER}/kernel/include/plat/plat/$(TYPE_SUFFIX)
INCLUDE_DIRS += ${PREBUILD_HEADER}/kernel/include/lib
INCLUDE_DIRS += ${PREBUILD_HEADER}/kernel/include/stdlib
INCLUDE_DIRS += ${PREBUILD_HEADER}/kernel/include/uapi
INCLUDE_DIRS += ${PREBUILD_HEADER}/kernel/include/machine
INCLUDE_DIRS += $(PREBUILD_HEADER)/kernel/klibc
INCLUDE_DIRS += $(PREBUILD_LIBC_INC)/
INCLUDE_DIRS += $(PREBUILD_LIBC_INC)/arch/$(ARCH)
INCLUDE_DIRS += $(PREBUILD_LIBC_INC)/arch/generic
INCLUDE_DIRS += $(TOPDIR)/platform/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/plat_cfg

INCLUDE_DIRS += $(TOPDIR)/../../../../hisi/ap/platform

ifeq ($(CONFIG_BOOT_ARGS_TRANSFER), true)
CFLAGS  += -DBOOT_ARGS_TRANSFER
ASFLAGS += -DBOOT_ARGS_TRANSFER
endif

ifeq ($(CONFIG_NO_PLATCFG_EMBEDDED), true)
CFLAGS  += -DNO_PLATCFG_EMBEDDED
ASFLAGS += -DNO_PLATCFG_EMBEDDED
CFLAGS  += -DBOOT_ARGS_TRANSFER
ASFLAGS += -DBOOT_ARGS_TRANSFER
endif

ifeq ($(__EFI__),y)
ASMFILES += $(patsubst $(SOURCE_DIR)/%,%,$(SOURCE_DIR)/src/binaries/efi/efi_head.S)
ENTRY_POINT := efi_stub_entry
endif

ifeq ($(__ARM_64__), y)
LIBS = cpio zlib_64
endif

ifeq ($(__ARM_32__), y)
LIBS = cpio_a32 zlib_a32
endif

# Not transfer commit msg since it will make binary different regardless of whether source is changed
NK_CFLAGS += -ffreestanding -Wall -Wextra -Werror -W -D__IN_KERNEL__
NK_CFLAGS += -fpie

NOCFI=y
include $(PREBUILD_HEADER)/.config

OBJFILES := $(sort $(ASMFILES:%.S=%.o))
OBJFILES += $(sort $(CFILES:%.c=%.o))
OBJFILES += $(sort $(CXXFILES:%.cxx=%.o))
OBJFILES += $(sort $(OFILES))
OBJFILES += $(sort $(RUST_TARGET))
OBJFILES += $(sort $(asmFILES:%.s=%.o))

OBJFILES := $(addprefix $(ELFLOADER_OUTDIR)/,$(OBJFILES))
CFILES   := $(addprefix $(ELFLOADER_SOURCE_ROOT)/,$(CFILES))
ASMFILES := $(addprefix $(ELFLOADER_SOURCE_ROOT)/,$(ASMFILES))

$(warning "OBJFILES is $(OBJFILES)")
# this is used just for use default link script
TARGET_CUSTOM_LINK_SCRIPT = y


include $(TOPDIR)/mk/teeos-flags.mk

TARGET_NO_LIBLOG = y
NO_KASAN=y
LDFLAGS += -static -z relro -z now
LDFLAGS := $(filter-out --gc-sections,$(LDFLAGS))
CFLAGS  += $(filter-out -march=armv8-a,$(flags)) $(C_FLAGS) ${DEFS:%=-D%} -fPIC -fstack-protector-strong
ASFLAGS += $(asflags) $(AS_FLAGS) ${DEFS:%=-D%}
ASFLAGS += -march=${ARMV}
CFLAGS += -Wall -Wextra -Werror -fPIC
CFLAGS := $(filter-out -ffunction-sections -fdata-sections, $(CFLAGS))

ifeq ($(CONFIG_DEBUG_BUILD), y)
CFLAGS += -g
ASFLAGS += -g
endif

# CFLAGS  := $(filter-out -munaligned-access, $(CFLAGS))
$(warning "elfloader CFILES is $(CFILES)")
$(warning "elfloader ASMFILES is $(ASMFILES)")
$(warning "elfloader CFLAGS is $(CFLAGS)")
$(warning "elfloader CPPFLAGS is $(CPPFLAGS)")
$(warning "elfloader ASFLAGS is $(ASFLAGS)")

is_filter_module = $(strip $(foreach module,$(FILTER_MODULE),$(findstring $(module),$1)))

uniq = $(if $1,$(firstword $1) $(call uniq,$(filter-out $(firstword $1),$1)))

GENERAL_OPTIONS := -Wdate-time -Wfloat-equal -Wshadow -Wformat=2 -fsigned-char -fno-strict-aliasing \
	-pipe -fno-common -Wextra \

INCLUDES = $(INCLUDE_DIRS:%=-I%)
$(warning "elfloader INCLUDE_DIRS is $(INCLUDE_DIRS)")
$(warning "elfloader INCLUDES is $(INCLUDES)")

define make-depend
	@echo "compile elfloader C make-depend make-depend"
	$(warning "make-depend CFLAGS is $(CFLAGS)")
	$(warning "make-depend CPPFLAGS is $(CPPFLAGS)")
	$(warning "object1 is $1, object1 is $2, object1 is $3")
	${CC} -x assembler-with-cpp -MM -MF $3 -MP -MT $2 $(CFLAGS) $(CPPFLAGS) $(INCLUDES) $1
endef

$(ELFLOADER_OUTDIR)/%.o : %.c
	@echo "compile elfloader C files"
	@echo " [CC] $*.o"
	@echo "[CC] CPPFLAGS is $(CPPFLAGS)"
	@echo "[CC] CFLAGS is $(CFLAGS)"
	$(Q)mkdir -p $(dir $@)
	$(Q)$(call make-depend,$<,$@,$(patsubst %.o,%.d,$@))
	@echo "compile elfloader C files make-depend end"
	$(Q)$(CC) $(call uniq,$(CFLAGS) $(CPPFLAGS) $(INCLUDES) $(if $(call is_filter_module,$@),,$(GENERAL_OPTIONS))) -c $< -o $@

$(ELFLOADER_OUTDIR)/%.o : %.S
	@echo "compile elfloader ASM SS files"
	@echo " [ASM1] $*.o"
	@echo "ASM1 CPPFLAGS is $(CPPFLAGS)"
	@echo "ASM1 ASFLAGS is $(ASFLAGS)"
	$(Q)mkdir -p $(dir $@)
	@echo "compile elfloader asm files make-depend end"
	$(Q)$(call make-depend,$<,$@,$(patsubst %.o,%.d,$@))
	$(Q)$(CC) $(ASFLAGS) $(CPPFLAGS) $(INCLUDES) -D__ASM__ -c $< -o $@

#
# We produce a partially linked object file here which, to be used, will be
# eventually relinked with the compiled kernel and user images forming
# a bootable ELF file.
#
HM_LIBDIR := $(OUTPUTDIR)/aarch64/libs $(PREBUILD_ARCH_PLAT_LIBS)
LDFLAGS += $(HM_LIBDIR:%=-L%) $(LIBS:%=-l%)
$(ELFLOADER_OUTDIR)/elfloader.o: $(OBJFILES)
	@echo " [LINK] $(@F)"
	@echo "#### link elfloader Q is ${Q}, LD is $(LD), LDFLAGS is $(LDFLAGS),  @ is $@"
	@echo "#### link elfloader OBJFILES is $(OBJFILES) else is $^"
	@echo "#### link elfloader ASMFILES is $(ASMFILES) CFILES is $(CFILES)"
	@echo "#### link elfloader ELFLOADER_SOURCE_ROOT is $(ELFLOADER_SOURCE_ROOT)"
	${Q}$(LD) -r $^ $(filter-out -pie,$(LDFLAGS)) -o $@

all: $(ELFLOADER_OUTDIR)/elfloader.o

.PHONY: all

default: all

