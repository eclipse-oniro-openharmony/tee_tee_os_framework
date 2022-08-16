#
# @TAG(HUAWEI)
#

.SUFFIXES:

include $(TOPDIR)/mk/var.mk
KERNEL_ROOT_PATH := $(CURDIR)

HM_ARCH_LIST:= aarch64 aarch32
ARCH_LIST:=arm x86
CPU_LIST:=cortex-a7 cortex-a8 cortex-a9 cortex-a15 cortex-a53 cortex-a57
ARMV_LIST:=armv8-a

HMBUILD_ROOT := $(KERNEL_OUTDIR)

ifeq ($(CONFIG_ARCH_AARCH32),y)
	DEFS += AARCH32
	DEFS += __KERNEL_32__
	export __ARM_32__ = y
	export KERNEL_32 = y
	export TEE_ARCH = arm
    ifeq ($(CONFIG_ARM_HYPERVISOR_SUPPORT),y)
        export HM_ARCH = arm_hyp
        export ARM_HYP = 1
        DEFS += ARM_HYP
    else
        export HM_ARCH = aarch32
    endif
	export TYPE_SUFFIX = 32
endif

ifeq ($(CONFIG_ARCH_AARCH64),y)
	DEFS += AARCH64
	DEFS += __KERNEL_64__
	export TEE_ARCH = aarch64
	export __ARM_64__ = y
	export KERNEL_64 = y
	export HM_ARCH = aarch64
	export TYPE_SUFFIX = 64
endif

ifeq ($(CONFIG_ARM_CORTEX_A15),y)
	DEFS += ARMV7_A
	DEFS += ARM_CORTEX_A15
	export ARMV=armv7ve
	export CPU=cortex-a15
endif

ifeq ($(CONFIG_ARM_CORTEX_A53),y)
	C_FLAGS += -mtune=cortex-a53
ifeq ($(CONFIG_ARCH_AARCH64),y)
	C_FLAGS  += -march=armv8-a+nofp
	AS_FLAGS += -march=armv8-a
	AS_FLAGS += -mcpu=cortex-a53
endif
	DEFS += ARMV8_A
	DEFS += ARM_CORTEX_A53
	export ARMV=armv8-a
	export CPU=cortex-a53
endif

_BIN_GIT = $(shell which git)
ifneq ($(_BIN_GIT),)
HM_BRANCH := $(word 2,$(shell cd $(TOPDIR)/../; cat .git/HEAD))
ifeq ($(HM_BRANCH),)
HM_BRANCH := $(word 1,$(shell cd $(TOPDIR)/../; cat .git/HEAD))
HMAPPS_COMMIT := $(shell echo $(HM_BRANCH) | head -c 7)
else
HM_COMMIT_ALL := $(shell cd $(TOPDIR)/../; cat .git/$(HM_BRANCH))
HMAPPS_COMMIT := $(shell echo $(HM_COMMIT_ALL) | head -c 7)
endif
else
HMAPPS_COMMIT :=
$(warning "no GIT")
endif

DEFS += HMAPPS_COMMIT_ID=\"$(HMAPPS_COMMIT)\"

CONFIG_DEFS += $(strip $(foreach v, \
  CONFIG_NUM_PRIORITIES CONFIG_MAX_NUM_BOOTINFO_DEVICE_REGIONS \
  CONFIG_TIMER_TICK_MS  CONFIG_TIME_SLICE \
  CONFIG_ROOT_CNODE_SIZE_BITS,  \
  $(if $(value ${v}), ${v}=$(value ${v}), )))

PATH := ${KERNEL_ROOT_PATH}/tools:${PATH}
export PATH

ifeq ($(HM_ARCH), aarch64)
	KERNEL_TARGET_ARCH := $(TARGET_ARCH_64)
endif

ifeq ($(HM_ARCH), aarch32)
	KERNEL_TARGET_ARCH := $(TARGET_ARCH_32)
endif

export KERNEL_TARGET_ARCH
$(warning kernel arch: $(KERNEL_TARGET_ARCH))

CFLAGS   += --target=$(KERNEL_TARGET_ARCH)
ASFLAGS  += --target=$(KERNEL_TARGET_ARCH)
CPPFLAGS += --target=$(KERNEL_TARGET_ARCH)

ifeq (${PYTHON},)
PYTHON = python
export PYTHONDONTWRITEBYTECODE = true
endif

ifndef SKIP_CHECKING_PATH
CPPPATH = $(shell PATH=${PATH} sh -c "which ${CPP}")
$(if ${CPPPATH},,$(error ${CPP} not in PATH or not executable))

LDPATH = $(shell PATH=${PATH} sh -c "which ${LD}")
$(if ${LDPATH},,$(error ${LD} not in PATH or not executable))

STRIPPATH = $(shell PATH=${PATH} sh -c "which ${STRIP}")
$(if ${STRIPPATH},,$(error ${STRIP} not in PATH or not executable))

PYTHONPATH = $(shell PATH=${PATH} sh -c "which ${PYTHON}")
$(if ${PYTHONPATH},,$(error ${PYTHON} not executable or not in PATH))

CCPATH = $(shell PATH=${PATH} sh -c "which ${CC}")
$(if ${CCPATH},,$(error ${CC} not in PATH or not executable))

endif # SKIP_CHECKING_PATH

# If a parent Makefile passed us DEFS, assume they will miss -D.
DEFS := ${DEFS:%=-D%}

DEFS += ${CONFIG_DEFS:%=-D%} -D__IN_KERNEL__

ifdef DEBUG   # DEBUG mode
CFLAGS  += -ggdb
DEFS += -DDEBUG
endif # DEBUG

ifeq ($(USE_FLAGS_A32),y)
CFLAGS += -march=armv8-a
ASFLAGS += -Wa,-march=armv8-a -mfpu=neon
endif

ifndef NK_CFLAGS
DEFS += -DHAVE_AUTOCONF

ifeq (${ARCH}, arm)  # ARCH==arm
CFLAGS += -mtune=${CPU} -march=${ARMV} -Wall -Wformat=2
ASFLAGS += -Wa,-mcpu=${CPU} -Wa,-march=${ARMV}
DEFS += -D$(shell echo ${ARMV}|tr [:lower:] [:upper:]|tr - _)
DEFS += -DARCH_ARM

ifeq (${HM_ARCH}, aarch64)
DEFS += -D__KERNEL_64__ -DAARCH64
TYPE_SUFFIX:=64
export __ARM_64__ = y
endif # HM_ARCH==aarch64

endif # ARCH==arm

else
$(if ${HAVE_AUTOCONF},,$(error autoconf.h not provided))
STATICHEADFILES += $(PREBUILD_HEADER)/autoconf.h
endif # NK_CFLAGS

INCLUDES := "-I$(KERNEL_ROOT_PATH)/src/kernel"
INCLUDES += "-I$(KERNEL_ROOT_PATH)/libgic"
INCLUDES += "-I$(KERNEL_ROOT_PATH)/libuart"
INCLUDES += "-I$(KERNEL_ROOT_PATH)/libuart/pl011"
INCLUDES += "-I$(KERNEL_ROOT_PATH)/libuart/pl011_general"
INCLUDES += "-I$(KERNEL_ROOT_PATH)/libuart/pl011_v500"
INCLUDES += "-I$(KERNEL_ROOT_PATH)/libuart/uart_lpc"
INCLUDES += "-I$(KERNEL_ROOT_PATH)/libversion"
INCLUDES += "-I$(KERNEL_ROOT_PATH)/elfloader/include"
INCLUDES += "-I$(KERNEL_ROOT_PATH)/../platform/common/include"

ifeq (${HM_ARCH}, ia32)
INCLUDES += "-I${PREBUILD_HEADER}/arch/$(ARCH)/arch/32"
INCLUDES += "-I${PREBUILD_HEADER}/plat/plat/32"
else
ifeq ($(HM_ARCH), x86_64)
INCLUDES += "-I${PREBUILD_HEADER}/arch/$(ARCH)/arch/64"
INCLUDES += "-I${PREBUILD_HEADER}/plat/plat/64"
endif # HM_ARCH==x86_64
endif # HM_ARCH==ia32

ifeq ($(HM_ARCH), aarch32)
INCLUDES += "-I${PREBUILD_HEADER}/arch/$(ARCH)/arch/32"
INCLUDES += "-I${PREBUILD_HEADER}/plat/plat/32"
else
ifeq ($(HM_ARCH), aarch64)
INCLUDES += "-I${PREBUILD_HEADER}/arch/$(ARCH)/arch/64"
INCLUDES += "-I${PREBUILD_HEADER}/plat/plat/64"
endif # HM_ARCH==aarch64
endif # HM_ARCH==aarch32

INCLUDES += "-I${PREBUILD_HEADER}"
INCLUDES += "-I${PREBUILD_HEADER}/kernel/capability"
INCLUDES += "-I${PREBUILD_HEADER}/kernel/include"
INCLUDES += "-I${PREBUILD_HEADER}/kernel/include/uapi"
INCLUDES += "-I${PREBUILD_HEADER}/kernel/include/stdlib"
INCLUDES += "-I${PREBUILD_HEADER}/kernel/include/plat/uapi"
INCLUDES += "-I${PREBUILD_HEADER}/kernel/include/plat"
INCLUDES += "-I${PREBUILD_HEADER}/kernel/include/plat/plat/${TYPE_SUFFIX}"
INCLUDES += "-I${PREBUILD_HEADER}/kernel/include/arch/$(ARCH)"
INCLUDES += "-I${PREBUILD_HEADER}/kernel/include/arch/$(ARCH)/arch/${TYPE_SUFFIX}"

WARNINGS = all extra error strict-prototypes missing-prototypes \
	nested-externs missing-declarations undef

CFLAGS += --std=c11 -nostdinc -nostdlib -ffreestanding \
	${WARNINGS:%=-W%} ${INCLUDES} -fpie
CPPFLAGS += -march=armv8-a -nostdinc
LDFLAGS += -nostdlib -pie -z noexecstack -z relro -z now -z notext -z max-page-size=4096
LDFLAGS += --build-id=none
LDFLAGS += -L$(TEE_ARM_COMPILER_RT_DIR) -lclang_rt.builtins

ASFLAGS += ${INCLUDES} -march=armv8-a

ifeq ($(CONFIG_DEBUG_BUILD), y)
CFLAGS += -g
ASFLAGS += -g
CPPFLAGS += -g
else
LDFLAGS += -s
endif # strip debug info

ifeq ($(HM_ARCH), aarch32)
LDFLAGS+= -marmelf
endif # HM_ARCH==aarch32

ifeq ($(HM_ARCH), aarch64)
CFLAGS += -mgeneral-regs-only
LDFLAGS+= -maarch64elf
endif # HM_ARCH==aarch64

ifeq (${CONFIG_WHOLE_PROGRAM_OPTIMIZATIONS_KERNEL}, y)
    CFLAGS += -fwhole-program
endif #CONFIG_WHOLE_PROGRAM_OPTIMIZATIONS_KERNEL==y


ifeq (${CONFIG_OPTIMIZATION_O0},y)
CFLAGS += -O0    # gcc's default optimization level is O0
else
ifeq (${CONFIG_OPTIMIZATION_O1},y)
CFLAGS += -O1     # compiler will optimize the code and the size of executable file
else
ifeq (${CONFIG_OPTIMIZATION_O2},y)
CFLAGS += -O2    # compiler will optimize the size of program
else
ifeq (${CONFIG_OPTIMIZATION_O3},y)
CFLAGS += -O3        # the highest optimization level is O3. compiler will optimize program deeply
else
CFLAGS += -Oz       # when Oz is configured compiler will take some extra time to optimize the code speed
endif # CONFIG_OPTIMIZATION_O3
endif # CONFIG_OPTIMIZATION_O2
endif # CONFIG_OPTIMIZATION_O1
endif # CONFIG_OPTIMIZATION_O0

CFLAGS += ${DEFS}
CPPFLAGS += ${DEFS} ${INCLUDES}

PYTHONPATH := ${PYTHONPATH}:${KERNEL_SOURCE_ROOT}/tools
export PYTHONPATH

vpath %.c   ${KERNEL_SOURCE_ROOT}
vpath %.S   ${KERNEL_SOURCE_ROOT}
vpath %.h   ${KERNEL_SOURCE_ROOT}
vpath %.lds ${KERNEL_SOURCE_ROOT}

DIRECTORIES += src/model
DIRECTORIES += src/lib
DIRECTORIES += src/machine
DIRECTORIES += src/api
DIRECTORIES += src/arch/arm/machine
ifeq (${HM_ARCH}, aarch64)
	DIRECTORIES += src/arch/$(ARCH)/64
else
	DIRECTORIES += src/arch/$(ARCH)/32
endif
DIRECTORIES += src/arch/arm/kernel
DIRECTORIES += src/kernel
DIRECTORIES += src/capability
DIRECTORIES += src/plat/machine

DIRECTORIES += src plat arch arch/api

KERNEL_ASM_SOURCES += $(sort $(patsubst %, src/arch/$(ARCH)/%, ${ARCH_ASM_SOURCES}))
KERNEL_ASM_SOURCES += $(sort $(patsubst %, src/plat/%, ${PLAT_ASM_SOURCES}))

STATICHEADFILES := $(shell find ${KERNEL_ROOT_PATH}/include/ -type f -name "*.h" \
                 ! -regex ".*include/arch.*"  ! -regex ".*include/plat.*") \
                 $(shell find ${KERNEL_ROOT_PATH}/include/arch/${ARCH} -type f -name "*.h") \
                 $(shell find ${KERNEL_ROOT_PATH}/include/plat -type f -name "*.h")

libcap.a        := $(PREBUILD_KERNEL_LIBS)/$(TEE_ARCH)/libcap.a
libfutex.a      := $(PREBUILD_KERNEL_LIBS)/$(TEE_ARCH)/libfutex.a
libipc.a        := $(PREBUILD_KERNEL_LIBS)/$(TEE_ARCH)/libipc.a
libsched.a      := $(PREBUILD_KERNEL_LIBS)/$(TEE_ARCH)/libsched.a
libsmp.a        := $(PREBUILD_KERNEL_LIBS)/$(TEE_ARCH)/libsmp.a
libcmd.a        := $(PREBUILD_KERNEL_LIBS)/$(TEE_ARCH)/libcmd.a
libklibc.a         := $(PREBUILD_KERNEL_LIBS)/$(TEE_ARCH)/libklibc.a
libverified.a   := $(PREBUILD_KERNEL_LIBS)/$(TEE_ARCH)/libverified.a
libhardware.a   := $(PREBUILD_KERNEL_LIBS)/$(TEE_ARCH)/libhardware.a
libkernel.a     := $(PREBUILD_KERNEL_LIBS)/$(TEE_ARCH)/libkernel.a

ifeq (${HAVE_AUTOCONF}, 1)
	STATICHEADFILES += $(PREBUILD_HEADER)/autoconf.h
endif # HAVE_AUTOCONF==1

STATICSOURCES = $(foreach file, ${C_SOURCES_WITH_PARSE} ${KERNEL_ASM_SOURCES}, \
                          ${KERNEL_ROOT_PATH}/${file})

OBJECTS = $(addprefix ${HMBUILD_ROOT}/, ${KERNEL_ASM_SOURCES:.S=.o} modules.a)
KLIBS := libuart.a libgic.a libversion.a
MODULES := libkernel.a ${KLIBS} libklibc.a libcap.a libfutex.a libipc.a libsched.a \
	libsmp.a libverified.a libhardware.a libcmd.a

.PHONY: all default clean preprocess

default: all

${HMBUILD_ROOT}/modules.a : ${MODULES}
	@echo "kernel.elf set modules.a AR is ${AR}"
	@cp $(libcap.a) ${HMBUILD_ROOT}/
	@cp $(libfutex.a) ${HMBUILD_ROOT}/
	@cp $(libipc.a) ${HMBUILD_ROOT}/
	@cp $(libcmd.a) ${HMBUILD_ROOT}/
	@cp $(libsched.a) ${HMBUILD_ROOT}/
	@cp $(libsmp.a) ${HMBUILD_ROOT}/
	@cp $(libverified.a) ${HMBUILD_ROOT}/
	@cp $(libhardware.a) ${HMBUILD_ROOT}/
	@cp $(libkernel.a) ${HMBUILD_ROOT}/
	@cp $(libklibc.a) ${HMBUILD_ROOT}/
	@set -e; cd ${HMBUILD_ROOT}; \
		${AR} -M < $(CURDIR)/combine.ari;

ALL_MAKEFILES := $(shell find ${KERNEL_ROOT_PATH} -name "Makefile")

all: ${HMBUILD_ROOT}/kernel.elf

.PHONY: ${MODULES}

style: astyle pylint

LINKER_SCRIPT = linker.lds

${HMBUILD_ROOT}/linker.lds_pp: ${LINKER_SCRIPT}
	@${CPP} ${CPPFLAGS} -P -o $@ -x c $<

${HMBUILD_ROOT}/kernel.elf: ${OBJECTS} ${HMBUILD_ROOT}/linker.lds_pp
	@${LD} ${LDFLAGS} -T ${HMBUILD_ROOT}/linker.lds_pp -o $@ ${OBJECTS}

# We need to split libkernel into more specific libs
# for example libplat, libvspace, libarch

define eval_klib
$(1) : $${STATICHEADFILES} $${DIRECTORIES}
	@echo "###### arch is ${ARCH}"
	@echo "###### plat is ${PLAT}"
	@echo "###### TARGET_ARCH_64 is ${TARGET_ARCH_64}"
	@echo "cc toolchain is ${CC}"
	@echo "CPP toolchain is ${CPP}"
	@echo " [$(1)]: " $${KERNEL_ROOT_PATH}
	@echo " CC " $${CC}
	$$(MAKE) -f $${KERNEL_ROOT_PATH}/Makefile.$$(patsubst %.a,%,$(1)) \
		STAGE_DIR=$${HMBUILD_ROOT} SOURCE_DIR=$${KERNEL_ROOT_PATH} \
		BUILD_DIR=$${HMBUILD_ROOT} KERNEL_ROOT_PATH=$(KERNEL_ROOT_PATH) \
		CPPFLAGS='$(CPPFLAGS)' LDFLAGS='$(LDFLAGS)' CXXFLAGS='$(CXXFLAGS)' CFLAGS='$(CFLAGS)'
endef

GENERAL_OPTIONS := -Wall -Wdate-time -Werror -Wextra -Wfloat-equal -Wshadow \
                   -fno-common -fno-strict-aliasing -fsigned-char -pipe
LINK_OPTIONS := -Wl,--no-undefined -Wl,-Bsymbolic -rdynamic
$(foreach klib,${KLIBS},$(eval $(call eval_klib, ${klib})))

%.o: %.s_pp | ${DIRECTORIES}
	@${CC} $(call uniq,${ASFLAGS} ${GENERAL_OPTIONS} ${LINK_OPTIONS}) -Qunused-arguments -x assembler -c $< -o $@

PRUNES = $(foreach file, ${STATICSOURCES} ${STATICHEADFILES},  --prune ${file} )
uniq = $(if $1,$(firstword $1) $(call uniq,$(filter-out $(firstword $1),$1)))
${HMBUILD_ROOT}/%.s_pp: %.S ${STATICHEADFILES} | ${DIRECTORIES}
	@echo "s_pp ##### cc toolchain is ${CC}"
	@echo "s_pp ##### CPP toolchain is ${CPP}"
	@echo "s_pp ##### ASFLAGS is ${ASFLAGS}"
	@echo "s_pp ##### GENERAL_OPTIONS is ${GENERAL_OPTIONS}"
	@echo "s_pp ##### LINK_OPTIONS is ${LINK_OPTIONS}"
	@echo "s_pp ##### CPPFLAGS is ${CPPFLAGS}"
	@echo "s_pp ##### DEFS is ${DEFS}"
	@mkdir -p $(@D)
	@${CPP} $(call uniq,${CPPFLAGS} ${GENERAL_OPTIONS}) -E -CC -o $@ $<

${HMBUILD_ROOT}/%.c_pp: %.c ${STATICHEADFILES} | ${DIRECTORIES}
	@mkdir -p $(@D)
	@${CPP} ${CFLAGS} ${CPPFLAGS} -E -CC -o $@ $<

CLEANTARGETS = kernel.elf ${OBJECTS} autoconf.h \
  arch api plat \
  ${KERNEL_ASM_SOURCES:.S=.s_pp} linker.lds_pp

clean:
	rm -Rf ${CLEANTARGETS}

.PHONY: distclean
distclean: clean
	@rm -f tools/*.pyc

${DIRECTORIES}:
	@mkdir -p ${DIRECTORIES}
