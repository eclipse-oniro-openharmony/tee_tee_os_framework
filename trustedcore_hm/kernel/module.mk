include $(TOPDIR)/mk/var.mk
include $(PREBUILD_HEADER)/.config
override BUILD_DIR := $(KERNEL_OUTDIR)

Q = @
ifeq ($V, 1)
	Q =
endif
ifeq ($V, 2)
	Q =
endif
ifeq ($V, 3)
	Q =
endif

HM_LIBDIR     ?= $(STAGE_DIR)/lib
HM_BINDIR     ?= $(STAGE_DIR)/bin
HM_HEADERS    ?= $(STAGE_DIR)/headers

INCLUDES = $(INCLUDE_PATH:%=-I%)

ifeq ($(USE_LIBC), y)
	CFLAGS := $(filter-out -march=armv8-a+nofp, $(CFLAGS)) -march=armv8-a
endif

CFLAGS := $(filter-out -march=armv8-a+nofp, $(CFLAGS)) -march=armv8-a
CPPFLAGS := $(filter-out -march=armv8-a+nofp, $(CPPFLAGS))

# Object files
OBJFILES := $(sort $(ASMFILES:%.S=%.o)) $(sort $(CFILES:%.c=%.o))
OBJFILES := $(addprefix $(BUILD_DIR)/,$(OBJFILES))

# keep object files to support incremental build
.SECONDARY : $(OBJFILES)

cp_file = @echo " [STAGE] $(notdir $2)"; cp -f $(1) $(2)

vpath %.h $(INCLUDE_PATH)

vpath %.c $(SOURCE_DIR)
vpath %.cxx $(SOURCE_DIR)
vpath %.S $(SOURCE_DIR)
vpath %.s $(SOURCE_DIR)

# Default is to build/install all targets
default: install-headers $(BUILD_DIR)/$(TARGETS)

$(HM_LIBDIR)/%.a: $(BUILD_DIR)/%.a
	$(Q)mkdir -p $(dir $@)
	$(call cp_file,$<,$@)

.PHONY: install-headers

INCLUDES += "-I$(PREBUILD_HEADER)"
HM_INCLUDEDIR := $(HM_HEADERS)/hm

install-headers:
	@if [ -n "$(HDRFILES)" ] ; then \
		mkdir -p $(HM_INCLUDEDIR) ; \
		for file in $(HDRFILES); do \
			cp -aL $$file $(HM_INCLUDEDIR) ; \
		done; \
	fi
	@if [ -n "$(RHDRFILES)" ] ; then \
		mkdir -p $(HM_INCLUDEDIR) ; \
		for hdrfile in $(RHDRFILES) ; do \
			source=`echo "$$hdrfile" | sed 's/^\(.*\)[ \t][^ \t]*$$/\1/'` ; \
			dest=$(HM_INCLUDEDIR)/`echo "$$hdrfile" | sed 's/^.*[ \t]\([^ \t]*\)$$/\1/'` ; \
			mkdir -p $$dest; \
			cp -a $$source $$dest ; \
		done ; \
	fi

uniq = $(if $1,$(firstword $1) $(call uniq,$(filter-out $(firstword $1),$1)))
GENERAL_OPTIONS := -Wdate-time -Wfloat-equal -Wshadow -Wformat=2 -fsigned-char -fno-strict-aliasing -pipe -fno-common \
                   -Wextra

$(BUILD_DIR)/%.o: %.c $(HFILES) | install-headers
	@echo " [CC] $*.o"
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CC) $(call uniq,$(CFLAGS) $(CPPFLAGS) $(INCLUDES) $(GENERAL_OPTIONS)) -c -o $@ $<

$(BUILD_DIR)/%.o: %.S $(HFILES) | install-headers
	@echo " [ASM] $*.o"
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CC) $(ASFLAGS) $(INCLUDES) -c $< -o $@

$(BUILD_DIR)/%.o: %.s $(HFILES) | install-headers
	@echo " [ASM] $*.o"
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CC) $(ASFLAGS) -c $< -o $@

$(BUILD_DIR)/%.a: $(OBJFILES)
	@echo " [AR] $*.a"
	$(Q)mkdir -p $(dir $@)
	$(Q)$(AR) rD $@ $(OBJFILES) > /dev/null 2>&1

$(TARGETS): $(LIBS:%=-l%)
