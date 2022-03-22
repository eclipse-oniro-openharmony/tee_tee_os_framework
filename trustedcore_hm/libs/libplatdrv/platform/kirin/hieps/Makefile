# Find the local dir of the make file
define last-mk-dir
$(patsubst %/,%,$(dir $(lastword $(MAKEFILE_LIST))))
endef

# abs dir
define abs-dir
$(shell cd $(1)&&pwd)
endef

SEC_ROOT_DIR := $(call abs-dir, $(call last-mk-dir))
include $(SEC_ROOT_DIR)/build/macros.mk
include $(SEC_ROOT_DIR)/build/config.mk

# SEC_PRODUCT   product name ::form env or adpter in build/config.mk
# SEC_CHIP_DIR  chip dir ::form env or adpter in build/config.mk
#               [note]: chip directory by $(call get-chip-dir, ROOT_PATH)

#########################################################
# build security engine library
#########################################################
ifneq ($(PCLINT), true)
SEC_INSTALL := $(SEC_OUT_LIB)
else
# pclint
LLT_TOOLS_PATH := $(call abs-dir, $(SEC_ROOT_DIR)/../../../../../../../../..)/hisi/bin/ap/tools
PYFILTER := $(LLT_TOOLS_PATH)/pc-lint/lint-diff/pyfilter.py
export LINT_PATH := $(LLT_TOOLS_PATH)/pc-lint
LINT_TOOL := wine $(LINT_PATH)/lint-nt.exe
LINT_CONF := $(LINT_PATH)/bsp32.lnt $(LINT_PATH)/config/ccac/size-options.lnt
SEC_INSTALL := lint
SEC_LINT_OUT := $(SEC_OUT_DIR)/$(SEC_PRODUCT).lint
endif
$(info SEC_PRODUCT = $(SEC_PRODUCT), SEC_CHIP_DIR = $(SEC_CHIP_DIR))
$(info SEC_TARGET = $(SEC_TARGET), SEC_INSTALL = $(SEC_INSTALL))

# initialize
SEC_LIBS :=
SEC_CFILES :=
SEC_SFILES :=
SEC_OBJECTS :=
SEC_INCS := $(call includes-cat, $(SEC_INCLUDES), $(SEC_INTERNAL_INCLUDE))

# get seceng makefiles
SEC_MAKE_FILES := $(shell find $(SEC_ROOT_DIR) -type f -iname "$(SEC_BUILD_ID).mk" -follow)

# get dft makefiles
ifeq ($(SEC_DFT_ENABLE),true)
SEC_MAKE_FILES += $(shell find $(SEC_ROOT_DIR) -type f -iname "$(SEC_BUILD_ID)_dft.mk" -follow)
endif

# load module makefile
$(eval $(call module-clean))
$(foreach mk, $(SEC_MAKE_FILES), $(info ----> $(mk))$(eval include $(mk))$(info <---- $(mk))$(info ))

# pclint
lint: pre_clean := $(shell rm -rf $(SEC_LINT_OUT))
lint: $(SEC_OBJECTS)
	echo do pclint finished

# build library
$(SEC_OUT_LIB): private_local_arflags := $(SEC_GLOBAL_ARFLAGS)
$(SEC_OUT_LIB): $(SEC_OBJECTS)
	$(info SEC_LIBS = $(SEC_LIBS))
	$(AR) $(private_local_arflags) $@ $^
	$(NOECHO) echo "gen success!"$@

$(SEC_TARGET): $(SEC_INSTALL)

