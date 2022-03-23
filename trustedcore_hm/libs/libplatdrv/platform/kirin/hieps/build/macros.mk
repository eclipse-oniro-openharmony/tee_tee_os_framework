#########################################################
# common function define
#########################################################
# Find the local dir of the make file
define last-mk-dir
$(patsubst %/,%,$(dir $(lastword $(MAKEFILE_LIST))))
endef

# abs dir
define abs-dir
$(shell cd $(1) 2>/dev/null && pwd)
endef

# Compile c or asm file to object
define build-files-to-o
mkdir -p $(dir $@)
echo "CC    "$<
$(CC) -c $(1) -MD -MF $(basename $@).d  $< -o $@
$(NOECHO) cp $(basename $@).d $(basename $@).P
sed -e 's/#.*//' -e 's/^[^:]*: *//' -e 's/ *\\$$//' \
    -e '/^$$/ d' -e 's/$$/ :/' < $(basename $@).d >> $(basename $@).P
rm -rf $(basename $@).d
endef

define options-format
$(strip $(filter-out -D, $(if $(PROJECT_ROOT_DIR), $(subst =./,=$(PROJECT_ROOT_DIR)/,$(subst -I./,-I$(PROJECT_ROOT_DIR)/, $(1))), $(1))))
endef

define includes-cat
$(strip $(1) $(filter-out $(filter $(2), $(1)), $(2)))
endef

# get product directory name
define get-product-name
$(word 1, $(subst _, ,$(shell echo $(SEC_PRODUCT) | tr A-Z a-z)))
endef

# get product directory
define get-product-dir
$(strip $(if $(call abs-dir, $(1)/$(SEC_PRODUCT)), $(1)/$(SEC_PRODUCT), $(1)/$(call get-product-name)))
endef

# get chip directory
define get-chip-dir
$(strip $(if $(call abs-dir, $(1)/$(SEC_CHIP_DIR)), $(1)/$(SEC_CHIP_DIR), $(1)/$(word 1, $(subst _, ,$(shell echo $(SEC_CHIP_DIR) | tr A-Z a-z)))))
endef

#########################################################
# module function define
#########################################################
# module clean
define module-clean
MODULE_DIR :=
MODULE_OUT_DIR :=
MODULE_INCLUDES :=
MODULE_CFLAGS :=
MODULE_COBJS-y :=
MODULE_SFLAGS :=
MODULE_SOBJS-y :=
MODULE_LIB-y :=
endef

# module dir
define module-dir
$(patsubst %/,%,$(dir $(lastword $(filter %/$(SEC_BUILD_ID).mk %/$(SEC_BUILD_ID)_dft.mk,$(MAKEFILE_LIST)))))
endef

define module-get-dir
$(if $(MODULE_DIR),$(MODULE_DIR),$(call module-dir))
endef

define module-chip-dir
$(call get-chip-dir, $(call module-get-dir))
endef

define module-chip-dir-name
$(patsubst $(call module-get-dir)/%,%,$(call get-chip-dir, $(call module-get-dir)))
endef

define module-get-def-inc
$(strip $(if $(filter $(SEC_ROOT_DIR)/libseceng/driver/%,$(call module-get-dir)), \
    -I$(call module-chip-dir) -I$(call module-get-dir) -I$(call module-get-dir)/include, \
    -I$(call module-get-dir)))
endef

# module output dir of objects
define module-output-dir
$(strip $(addprefix $(SEC_OUT_DIR)/, $(patsubst $(SEC_ROOT_DIR)/%,%, $(MODULE_DIR))))
endef

# module c code files
define module-dir-cfiles
$(patsubst %.c,%.o,$(patsubst $(call module-get-dir)/%,%,$(shell find $(1) -type f -iname "*.c" -follow)))
endef

# module chip files
define module-chip-dir-cfiles
$(filter-out %_dft.o,$(call module-dir-cfiles, $(call module-chip-dir)))
endef

# module dft files
define module-dft-cfiles
$(filter %_dft.o,$(call module-dir-cfiles, $(call module-get-dir)))
endef

# module make
define module-make
include $(SEC_ROOT_DIR)/build/module.mk
endef
