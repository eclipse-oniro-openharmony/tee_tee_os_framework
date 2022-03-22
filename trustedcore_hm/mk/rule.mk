## This function will generate $(1)_objs variables which provided
## the objects needed to compile to the $(1) module.
##
## Args:
##    $(1) : the module name

define eval_objs
ifneq ($(NO_OBJFILE_SORT),y)
$(1)_c_obj_files   = $$(sort $$(patsubst %.c,%.o,$$($(1)_c_files)))
$(1)_cpp_obj_files = $$(sort $$(patsubst %.cpp,%.o,$$($(1)_cpp_files)))
$(1)_asm_obj_files = $$(sort $$(patsubst %.s,%.o,$$($(1)_asm_files)))
$(1)_ASM_obj_files = $$(sort $$(patsubst %.S,%.o,$$($(1)_ASM_files)))
else
$(1)_c_obj_files   = $$(patsubst %.c,%.o,$$($(1)_c_files))
$(1)_cpp_obj_files = $$(patsubst %.cpp,%.o,$$($(1)_cpp_files))
$(1)_asm_obj_files = $$(patsubst %.s,%.o,$$($(1)_asm_files))
$(1)_ASM_obj_files = $$(patsubst %.S,%.o,$$($(1)_ASM_files))
endif

$(1)_objs  = $$(addprefix $(BUILD_DIR)/,$$($(1)_c_obj_files))
$(1)_objs += $$(addprefix $(BUILD_DIR)/,$$($(1)_cpp_obj_files))
$(1)_objs += $$(addprefix $(BUILD_DIR)/,$$($(1)_asm_obj_files))
$(1)_objs += $$(addprefix $(BUILD_DIR)/,$$($(1)_ASM_obj_files))
endef

define eval_dep_libs
$(1)_dep_libs := $$(patsubst lib%_shared.a,lib%_shared.so,$(3))
$(1)_dep_libs := $$(patsubst lib%_shared_a32.a,lib%_shared_a32.so,$$($(1)_dep_libs))
$(1)_dep_libs := $$(addprefix $(2)/,$$($(1)_dep_libs))
endef

## provide the static linked target compile rules.
## Args:
##  $(1)  : the $(MODULE_FOLDER) needed to be compile.
##  $(2)  : the $(MODULE_FILE) needed to be generated.
define eval_libs
$(2): $$($(1)_objs)
	@echo "[ AR2 ] $$@ $$^"
	$$(VER)$$(AR) rD $$@ $$^
endef

## provide the app target compile rules.
## Args:
##  $(1)  : the $(MODULE_FOLDER) needed to be compile.
##  $(2)  : the $(MODULE_FILE) needed to be generated.
ifeq ($(xom32_enable),y)
define eval_apps
$(2): $$($(1)_objs) $$($(1)_dep_libs)
	@echo "[ LD ] $$@"
	@test -d $$(dir $$@) || mkdir -p $$(dir $$@)
	$$(VER)$$(LD) $$($(1)_objs) $$($(1)_extracted_objs) $$(TA_LDFLAGS) --build-id=none \
	$(if $(findstring se_service, $(2)) if $(findstring permission_service, $(2)),, -rdynamic) \
	$$($(1)_LDFLAGS) -o $$@
	$$(XOM) $$@
	$$(OBJCOPY) $$@ --remove-section ".xomloc"
endef

## provide the driver target compile rules.
## Args:
##  $(1)  : the $(MODULE_FOLDER) needed to be compile.
##  $(2)  : the $(MODULE_FILE) needed to be generated.
define eval_drivers
$(2): $$($(1)_objs) $$($(1)_dep_libs)
	@echo "[ LD ] $$@"
	@test -d $$(dir $$@) || mkdir -p $$(dir $$@)
	$$(VER)$$(LD) $$($(1)_objs) $$($(1)_extracted_objs) $$(DRV_LDFLAGS) --build-id=none \
	$(if $(findstring tarunner_a32, $(2)) if $(findstring gtask_a32, $(2)),, -rdynamic) \
	$$($(1)_LDFLAGS) -o $$@
	$$(XOM) $$@
	$$(OBJCOPY) $$@ --remove-section ".xomloc"
endef
else
define eval_apps
$(2): $$($(1)_objs) $$($(1)_dep_libs)
	@echo "[ LD ] $$@"
	@test -d $$(dir $$@) || mkdir -p $$(dir $$@)
	$$(VER)$$(LD) $$($(1)_objs) $$($(1)_extracted_objs) $$(TA_LDFLAGS) --build-id=none \
	$(if $(findstring se_service, $(2)) if $(findstring permission_service, $(2)),, -rdynamic) \
	$$($(1)_LDFLAGS) -o $$@
endef
define eval_drivers
$(2): $$($(1)_objs) $$($(1)_dep_libs)
	@echo "[ LD ] $$@"
	@test -d $$(dir $$@) || mkdir -p $$(dir $$@)
	$$(VER)$$(LD) $$($(1)_objs) $$($(1)_extracted_objs) $$(DRV_LDFLAGS) --build-id=none \
	$(if $(findstring tarunner_a32, $(2)) if $(findstring gtask_a32, $(2)),, -rdynamic) \
	$$($(1)_LDFLAGS) -o $$@
endef
endif

## This function will generate $(1)_extracted_objs variables which are
## extracted from the $(2) archive file and provided the objects needed to
## compile to the $(1) module.
##  $(1)  : $(MODULE_FOLDER) needed to be compile.
##  $(2)  : $(PREBUILD_ARCHIVE) needed to be extracted.
##  $(3)  : the $(BUILD_DIR) where target generates.
define eval_extracted_objs
$(1)_extracted_objs += $$(addprefix $(3)/,$$(shell $$(AR) -t $(2)))
endef

## provide an extra archive dependence for the app/driver target
## and the extraction rule
##  $(1)  : the $(BUILD_DIR) where target generates.
##  $(2)  : the $(MODULE_FILE) needed to be generated.
##  $(3)  : the $(PREBUILD_ARCHIVE) needed to be extracted.
define eval_extract_ar
$(1)/.extracted: $(3)
	@echo "extracting $(3)"
	@test -d $$(dir $$@) || mkdir -p $$(dir $$@)
	$$(VER)cd $(1) && $$(AR) -x $(3)
	@touch $$@
$(2): $(1)/.extracted
endef

CHOOSE_OPTIONS:=tee_ecies_ext.c
CHOOSE_OPTIONS += ta_magic.c
ROOT_PATH:=$(abspath $(lastword $(MAKEFILE_LIST))../../../)

#CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/platform/kirin/phone/common/platdrv/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/drivers/platdrv/src/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/drivers/platdrv/platform/kirin/hdcp_wfd/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/drivers/platdrv/platform/kirin/secmem/driver/lib/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/drivers/platdrv/platform/kirin/secmem/driver/sion/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/tee_sharedmem/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/drivers/platdrv/platform/kirin/hdcp_wfd/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/tee_sharedmem/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/common/crypto/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/ccdriver_lib/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/libthirdparty_drv/include/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/framework/gtask/src/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/common/tui_drv/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/common/include/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/common/crypto/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/seccfg/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/sys_apps/storage/src/task_storage/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/drivers/platdrv/src/drm/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/common/gatekeeper/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/sys_libs/libta_magic_a32/src/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/$(ROOT_PATH)/drivers/platdrv/src/drm/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/common/touchscreen/*.c)
#CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/common/touchscreen/panel/*.c)
#CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/fingerprint/src/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/antiroot/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/drivers/platdrv/platform/kirin/antiroot/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/isp/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/isp/kirin990/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/isp/revisions/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/isp/baltimore/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/vcodec/hi_vcodec/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/vcodec/hi_vcodec/venc_hivna/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/video_decrypt/*.c)
CHOOSE_OPTIONS += $(wildcard $(TOP)/vendor/hisi/ap/kernel/drivers/vcodec/hi_vcodec/vdec_hivna/vfmw/vfmw_v6.2/core/decode/*.c)
CHOOSE_OPTIONS += $(wildcard $(TOP)/vendor/hisi/ap/kernel/drivers/vcodec/hi_vcodec/vdec_hivna/vfmw/vfmw_v6.2/core/decode/hal/v5r7b5/*.c)
CHOOSE_OPTIONS += $(wildcard $(TOP)/vendor/hisi/ap/kernel/drivers/vcodec/hi_vcodec/vdec_hivna/vfmw/vfmw_v6.2/core/stream/*.c)
CHOOSE_OPTIONS += $(wildcard $(TOP)/vendor/hisi/ap/kernel/drivers/vcodec/hi_vcodec/vdec_hivna/vfmw/vfmw_v6.2/osal/tee/*.c)
CHOOSE_OPTIONS += $(wildcard $(TOP)/vendor/hisi/ap/kernel/drivers/vcodec/hi_vcodec/vdec_hivna/vfmw/vfmw_v6.2/core/stream/hal/v3r3/*.c)
CHOOSE_OPTIONS += $(wildcard $(TOP)/vendor/hisi/ap/kernel/drivers/vcodec/hi_vcodec/vdec_hivna/vfmw/vfmw_v6.2/product/HiVCodecV600/*.c)
CHOOSE_OPTIONS += $(wildcard $(TOP)/vendor/hisi/ap/kernel/drivers/vcodec/hi_vcodec/vdec_hivna/vfmw/vfmw_v6.2/intf/*.c)
CHOOSE_OPTIONS += $(wildcard $(TOP)/vendor/hisi/ap/kernel/drivers/vcodec/hi_vcodec/vdec_hivna/vfmw/vfmw_v6.2/intf/sec_smmu/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/vcodec/hi_vcodec/venc_hivna/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/vcodec/video_decrypt/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/hifi/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/ivp/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/gpio/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/mailbox/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/dma/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/spi/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/i2c/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/i3c/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/common/display2.0/hdcp_syscall.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/common/display2.0/*/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/secmem/driver/iommu/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/drivers/platdrv/platform/common/tzpc/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/drivers/platdrv/platform/kirin/file_encry_v3/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/drivers/platdrv/platform/kirin/secureboot/bspatch/*.cpp)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/drivers/platdrv/platform/kirin/secureboot/eiius_interface.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/drivers/platdrv/platform/kirin/secureboot/secboot.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/drivers/platdrv/platform/kirin/secureboot/sec_derive_cuid.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/drivers/platdrv/platform/kirin/secureboot/secureboot.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/drivers/platdrv/platform/kirin/secureboot/secureboot_v2.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/msp_engine/adapter/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/msp_engine/custom/*/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/msp_engine/driver/power/chip/*/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/msp_engine/driver/smmu/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/msp_engine/driver/timer/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/msp_engine/autotest/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/msp_engine/autotest/custom/cdrm/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/msp_engine/autotest/custom/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/msp_engine/common/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/msp_engine/host/osl/teeos/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/msp_engine/host/pal/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/eSE/hisee/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/eSE/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/mspc/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/mspc/apdu/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/privacy_protection/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/secmem/driver/sec/baltimore/sec_region.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/drivers/platdrv/platform/kirin/secmem/driver/sec/baltimore_ddr_autofsgt_proxy_secure_os.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/drivers/platdrv/platform/kirin/face_recognize/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/drivers/platdrv/platform/kirin/sensorhub/sensorhub_ipc.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/npu_v200/platform/hi36a0/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/npu_v200/platform/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/npu_v200/manager/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/npu_v200/device/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/drivers/platdrv/platform/kirin/npu_v200/platform/hi36a0/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/drivers/platdrv/platform/kirin/npu_v200/platform/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/drivers/platdrv/platform/kirin/npu_v200/manager/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/drivers/platdrv/platform/kirin/npu_v200/device/*.c)
CHOOSE_OPTIONS += $(wildcard $(ROOT_PATH)/libs/libplatdrv/platform/kirin/mesp_decrypt/*.c)

CHOOSE_OPTIONS_2 := ta_magic.c
CHOOSE_OPTIONS_2 += $(wildcard $(ROOT_PATH)/sys_libs/libta_magic_a32/src/*.c)

FILTER_MODULE := open_source libgmssl libboringssl openssl libpng libmbedtls austin
FILTER_MODULE += secisp kds bdkernel task_secboot sre_dev_relcb eSE touchscreen npu_v100 video_decrypt

GENERAL_OPTIONS := -Wdate-time -Wfloat-equal -Wshadow -Wformat=2 -fsigned-char -fno-strict-aliasing \
                   -pipe
WARNING_OPTIONS := -Wall -Wextra -Werror
BLOCKLIST += libplatdrv libbiometric libsec_flash_client libvltmm librot libmspcore softcrys secmem eSE
BLOCKLIST += libthp task_antiroot sec_flash task_ukey hieps codesafe austin/host adp hieps secureflash npu_v100
BLOCKLIST += secureboot fingerprint modem_secboot libfdt touchscreen msp_ta_channel npu_v100 secsvm vcodec pal/src tvp

# we need function uniq to deduplication
uniq = $(if $1,$(firstword $1) $(call uniq,$(filter-out $(firstword $1),$1)))

# we need function is_filter_module to remove open source files
is_filter_module = $(strip $(foreach module,$(FILTER_MODULE),$(findstring $(module),$1)))

# we need function checklist to add blocklist
check_list = $(strip $(foreach module,$(BLOCKLIST),$(findstring $(module),$1)))

last_component = $(shell echo $1 | awk -F '//' '{print $$NF}')
is_abs_path = $(filter $(shell echo $1 | head -c 1),/)

## compile object file rules:
ifneq ($(xom32_enable),y)
ifeq ($(CONFIG_GCOV),y)
$(BUILD_DIR)/%.o: %.cpp
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@echo "[ CXX ] $@"
	$(VER)$(CXX) -MMD -MP -MF $(BUILD_DIR)/$<.d $(flags) $(inc-flags) $(cxx-flags) -c -o $@ $(CURDIR)/$<

$(BUILD_DIR)/%.o: %.cxx
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@echo "[ CXX ] $@"
	$(VER)$(CXX) -MMD -MP -MF $(BUILD_DIR)/$<.d $(flags) $(inc-flags) $(cxx-flags) -c -o $@ $(CURDIR)/$<

$(BUILD_DIR)/%.o: %.c
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@echo "[ CC ] $@"
	$(VER)$(CC) -MMD -MP -MF $(BUILD_DIR)/$<.d $(flags) $(inc-flags) $(c-flags) -c -o $@ $(if $(call is_abs_path,$<),$<,$(CURDIR)/$<)
else
$(BUILD_DIR)/%.o: %.cpp
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@echo "[ CXX ] $@"
	$(VER)$(CXX) -MMD -MP -MF $(BUILD_DIR)/$<.d $(flags) $(inc-flags) $(cxx-flags) -c -o $@ $<

$(BUILD_DIR)/%.o: %.cxx
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@echo "[ CXX ] $@"
	$(VER)$(CXX) -MMD -MP -MF $(BUILD_DIR)/$<.d $(flags) $(inc-flags) $(cxx-flags) -c -o $@ $<

$(BUILD_DIR)/%.o: %.c
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@echo "[ CC ] $@ "
	$(VER)$(CC) -MMD -MP -MF $(BUILD_DIR)/$<.d $(if $(call is_filter_module,$(call last_component,$@)), \
	$(filter-out -Werror, $(flags) $(inc-flags) $(c-flags)),$(call uniq, \
	$(if $(if $(call check_list,$(call last_component,$@)),$(findstring $(notdir $<),$(notdir $(CHOOSE_OPTIONS_2))),"need options"),$(WARNING_OPTIONS),) \
	$(if $(findstring modem,$<)$(findstring secureboot,$<)$(findstring eSE,$<)$(findstring libdx,$@),, -fno-common) \
	$(flags) $(inc-flags) $(c-flags) $(GENERAL_OPTIONS))) -c -o $@ $<
endif

$(BUILD_DIR)/%.o: %.S
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@echo "[ ASM ] $@"
	$(VER)$(CC) -MMD -MP -MF $(BUILD_DIR)/$<.d $(flags) $(inc-flags) $(CXXFLAGS) -c -o $@ $<

$(BUILD_DIR)/%.o: %.s
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@echo "[ asm ] $@"
	$(VER)$(CC) -MMD -MP -MF $(BUILD_DIR)/$<.d $(flags) $(inc-flags) $(CXXFLAGS) -c -o $@ $<
else
ifeq ($(CONFIG_GCOV),y)
$(BUILD_DIR)/%.o: %.cpp
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@echo "[ CXX-XOM ] $@"
	$(VER)$(CXX-XOM) -MMD -MP -MF $(BUILD_DIR)/$<.d $(flags) $(inc-flags) $(cxx-flags) -c -o $@ $(CURDIR)/$<

$(BUILD_DIR)/%.o: %.cxx
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@echo "[ CXX-XOM ] $@"
	$(VER)$(CXX-XOM) -MMD -MP -MF $(BUILD_DIR)/$<.d $(flags) $(inc-flags) $(cxx-flags) -c -o $@ $(CURDIR)/$<

$(BUILD_DIR)/%.o: %.c
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@echo "[ CC-XOM ] $@"
	$(VER)$(CC-XOM) -MMD -MP -MF $(BUILD_DIR)/$<.d $(flags) $(inc-flags) $(c-flags) -c -o $@ $(if $(call is_abs_path,$<),$<,$(CURDIR)/$<)
else
$(BUILD_DIR)/%.o: %.cpp
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@echo "[ CXX-XOM ] $@"
	$(VER)$(CXX-XOM) -MMD -MP -MF $(BUILD_DIR)/$<.d $(flags) $(inc-flags) $(cxx-flags) -c -o $@ $<

$(BUILD_DIR)/%.o: %.cxx
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@echo "[ CXX-XOM ] $@"
	$(VER)$(CXX-XOM) -MMD -MP -MF $(BUILD_DIR)/$<.d $(flags) $(inc-flags) $(cxx-flags) -c -o $@ $<

$(BUILD_DIR)/%.o: %.c
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@echo "[ CC-XOM ] $@"
	$(VER)$(CC-XOM) -MMD -MP -MF $(BUILD_DIR)/$<.d $(if $(call is_filter_module,$(call last_component,$@)), \
	$(filter-out -Werror, $(flags) $(inc-flags) $(c-flags)),$(call uniq, \
	$(if $(if $(call check_list,$(call last_component,$@)),$(findstring $(notdir $<),$(notdir $(CHOOSE_OPTIONS))),"need options"),$(WARNING_OPTIONS),) \
	$(if $(findstring modem,$<)$(findstring secureboot,$<)$(findstring eSE,$<)$(findstring libdx,$@),,-fno-common) \
	$(flags) $(inc-flags) $(c-flags) $(GENERAL_OPTIONS))) -c -o $@ $<
endif

$(BUILD_DIR)/%.o: %.S
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@echo "[ ASM ] $@"
	$(VER)$(CC) -MMD -MP -MF $(BUILD_DIR)/$<.d $(flags) $(inc-flags) $(CXXFLAGS) -c -o $@ $<

$(BUILD_DIR)/%.o: %.s
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@echo "[ asm ] $@"
	$(VER)$(CC) -MMD -MP -MF $(BUILD_DIR)/$<.d $(flags) $(inc-flags) $(CXXFLAGS) -c -o $@ $<
endif

rwildcard=$(wildcard $1$2) $(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2))

DEPS := $(patsubst %.c,$(BUILD_DIR)/%.c.d,$(call rwildcard,./,*.c))
DEPS += $(patsubst %.cxx,%$(BUILD_DIR)/.cxx.d,$(call rwildcard,./,*.cxx))
DEPS += $(patsubst %.cpp,$(BUILD_DIR)/%.cpp.d,$(call rwildcard,./,*.cpp))
DEPS += $(patsubst %.S,$(BUILD_DIR)/%.S.d,$(call rwildcard,./,*.S))
DEPS += $(patsubst %.s,$(BUILD_DIR)/%.s.d,$(call rwildcard,./,*.s))

ifneq ($(MAKECMDGOALS),clean)
-include $(DEPS)
endif
