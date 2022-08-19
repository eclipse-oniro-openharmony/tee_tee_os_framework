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
$(2): $$($(1)_objs)
	@echo "[ LD ] $$@"
	@test -d $$(dir $$@) || mkdir -p $$(dir $$@)
	$$(VER)$$(LD) $$($(1)_objs) $$($(1)_extracted_objs) $$(TA_LDFLAGS) --build-id=none \
	$$($(1)_LDFLAGS) -o $$@
	$$(XOM) $$@
	$$(OBJCOPY) $$@ --remove-section ".xomloc"
endef

## provide the driver target compile rules.
## Args:
##  $(1)  : the $(MODULE_FOLDER) needed to be compile.
##  $(2)  : the $(MODULE_FILE) needed to be generated.
define eval_drivers
$(2): $$($(1)_objs)
	@echo "[ LD ] $$@"
	@test -d $$(dir $$@) || mkdir -p $$(dir $$@)
	$$(VER)$$(LD) $$($(1)_objs) $$($(1)_extracted_objs) $$(DRV_LDFLAGS) --build-id=none \
	$$($(1)_LDFLAGS) -o $$@
	$$(XOM) $$@
	$$(OBJCOPY) $$@ --remove-section ".xomloc"
endef
else
define eval_apps
$(2): $$($(1)_objs)
	@echo "[ LD ] $$@"
	@test -d $$(dir $$@) || mkdir -p $$(dir $$@)
	$$(VER)$$(LD) $$($(1)_objs) $$($(1)_extracted_objs) $$(TA_LDFLAGS) --build-id=none \
	$$($(1)_LDFLAGS) -o $$@
	$$(OBJCOPY) $$@
endef
define eval_drivers
$(2): $$($(1)_objs)
	@echo "[ LD ] $$@"
	@test -d $$(dir $$@) || mkdir -p $$(dir $$@)
	$$(VER)$$(LD) $$($(1)_objs) $$($(1)_extracted_objs) $$(DRV_LDFLAGS) --build-id=none \
	$$($(1)_LDFLAGS) -o $$@
	$$(OBJCOPY) $$@
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

GENERAL_OPTIONS := -Wdate-time -Wfloat-equal -Wshadow -Wformat=2 -fsigned-char -fno-strict-aliasing \
                   -pipe -Wall -Wextra -Werror -fno-common

FILTER_MODULE := open_source openssl bounds_checking_function

# we need function is_filter_module to remove open source files
is_filter_module = $(strip $(foreach module,$(FILTER_MODULE),$(findstring $(module),$1)))

last_component = $(shell echo $1 | awk -F '//' '{print $$NF}')

# we need function uniq to deduplication
uniq = $(if $1,$(firstword $1) $(call uniq,$(filter-out $(firstword $1),$1)))

is_abs_path = $(filter $(shell echo $1 | head -c 1),/)

## compile object file rules:
ifneq ($(xom32_enable),y)
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
	$(flags) $(inc-flags) $(c-flags) $(GENERAL_OPTIONS))) -c -o $@ $<

$(BUILD_DIR)/%.o: %.S
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@echo "[ ASM ] $@"
	$(VER)$(CC) -MMD -MP -MF $(BUILD_DIR)/$<.d $(flags) $(inc-flags) $(CXXFLAGS) -D__ASM__ -c -o $@ $<

$(BUILD_DIR)/%.o: %.s
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@echo "[ asm ] $@"
	$(VER)$(CC) -MMD -MP -MF $(BUILD_DIR)/$<.d $(flags) $(inc-flags) $(CXXFLAGS) -c -o $@ $<
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
	$(flags) $(inc-flags) $(c-flags) $(GENERAL_OPTIONS))) -c -o $@ $<

$(BUILD_DIR)/%.o: %.S
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@echo "[ ASM ] $@"
	$(VER)$(CC) -MMD -MP -MF $(BUILD_DIR)/$<.d $(flags) $(inc-flags) $(CXXFLAGS) -D__ASM__ -c -o $@ $<

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
