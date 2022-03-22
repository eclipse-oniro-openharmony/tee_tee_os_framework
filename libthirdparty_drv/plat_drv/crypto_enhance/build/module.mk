ifeq ($(MODULE_DIR),)
	MODULE_DIR := $(call module-dir)
endif
ifeq ($(MODULE_OUT_DIR),)
	MODULE_OUT_DIR := $(call module-output-dir)
endif
MODULE_COBJS-y := $(strip $(MODULE_COBJS-y))
MODULE_SOBJS-y := $(strip $(MODULE_SOBJS-y))
MODULE_LIB-y := $(strip $(MODULE_LIB-y))

# compile preprocess
ifeq ($(MODULE_LIB-y),)
	c_objects :=
	s_objects :=
	m_library :=
else
	c_files := $(addprefix $(MODULE_DIR)/, $(patsubst %.o,%.c,$(MODULE_COBJS-y)))
	c_objects := $(addprefix $(MODULE_OUT_DIR)/, $(MODULE_COBJS-y))
	s_files := $(addprefix $(MODULE_DIR)/, $(patsubst %.o,%.s,$(MODULE_SOBJS-y)))
	s_objects := $(addprefix $(MODULE_OUT_DIR)/, $(MODULE_SOBJS-y))
	m_library := $(addprefix $(MODULE_OUT_DIR)/, $(MODULE_LIB-y))
endif
export PRIVATE_LOCAL_CFLAGS := $(MODULE_CFLAGS) $(MODULE_INCLUDES) $(SEC_GLOBAL_CFLAGS)
PRIVATE_LOCAL_SFLAGS := $(MODULE_SFLAGS) $(MODULE_INCLUDES) $(SEC_GLOBAL_SFLAGS)

# debug
ifeq ($(MAKE_DEBUG), 1)
	$(info )
	$(info **************************************)
	$(info MODULE_DIR = $(MODULE_DIR))
	$(info MODULE_OUT_DIR = $(MODULE_OUT_DIR))
	$(info MODULE_INCLUDES = $(MODULE_INCLUDES))
	$(info MODULE_CFLAGS = $(MODULE_CFLAGS))
	$(info MODULE_COBJS-y = $(MODULE_COBJS-y))
	$(info MODULE_SFLAGS = $(MODULE_SFLAGS))
	$(info MODULE_SOBJS-y = $(MODULE_SOBJS-y))
	$(info MODULE_LIB-y = $(MODULE_LIB-y))
	$(info c_objects = $(c_objects))
	$(info s_objects = $(s_objects))
	$(info m_library = $(m_library))
	$(info **************************************)
	$(info )
endif

# pclint
ifeq ($(PCLINT), true)
$(c_objects): private_lint_flags := $(shell eval $(PYFILTER) "'(\s?-[dD][^\s]*)|(\s?-[Ii]\s*[^\s]*)|(\s?-include [^\s]*)' '$(PRIVATE_LOCAL_CFLAGS)'")
$(c_objects): $(MODULE_OUT_DIR)/%.o:$(MODULE_DIR)/%.c
	$(NOECHO) echo "PC-lint : $<"
	$(NOECHO) mkdir -p $(dir $(SEC_LINT_OUT))
	-$(LINT_TOOL) $(LINT_CONF) $(private_lint_flags) $< >> $(SEC_LINT_OUT)

SEC_OBJECTS += $(c_objects)
c_objects :=
s_objects :=
m_library :=
endif

# collect objects for library
ifneq ($(c_objects)$(s_objects),)
	ifneq ($(m_library),)
		SEC_LIBS += $(MODULE_LIB-y)
		SEC_CFILES += $(c_files)
		SEC_CFLAGS := $(call includes-cat, $(SEC_CFLAGS), $(MODULE_CFLAGS))
		SEC_SFILES += $(s_files)
		SEC_SFLAGS := $(call includes-cat, $(SEC_SFLAGS), $(MODULE_SFLAGS))
		SEC_OBJECTS += $(c_objects) $(s_objects)
		SEC_INCS := $(call includes-cat, $(SEC_INCS), $(MODULE_INCLUDES))
	endif
endif

# compile c code
ifneq ($(c_objects),)
	sinclude $(c_objects:.o=.P)
$(c_objects): private_local_cflags := $(PRIVATE_LOCAL_CFLAGS)
$(c_objects): $(MODULE_OUT_DIR)/%.o:$(MODULE_DIR)/%.c
	$(call build-files-to-o, $(private_local_cflags))
endif

# compile asm code
ifneq ($(s_objects),)
	sinclude $(s_objects:.o=.P)
$(s_objects): private_local_sflags := $(PRIVATE_LOCAL_SFLAGS)
$(s_objects): $(MODULE_OUT_DIR)/%.o:$(MODULE_DIR)/%.s
	$(call build-files-to-o, $(private_local_sflags))
endif

# empty module vars
$(eval $(call module-clean))
