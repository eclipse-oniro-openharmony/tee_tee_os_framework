# Utils top level Makefile

TARGETS = secure_boot_utils oem_asset_utils secure_debug_utils x509_cert_utils

UTILS_ROOT = $(shell pwd)/..

all:

clean_%:
	@echo "cleaning" $*	
	@make -C $* clean

distclean: clean clrconfig
	rm -rf $(UTILS_ROOT)/bin
	rm -rf $(UTILS_ROOT)/lib
	rm -rf $(UTILS_ROOT)/include
	rm -rf $(UTILS_ROOT)/doc

# Generate dependency on existence only (i.e., don't care if newer). 
# To be used primarily for directories creation
DEPENDENCY_ON_EXISTENCE_OF = $(filter-out $(wildcard $(1)), $(1))


################################################
### Handle project configuration definitions ###
################################################

PROJ_CFG_FNAME = proj.cfg
PROJ_CFG_PATH = $(PROJ_CFG_FNAME)
PROJ_CONFIGS_DIR = configs

############ Special rules for project configuration selection ##############
ifneq ($(wildcard $(PROJ_CFG_PATH)),$(PROJ_CFG_PATH)) # No proj.cfg linked

all: # default in case there is no proj.cfg and setconfig_ was not used
	$(info Invoke 'make setconfig_<config. name>' to select project configuration )
	$(error 'proj.cfg' not found)

setconfig_%: $(PROJ_CONFIGS_DIR)/proj-%.cfg
	@$(info [CFG] $(PROJ_CONFIGS_DIR)/proj-$*.cfg --> proj.cfg)
	@ln -s $(PROJ_CONFIGS_DIR)/proj-$*.cfg $(PROJ_CFG_FNAME)

$(PROJ_CONFIGS_DIR)/proj-%.cfg:
	@$(error Unknown project configuration. $@ does not exist.)

clrconfig:
	$(info [CFG-CLN] No active configuration )

.PHONY: all setconfig_% clrconfig

else 
### proj.cfg exists. Include it to get project cofiguration defintions ###

include $(PROJ_CFG_PATH)
$(info PROJ_NAME=$(PROJ_NAME)  PROJ_REV=$(PROJ_REV))
# Export all definition from proj.cfg to dispatched makefiles 

all: $(PROJ_TARGETS)

$(PROJ_TARGETS):
	@make $(CFLAGS) -C $@

clean: $(foreach target,$(PROJ_TARGETS),clean_$(target))


# setconfig_/clrconfig are available only if $(PROJ_CONFIGS_DIR) exists
# (i.e., eliminated on release trees)
ifeq ($(wildcard $(PROJ_CONFIGS_DIR)),$(PROJ_CONFIGS_DIR))
# Configuration rules
setconfig_%:
	$(if $(filter $(PROJ_CONFIGS_DIR)/proj-$*.cfg,$(shell readlink $(PROJ_CFG_PATH))),$(info $* configuration is already set.),$(error Before changing configuration invoke 'make clrconfig'))

clrconfig:
	@echo [CFG-CLN] X $(shell readlink $(PROJ_CFG_PATH))
	@rm -f $(PROJ_CFG_PATH)
endif

endif

# Provide lsconfig to list available configurations
configs_list = $(foreach cfg_file,$(wildcard $(PROJ_CONFIGS_DIR)/proj-*.cfg),$(patsubst $(PROJ_CONFIGS_DIR)/proj-%.cfg,%,$(cfg_file)))
lsconfig:
	@$(info Available project configurations:)
	@$(foreach cfg_file,$(configs_list),$(info $(cfg_file)))

.PHONY: all setconfig_% clrconfig lsconfig clean distclean all clean_% $(TARGETS)
