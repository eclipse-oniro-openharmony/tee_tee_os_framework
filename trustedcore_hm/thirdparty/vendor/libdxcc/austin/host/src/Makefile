# "Root" Makefile for Host domain
# This makefile invokes the relevant target specific makefile to build it (e.g., cclib)

HOST_PROJ_ROOT = $(shell pwd)/..
include $(HOST_PROJ_ROOT)/Makefile.defs

# List of known modules in host and shared domains
ifeq ($(PROJ_DIR), softcrys)
HOST_COMPONENTS = softcrys
HOST_COMPONENTS += tests
else
HOST_COMPONENTS = cc_driver/$(CC_TYPE)/$(OS) moc_ipsec/$(OS) cc_ll_test
HOST_COMPONENTS += cclib tests sblib sbromlib sbromx509lib cmpu_utils taentry_a32
APPS = cmpu sep_consoled
endif
HOST_COMPONENTS += $(foreach app,$(APPS),apps/$(app))
ifneq ($(CROSS_COMPILE),arm-dsm-)
SHARED_COMPONENTS += libtom
endif

ifeq ($(DX_CONFIG_HASH_XOR_SUPPORTED),1)
	CFLAGS += -DDX_CONFIG_HASH_XOR_SUPPORTED
endif
ifneq ($(PROJ_NAME),) # proj.cfg found

default: release 

$(info PROJ_NAME=$(PROJ_NAME)  PROJ_REV=$(PROJ_REV)  PROJ_TYPE=$(PROJ_TYPE))

release: $(foreach target,$(PROJ_TARGETS),release_$(target))

# Generic release rules recipes
$(foreach module,$(filter-out cc_driver/public/linux,$(HOST_COMPONENTS)),release_$(module)): release_%:
	@$(ECHO) [REL] $*
	@$(MAKE) -C $*

# Exception for cc_driver/public/linux : requires Makefile.setup
release_cc_driver/public/linux: release_%:
	@$(ECHO) [REL] $*
	@$(MAKE) -C $* -f Makefile.setup

# Similar recipes for shared components
$(foreach module,$(SHARED_COMPONENTS),release_$(module)): release_%:
	@$(ECHO) [REL] $*
	@$(MAKE) -C $(SHARED_SRCDIR)/$* -f Makefile.host


# Dependencies for known targets
release_cclib: $(if $(filter $(PROJ_TARGETS),cc_driver/$(CC_TYPE)/$(OS)),release_cc_driver/$(CC_TYPE)/$(OS))

# Tests dependencies (depends on PROJ_TARGETS)
ifneq ($(CROSS_COMPILE),arm-dsm-)
release_tests: release_libtom
endif

ifeq ($(PROJ_DIR), softcrys)
release_tests: $(filter $(addprefix release_,$(PROJ_TARGETS)),release_softcrys)
else
release_tests: $(filter $(addprefix release_,$(PROJ_TARGETS)),release_cclib)
release_tests: $(if $(filter crys_sym crys_asym dx_utils_tests,$(PROJ_TESTS)),release_cclib)
endif

# Target installation rules
# Default location of NFS root for target
TARGET_ROOT ?= ~/work/nfsroot
# Default location of work area on target
TARGET_WORK_DIR ?= $(PROJ_DIR)
target_install: $(if $(filter $(PROJ_TESTS),tee4sos),install_driver)
target_install: $(if $(filter $(PROJ_TARGETS),cc_driver/$(CC_TYPE)/$(OS)),install_driver) $(call DEPENDENCY_ON_EXISTENCE_OF,$(TARGET_ROOT)/$(TARGET_WORK_DIR)/dat)
	@$(if $(wildcard $(RELEASE_EXEDIR)/*),$(ECHO) [CP] $(foreach fl,$(wildcard $(RELEASE_EXEDIR)/*),$(notdir $(fl))) --\> $(TARGET_ROOT)/$(TARGET_WORK_DIR)/)
	@$(if $(wildcard $(RELEASE_EXEDIR)/*),$(CP) $(RELEASE_EXEDIR)/* $(TARGET_ROOT)/$(TARGET_WORK_DIR)/)
	@$(if $(wildcard $(RELEASE_LIBDIR)/*.so),$(ECHO) [CP] $(foreach fl,$(wildcard $(RELEASE_LIBDIR)/*.so),$(notdir $(fl))) --\> $(TARGET_ROOT)/$(TARGET_WORK_DIR)/)
	@$(if $(wildcard $(RELEASE_LIBDIR)/*.so),$(CP) $(RELEASE_LIBDIR)/*.so $(TARGET_ROOT)/$(TARGET_WORK_DIR)/)
	@$(if $(wildcard $(RELEASE_DATDIR)/*),$(ECHO) [CP] $(foreach fl,$(wildcard $(RELEASE_DATDIR)/*),$(notdir $(fl))) --\> $(TARGET_ROOT)/$(TARGET_WORK_DIR)/dat/)
	@$(if $(wildcard $(RELEASE_DATDIR)/*),$(CP) $(RELEASE_DATDIR)/* $(TARGET_ROOT)/$(TARGET_WORK_DIR)/dat/)

$(TARGET_ROOT)/$(TARGET_WORK_DIR)/dat:
	$(MKDIR) $@

# Driver release rules are special due to modules location
MODULES_DIRS = $(notdir $(wildcard $(RELEASE_LIBDIR)/modules/*))
TARGET_MODULES_DIR = $(foreach moddir,$(MODULES_DIRS),$(TARGET_ROOT)/lib/modules/$(moddir))
RELEASE_FW_DIR = $(RELEASE_LIBDIR)/firmware
TARGET_FW_DIR = $(TARGET_ROOT)/lib/firmware


install_driver:  $(MODULES_DIRS:%=install_driver_%) install_fw

$(MODULES_DIRS:%=install_driver_%): install_driver_%: $(call DEPENDENCY_ON_EXISTENCE_OF,$(TARGET_ROOT)/lib/modules/%)
	@$(if $(shell ls $(RELEASE_LIBDIR)/modules/$*/),$(ECHO) [CP] $(foreach fl,$(shell ls $(RELEASE_LIBDIR)/modules/$*/),$*/$(fl)) --\> $(TARGET_ROOT)/lib/modules/$*/ )
	@$(if $(shell ls $(RELEASE_LIBDIR)/modules/$*/),$(CP) $(foreach fl,$(shell ls $(RELEASE_LIBDIR)/modules/$*/),$(RELEASE_LIBDIR)/modules/$*/$(fl)) $(TARGET_ROOT)/lib/modules/$*/ )

install_fw: $(call DEPENDENCY_ON_EXISTENCE_OF,$(TARGET_FW_DIR))
	@$(if $(wildcard $(RELEASE_FW_DIR)/*),$(ECHO) [CP] $(foreach fl,$(wildcard $(RELEASE_FW_DIR)/*),$(notdir $(fl))) --\> $(TARGET_FW_DIR)/ )
	@$(if $(wildcard $(RELEASE_FW_DIR)/*),$(CP) $(wildcard $(RELEASE_FW_DIR)/*) $(TARGET_FW_DIR)/)
	

$(TARGET_MODULES_DIR) $(TARGET_FW_DIR):
	@$(ECHO) [MKDIR] $@
	@$(call exec_logged,$(MKDIR) $@ )


.PHONY: all target_install install_driver install_driver_% install_fw release_% clean_% 

endif # proj.cfg exists
###########################################

### Common rules (with or without proj.cfg) ###

# "clean" target only cleans host component 
# (shared components are "quasi-static" external components that we do not wish
# to re-build each time. Use distclean for deeper clean which includes shared
# components
clean: $(foreach target,$(PROJ_TARGETS),clean_$(target))

# Clean only intermediate build files (leave released files)
clean_intermediate: $(foreach target,$(PROJ_TARGETS),clean_intermediate_$(target))

clean_shared: $(foreach target,$(SHARED_COMPONENTS),$(if $(wildcard $(SHARED_SRCDIR)/$(target)),clean_$(target))) 

$(foreach module,$(filter-out cc_driver/public/linux,$(HOST_COMPONENTS)),clean_$(module)): clean_%:
	@$(ECHO) [CLN] $*
	@$(MAKE) -s -C $* clean

$(foreach module,$(filter-out cc_driver/public/linux,$(HOST_COMPONENTS)),clean_intermediate_$(module)): clean_intermediate_%:
	@$(ECHO) [CLN-INT] $*
	@$(MAKE) -s -C $* clean_intermediate

# Exception for cc_driver/public/linux : requires Makefile.setup
clean_cc_driver/public/linux: clean_%:
	@$(ECHO) [CLN] $*
	@$(MAKE) -s -C $* -f Makefile.setup clean

clean_intermediate_cc_driver/public/linux: clean_intermediate_%:
	@$(ECHO) [CLN-INT] $*
	@$(MAKE) -s -C $* -f Makefile.setup clean_intermediate

$(foreach module,$(SHARED_COMPONENTS),clean_$(module)): clean_%:
	@$(ECHO) [CLN] $*
	@$(MAKE) -s -C $(SHARED_SRCDIR)/$* -f Makefile.host clean

distclean: clean clean_shared clrconfig
	@$(ECHO) [REL-CLN] $(RELEASE_EXEDIR)
	@$(RMDIR) $(RELEASE_EXEDIR) 
	@$(ECHO) [REL-CLN] $(RELEASE_LIBDIR)
	@$(RMDIR) $(RELEASE_LIBDIR) 
	@$(ECHO) [REL-CLN] $(RELEASE_INCDIR)
	@$(RMDIR) $(RELEASE_INCDIR) 
	@$(ECHO) [REL-CLN] $(RELEASE_DATDIR)
	@$(RMDIR) $(RELEASE_DATDIR) 
	@$(ECHO) [REL-CLN] $(ROM_RELEASE_DIR)
	@$(RMDIR) $(ROM_RELEASE_DIR) 

.PHONY: clean clean_intermediate clean_% distclean
