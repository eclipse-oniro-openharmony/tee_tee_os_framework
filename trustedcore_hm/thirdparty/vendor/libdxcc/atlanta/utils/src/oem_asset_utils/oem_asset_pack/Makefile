UTIL_EXE_NAME = oem_asset_pack_util

UTILS_ROOT = $(shell pwd)/../../..
UTILS_LIB_PATH = $(UTILS_ROOT)/lib
SHARED_DIR = $(UTILS_ROOT)/../shared
INCLUDE_DIRS = $(SHARED_DIR)/include/cc_util  $(SHARED_DIR)/include/proj/$(PROJ_PRD) $(UTILS_ROOT)/src/common
UTILS_EXE_PATH = $(UTILS_ROOT)/src/oem_asset_utils/oem_asset_pack
UTILS_COMMON = $(UTILS_ROOT)/src/common

vpath %.c $(UTILS_COMMON)

EXE_SRC_O = oem_asset_pack.o common_rsa_keypair.o common_rsa_keypair_util.o common_util_files.o common_crypto_sym.o common_crypto_asym.o common_crypto_encode.o

CFLAGS += -fPIC $(foreach incdir,$(INCLUDE_DIRS),-I$(incdir)) -c


ifeq ($(DEBUG),1)
    CFLAGS += -DUTIL_DEBUG -g
endif

LIBS = -lcrypto -lssl

LDFLAGS = $(LIBDIRS) $(LIBS)


all: $(UTIL_EXE_NAME)

# Compile and link the sbu_crypto library with hard-coded library run path to utils/lib
# (to assure the private version of openssl libraries are used)
$(UTIL_EXE_NAME): $(EXE_SRC_O)
	gcc -o $(UTIL_EXE_NAME) $(EXE_SRC_O) $(LDFLAGS) 

%.o: %.c
	gcc $(CFLAGS) $<


DEPENDENCY_ON_EXISTENCE_OF = $(filter-out $(wildcard $(1)), $(1))

all: install_oem_asset

install_oem_asset: $(call DEPENDENCY_ON_EXISTENCE_OF,$(UTILS_ROOT)/bin)
	@echo Installing OEM asset pack
	@cp $(UTILS_EXE_PATH)/$(UTIL_EXE_NAME) $(UTILS_ROOT)/bin/$(UTIL_EXE_NAME)

$(UTILS_ROOT)/%:
	@echo Creating directory $@
	@mkdir $@

clean:
	rm -f $(UTIL_EXE_NAME) $(EXE_SRC_O) *.bin

.PHONY: clean all

