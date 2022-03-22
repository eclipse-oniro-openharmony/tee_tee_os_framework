# MODULE is a lib
MODULE := libbz_hm.a

# Source files required to build the target
libbz_hm_c_files += $(wildcard src/*.c)

c-flags += -Wall -Wextra
c-flags += -Wno-unused-parameter
c-flags += -Wno-implicit-fallthrough # inflate.c have switch-case-fallthrough
c-flags += -Wno-sign-compare	    # inflate.c have a sign compare with unsign

# zlib have conflict builtin functions
c-flags += -fno-builtin-fwrite	\
           -fno-builtin-malloc	\
           -fno-builtin-calloc

# Header files/directories this library provides
EXPORT_HDRS := $(wildcard $(TOPDIR)/thirdparty/opensource/libbz_hm/src/*.h)

include $(TOPDIR)/mk/ext_lib-common.mk
