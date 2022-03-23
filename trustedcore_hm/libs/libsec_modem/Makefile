# MODULE is a lib
MODULE := libsec_modem.a

include $(TOPDIR)/mk/var.mk

include $(LIBS_DIR)/libsec_modem/sec_modem.mk

c-flags += -Wno-unused-parameter -Wno-visibility -Wno-constant-logical-operand
c-flags += -Wno-missing-braces
c-flags += -Wno-uninitialized
c-flags += -fno-builtin
c-flags += -Wall -Wextra

# Source files required to build the target
libsec_modem_c_files += $(CFILES)

include $(TOPDIR)/mk/lib-common.mk
