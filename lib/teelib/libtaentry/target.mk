libs-$(CONFIG_LIB_TEELIB) += libtaentry libtaentry_a32 

libtaentry: common \
    libc

libtaentry_a32: common \
    libc_a32
