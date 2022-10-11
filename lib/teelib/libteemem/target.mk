#
#
# See "HUAWEI_LICENSE" for details.
#
#

libs-$(CONFIG_LIB_TEEMEM) += libteemem libteemem_a32

libteemem: common \
    libsyscalls   \
    libc          \
    libmmgr       \
    libhongmeng   \
    libhwsecurec

libteemem_a32: common \
    libsyscalls_a32   \
    libc_a32          \
    libmmgr_a32       \
    libhongmeng_a32   \
    libhwsecurec_a32
