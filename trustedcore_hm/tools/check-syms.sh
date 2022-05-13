#!/bin/bash
# Usage: check-syms.sh TA.elf libc.so libtee.so
# Copyright Huawei Technologies Co., Ltd. 2010-2022. All rights reserved.
#set -e

# add ignored syms to IGNORED
IGNORED=$(echo cfi_disabled; echo llvm_gcov_init; echo llvm_gcov_reset; echo llvm_gcov_dump;)
# add undefined syms to UNDEF
UNDEF=$(objdump -T "$1" | grep '\*UND\*' | egrep -o '[^ ]+$')

# add defined syms to ALLDEF
# ALLDEF for check:
# libc_shared_a32.so             libc_shared_a32.so
# libtee_shared_a32.so           libtee_shared.so
# libvendor_shared_a32.so        libvendor_shared.so
# libtui_internal_shared_a32.so  libtui_internal_shared.so
# libdrv_shared_a32.so           libdrv_shared.so
# libbase_shared_a32.so          libbase_shared.so
ALLDEF="$IGNORED\n"
DEF_NUM=1
for i in $* ; do
if [ $DEF_NUM -gt 1 ] ; then
DEF[$DEF_NUM]=$(objdump -T "$i" | grep -v '\*UND\*' | egrep -o '[^ ]+$')
ALLDEF=${ALLDEF}"${DEF[$DEF_NUM]}\n"
fi
let DEF_NUM++
done

# check undefined syms
for sym in $UNDEF ; do
if ! (echo -e "$ALLDEF" | grep -qs "^$sym$") ; then
echo "$(basename $1) contains undefined symbol $sym"
if [ "$CONFIG_LIBFUZZER_SERVICE_64BIT" !=  "true" ] ; then
exit 1
fi
fi
done
exit 0
