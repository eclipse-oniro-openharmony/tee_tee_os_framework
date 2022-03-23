#!/bin/bash
# Usage: check-syms.sh TA.elf libc.so libtee.so
# Copyright Huawei Technologies Co., Ltd. 2010-2019. All rights reserved.
#set -e

IGNORED=$(echo cfi_disabled; echo llvm_gcov_init; echo llvm_gcov_reset; echo llvm_gcov_dump;)
UNDEF=$(objdump -T "$1" | grep '\*UND\*' | egrep -o '[^ ]+$')
DEFC=$(objdump -T "$2" | grep -v '\*UND\*' | egrep -o '[^ ]+$')
DEFTEE=$(objdump -T "$3" | grep -v '\*UND\*' | egrep -o '[^ ]+$')
DEFVENDOR=$(objdump -T "$4" | grep -v '\*UND\*' | egrep -o '[^ ]+$')
DEFTUI=$(objdump -T "$5" | grep -v '\*UND\*' | egrep -o '[^ ]+$')
DEFDRV=$(objdump -T "$6" | grep -v '\*UND\*' | egrep -o '[^ ]+$')
DEFBASE=$(objdump -T "$7" | grep -v '\*UND\*' | egrep -o '[^ ]+$')
ALLDEF=$(echo "$IGNORED" ; echo "$DEFC" ; echo "$DEFTEE" ; echo "$DEFVENDOR" ; echo "$DEFTUI" ; echo "$DEFDRV" ; echo "$DEFBASE")

for sym in $UNDEF ; do
if ! (echo "$ALLDEF" | grep -qs "^$sym$") ; then
echo "$(basename $1) contains undefined symbol $sym"
exit 1
fi
done
exit 0
