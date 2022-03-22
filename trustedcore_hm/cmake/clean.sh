#!/bin/bash
# Print all commands if V=3; maximum verbosity.
# Copyright Huawei Technologies Co., Ltd. 2010-2019. All rights reserved.
set -e

clean_after_compile()
{
    set -x
    set +x
}


clean()
{
    clean_after_compile
    set -x
    [ -n "${CMAKE_INSTALL_PREFIX}" ] && rm -rf ${CMAKE_INSTALL_PREFIX}
    [ -n "${CMAKE_BUILD_PREFIX}" ] && rm -rf ${CMAKE_BUILD_PREFIX}
    [ -n "${OUT_MODEM}" ] && rm -rf ${OUT_MODEM}
    set +x
    exit 0
}

check_for_arch()
{
    while read line;
    do
        echo $line;
        var=${line%=*}
        val=${line#*=}

        if [ "$var" == "CONFIG_ARCH_AARCH64" ] && [ "$val" == "y" ]; then
            ARCH=aarch64
        fi

        if [ "$var" == "CONFIG_ARCH_AARCH32" ] && [ "$val" == "y" ]; then
            ARCH=arm
        fi

        if [ "$var" == "CONFIG_ENABLE_XOM32" ] && [ "$val" == "y" ]; then
            USE_XOM32=y
        fi

        if [ -n "$ARCH" ] && [ -n "$USE_XOM32" ]; then
            break
        fi
    done < ${CONFIG_FILE} &> /dev/null

    if [ -z "${ARCH}" ]; then
        echo "ERROR: ARCH is not set" 2>&1
        exit 1
    fi
}

usage()
{
    echo "Example: ./configure.sh -o kirin990 -t kirin990"
}
