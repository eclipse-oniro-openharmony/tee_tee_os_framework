#!/bin/bash

CUR_PATH="$(pwd)"
ENV_INC_PATH=${CUR_PATH}/tzcc_fw/shared/include/env
ATF_VER=v1.3
ATF_ROOT=../../../../../../../../trustzone/atf

export OS=atf
TRUSTONIC_ROOT=../../../../../../../../../

rm -rf ${CUR_PATH}/include
rm -rf ${CUR_PATH}/lib
mkdir ${CUR_PATH}/include
mkdir ${CUR_PATH}/lib
mkdir ${ENV_INC_PATH}

#copy env include files to ENV_INC_PATH
cp -rf ${ATF_ROOT}/${ATF_VER}/include/lib/ ${ENV_INC_PATH}/

cd ${CUR_PATH}/tzcc_fw/host/src
make clean
make
cd ${PWD}
cp -rf ${CUR_PATH}/tzcc_fw/host/include ${CUR_PATH}/
cp -rf ${CUR_PATH}/tzcc_fw/host/lib ${CUR_PATH}/
cd ${CUR_PATH}/tzcc_fw/host/src
make clean
rmdir ${CUR_PATH}/tzcc_fw/host/include
rmdir ${CUR_PATH}/tzcc_fw/host/lib
rm -rf ${ENV_INC_PATH}

cd ${CUR_PATH}
