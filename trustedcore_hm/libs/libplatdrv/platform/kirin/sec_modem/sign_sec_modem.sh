#!/bin/bash
# preare toolchains and env for build ta.
# Copyright @ Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
set -e

LOCAL_PATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

#JDK 1.8
java_version=$(java -version 2>&1 |awk 'NR==1{gsub(/"/,"");print $3}' | cut -b 1,2,3)
if [ "$java_version" == "1.8" ];then
    echo $JAVA_HOME
else
    export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
    export JRE_HOME=$JAVA_HOME/jre/jre
    export CLASSPATH=.:$JAVA_HOME/lib:$JRE_HOME/lib:$CLASSPATH
    export PATH=$JAVA_HOME/bin:$JRE_HOME/bin:$PATH
fi


### input
INPUT_PATH=$1
OUTPUT_PATH=$2
INI_FILE_PATH=$3

ITRUSTEE_CODE_ROOT_PATH=$LOCAL_PATH/../../../../../../../../../../
export NATIVE_CA_SIGN_JAR_PATH=$ITRUSTEE_CODE_ROOT_PATH/tools/signcenter/NativeCASign.jar

# set sdk path
ITRUSTEE_SDK_PATH=$LOCAL_PATH/../../../../../../../itrustee_sdk


echo "sign TA now"

cd $ITRUSTEE_SDK_PATH/build/signtools

if [ -f signtool_v3.py ];then
    python -B signtool_v3.py "${INPUT_PATH}" "${OUTPUT_PATH}" --config "${INI_FILE_PATH}"
else
    echo "Can not find signtool_v3.py"
fi

exit 0
