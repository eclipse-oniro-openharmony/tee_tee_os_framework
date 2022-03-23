#!/bin/bash
#       "[-c csr file name <csr.bin>] "
#       "[-q optional CM public key key file name - PEM format <pubKey1.pem>]"
#       "[-o @OUTPUT@ oem key file name - PEM format <oem_key.pem>]"
#       "[-s file name for Scp and Krtl <cm_secrets.bin>]"
#	"[-w secters passphrase file name <cm_pwd.txt>]\n");

cd ../../../bin/

cp ../tester/oem_asset_prov/dat/cm_secrets_pwd1.txt .
cp ../tester/oem_asset_prov/dat/cm_orig_secrets3.bin .
cp ../tester/oem_asset_prov/dat/key_pair0.pem .
cp ../tester/oem_asset_prov/dat/passphrase0.txt .
cp ../tester/util_assisted/encrypt_encode_secrets/encrypt_encode_secrets.sh .

echo
echo " Run: encrypt encode secret... "
echo "================================================"
./oem_gen_csr_util -c csr1.bin -p key_pair0.pem -w passphrase0.txt
./encrypt_encode_secrets.sh cm_orig_secrets3.bin cm_secrets1.bin cm_secrets_pwd1.txt

echo
echo " Run: gen_oem_key "
echo "================================================"
./cm_gen_oem_key_util -c csr1.bin -o oem_key1.bin -s cm_secrets1.bin -w cm_secrets_pwd1.txt

