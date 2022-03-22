#!/bin/bash
#        "[-a @OUTPUT@ asset package file name <asset_pkg.bin>] "
#        "[-b asset data binary file <asset_bin.bin>] "
#        "[-i asset ID  <32 bit word>]"
#        "[-o file name for oem-key <oem_key.bin>]"
#	 "[-p key pair file name - PEM format <key_pair.pem>]"
#	 "[-w passpfrase file name  <pwd.txt>]"
#        "[-u optional additional user data <32 bit word>]\n");

cd ../../../bin/

cp ../tester/oem_asset_prov/dat/asset_bin1.bin .
cp ../tester/oem_asset_prov/dat/key_pair0.pem .


echo
echo " Run: oem_asset_pack (1234512345)"
echo "================================================"
./oem_asset_pack_util -a asset_pkg1.bin -b asset_bin1.bin -i 0x367 -o oem_key1.bin -p key_pair0.pem -u 0x0

