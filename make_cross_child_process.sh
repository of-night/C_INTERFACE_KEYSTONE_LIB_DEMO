#!/bin/bash

CXX=riscv64-buildroot-linux-gnu-g++

if ! command -v "${CXX}"
then
	echo "set CXX"
    source source.sh
fi

VF_KEYSTONE=/home/yx/Desktop/vf-keystone

KEYSTONELIB=${VF_KEYSTONE}/IPFS_KEYSTONE/C_INTERFACE_KEYSTONE_LIB_DEMO/lib_keystone/lib
KEYSTONEINCLUDE=${VF_KEYSTONE}/IPFS_KEYSTONE/C_INTERFACE_KEYSTONE_LIB_DEMO/lib_keystone/include

MYKEYSTONEINCLUDE=${VF_KEYSTONE}/IPFS_KEYSTONE/C_INTERFACE_KEYSTONE_LIB_DEMO/lib_c_interface_keystone/include

src_name=cross_child_process.cpp
dest_name=cross_child_process

src_path=lib_c_interface_keystone/src

src=${src_path}/${src_name}

rm ${dest_name} -rf

$CXX -o ${dest_name} \
	${src} \
	-I${MYKEYSTONEINCLUDE} \
	-L${KEYSTONELIB} \
	-lkeystone-host \
	-lkeystone-edge \
	-I${KEYSTONEINCLUDE}/host \
	-I${KEYSTONEINCLUDE}/edge \
	-I${KEYSTONEINCLUDE} \
	-static

sudo rm ~/ipfs/cross_child_process -rf
sync
sudo cp cross_child_process ~/ipfs/
sync

