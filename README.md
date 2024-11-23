# C_KEYSTONE_INTERFACE_LIB

# 设置编译器

```bash
export PATH=$PATH:/home/yx/Desktop/vf-keystone/keystone/build-starfive/visionfive264/buildroot.build/host/bin
```

# 制作libipfs_keystone.o库

```bash
riscv64-buildroot-linux-gnu-g++ -o lib_c_interface_keystone/ipfs_keystone_lib.o -c lib_c_interface_keystone/src/host_native.cpp -I/home/yx/Desktop/vf-keystone/IPFS_KEYSTONE/C_INTERFACE_KEYSTONE_LIB_DEMO/lib_c_interface_keystone/include -L/home/yx/Desktop/vf-keystone/IPFS_KEYSTONE/C_INTERFACE_KEYSTONE_LIB_DEMO/lib_keystone/lib -lkeystone-host -lkeystone-edge -I/home/yx/Desktop/vf-keystone/IPFS_KEYSTONE/C_INTERFACE_KEYSTONE_LIB_DEMO/lib_keystone/include/host -I/home/yx/Desktop/vf-keystone/IPFS_KEYSTONE/C_INTERFACE_KEYSTONE_LIB_DEMO/lib_keystone/include/edge -I/home/yx/Desktop/vf-keystone/IPFS_KEYSTONE/C_INTERFACE_KEYSTONE_LIB_DEMO/lib_keystone/include
mv lib_c_interface_keystone/ipfs_keystone_lib.o ./
riscv64-buildroot-linux-gnu-ar x lib_keystone/lib/libkeystone-host.a
riscv64-buildroot-linux-gnu-ar x lib_keystone/lib/libkeystone-edge.a
riscv64-buildroot-linux-gnu-ar rcs lib_c_interface_keystone/libipfs_keystone.a *.o
rm -rf *.o
```
# 提供给go项目使用

将静态库和头文件移动到指定位置

```bash
sudo cp -r lib_c_interface_keystone/include /usr/local/ipfs-keystone
sudo cp -r lib_keystone/include /usr/local/ipfs-keystone
sudo cp lib_c_interface_keystone/libipfs_keystone.a /usr/local/ipfs-keystone/
```

go项目通过cgo使用

```golang
package <package-name>

// #cgo LDFLAGS: -L/usr/local/ipfs-keystone -lipfs_keystone -lstdc++
// #cgo CFLAGS: -I/usr/local/ipfs-keystone/include -I/usr/local/ipfs-keystone/include/host -I/usr/local/ipfs-keystone/include/edge
// #include "ipfs_keystone.h"
import "C"
```

# 在c语言环境中测试

```bash
riscv64-buildroot-linux-gnu-g++ -o test_c_interface/testcinterface test_c_interface/test.c -L/home/yx/Desktop/vf-keystone/IPFS_KEYSTONE/C_INTERFACE_KEYSTONE_LIB_DEMO/lib_c_interface_keystone -lipfs_keystone -I/home/yx/Desktop/vf-keystone/IPFS_KEYSTONE/C_INTERFACE_KEYSTONE_LIB_DEMO/lib_c_interface_keystone/include -I/home/yx/Desktop/vf-keystone/IPFS_KEYSTONE/C_INTERFACE_KEYSTONE_LIB_DEMO/lib_keystone/include/host -I/home/yx/Desktop/vf-keystone/IPFS_KEYSTONE/C_INTERFACE_KEYSTONE_LIB_DEMO/lib_keystone/include/edge -I/home/yx/Desktop/vf-keystone/IPFS_KEYSTONE/C_INTERFACE_KEYSTONE_LIB_DEMO/lib_keystone/include
```

# 最终结构（不包括eapp、runtime）

```bash
.
├── lib_c_interface_keystone
│   ├── include
│   │   └── ipfs_keystone_demo.h
│   ├── libipfs_keystone.a
│   └── src
│       └── host_native.cpp
├── lib_keystone
│   ├── include
│   │   ├── app
│   │   │   ├── eapp_utils.h
│   │   │   ├── malloc.h
│   │   │   ├── sealing.h
│   │   │   ├── string.h
│   │   │   └── syscall.h
│   │   ├── common
│   │   │   └── sha3.h
│   │   ├── edge
│   │   │   ├── edge_call.h
│   │   │   ├── edge_common.h
│   │   │   ├── edge_syscall.h
│   │   │   └── syscall_nums.h
│   │   ├── host
│   │   │   ├── common.h
│   │   │   ├── elf32.h
│   │   │   ├── elf64.h
│   │   │   ├── ElfFile.hpp
│   │   │   ├── elf.h
│   │   │   ├── Elfloader.hpp
│   │   │   ├── Enclave.hpp
│   │   │   ├── Error.hpp
│   │   │   ├── hash_util.hpp
│   │   │   ├── KeystoneDevice.hpp
│   │   │   ├── keystone.h
│   │   │   ├── keystone_user.h
│   │   │   ├── Log.hpp
│   │   │   ├── Memory.hpp
│   │   │   └── Params.hpp
│   │   ├── shared
│   │   │   ├── eyrie_call.h
│   │   │   ├── keystone_user.h
│   │   │   ├── sm_call.h
│   │   │   └── sm_err.h
│   │   └── verifier
│   │       ├── ed25519
│   │       │   ├── ed25519.h
│   │       │   ├── fe.h
│   │       │   ├── fixedint.h
│   │       │   ├── ge.h
│   │       │   ├── precomp_data.h
│   │       │   └── sc.h
│   │       ├── json11.h
│   │       ├── Keys.hpp
│   │       ├── report.h
│   │       ├── Report.hpp
│   │       └── test_dev_key.h
│   ├── libkeystone-edge.a
│   └── libkeystone-host.a
└── README.md
└── test_c_interface
    ├── keystone-ipfs.sh
    ├── test.c
    └── testcinterface

```

# 结果

输出 test代表该库可以正常使用。

后面的错误是因为没有提供eapp和runtime以及测试环境的keystone版本与目的版本不一致。不影响测试结果。

```bash
# ./testcinterface 
test
[Keystone SDK] ElfFile.cpp:25 : file does not exist - hello-native
[Keystone SDK] ElfFile.cpp:25 : file does not exist - loader.bin
ioctl error: Function not implemented
[Keystone SDK] Enclave.cpp:247 : failed to run enclave - ioctl() failed

```

