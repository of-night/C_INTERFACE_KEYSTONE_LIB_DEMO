#ifndef IPFS_KEYSTONE_H
#define IPFS_KEYSTONE_H

#define AES 1
#define SM4 2
#define demo 3

#ifdef __cplusplus
extern "C" {
#endif

void ipfs_keystone(int isAES, char *fileName);

#ifdef __cplusplus
}
#endif

#endif //IPFS_KEYSTONE_H
