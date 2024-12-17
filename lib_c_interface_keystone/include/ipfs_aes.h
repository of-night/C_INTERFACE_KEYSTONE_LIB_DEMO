// ==================================================================================
//									Aes Decrypt
// ==================================================================================

#ifndef IPFS_AES_H
#define IPFS_AES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char u8;
typedef unsigned int u32;

/* AES decrypt interface */

void * aes_decrypt_init(const u8 *key, size_t len);

void aes_decrypt(void *ctx, const u8 *crypt, u8 *plain);

void aes_decrypt_deinit(void *ctx);

void decrypt_init();
void decrypt_deinit();
int decrypt(void* ct, int ctLen, void* pt);


/* AES encrypt interface */

void * aes_encrypt_init(const u8 *key, size_t len);

void aes_encrypt(void *ctx, const u8 *plain, u8 *crypt);

void aes_encrypt_deinit(void *ctx);

void encrypt_init();
void encrypt_deinit();
int encrypt(void* pt, int ptLen, void* ct);

#ifdef __cplusplus
}
#endif

#endif //IPFS_AES_H