struct BLOWFISH_CTX
{
    unsigned int p[18];
    unsigned int sbox[4][256];
};

void blowfish_encrypt_block(struct BLOWFISH_CTX *ctx, unsigned int *left, unsigned int *right);
void blowfish_decrypt_block(struct BLOWFISH_CTX *ctx, unsigned int *left, unsigned int *right);
void blowfish_init(struct BLOWFISH_CTX *ctx, unsigned char *key, int key_size);
