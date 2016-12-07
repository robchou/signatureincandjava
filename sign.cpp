#include <iostream>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include "common_tool.h"


//二进制转换为base64编码
char* base64(const void *input, int length)
{
    BIO *bmem, *b64;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);

    //去掉回车换行
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    BIO_write(b64, input, length);
    BIO_flush(b64);

    BIO_get_mem_ptr(b64, &bptr);

    char *buff = (char*)malloc(bptr->length);

    memcpy(buff, bptr->data, bptr->length-1);
    buff[bptr->length - 1] = 0;

    BIO_free_all(b64);

    return buff;
}


static std::string sign(const char *private_key,
                        const std::string &content) {
    BIO *bufio = NULL;
    RSA *rsa = NULL;
    EVP_PKEY *evpKey = NULL;
    bool verify = false;
    EVP_MD_CTX ctx;
    int result = 0;
    unsigned int size = 0;
    char *sign = NULL;
    std::string signStr = "";

    //bufio = BIO_new_mem_buf((void*)private_key, -1);
    //if (bufio == NULL) {
    //  ERR("BIO_new_mem_buf failed");
    //  goto safe_exit;
    //}
    bufio = BIO_new(BIO_s_file());
    //BIO_read_filename(bufio, "rsa_private_key_pkcs8.pem");
    BIO_read_filename(bufio, "rsa_private_key.pem");

    rsa = PEM_read_bio_RSAPrivateKey(bufio, NULL, NULL, NULL);
    if (rsa == NULL) {
        //ERR("PEM_read_bio_RSAPrivateKey failed");
        printf("PEM_read_bio_RSAPrivateKey failed");
        goto safe_exit;
    }

    evpKey = EVP_PKEY_new();
    if (evpKey == NULL) {
        //ERR("EVP_PKEY_new failed");
        printf("EVP_PKEY_new failed");
        goto safe_exit;
    }

    if ((result = EVP_PKEY_set1_RSA(evpKey, rsa)) != 1) {
        //ERR("EVP_PKEY_set1_RSA failed");
        printf("EVP_PKEY_set1_RSA failed");
        goto safe_exit;
    }

    EVP_MD_CTX_init(&ctx);

    if (result == 1 && (result = EVP_SignInit_ex(&ctx,
                                 //EVP_md5(), NULL)) != 1) {
                                 EVP_sha1(), NULL)) != 1) {
        //ERR("EVP_SignInit_ex failed");
        printf("EVP_SignInit_ex failed");
    }

    if (result == 1 && (result = EVP_SignUpdate(&ctx,
                                 content.c_str(), content.size())) != 1) {
        //ERR("EVP_SignUpdate failed");
        printf("EVP_SignUpdate failed");
    }

    size = EVP_PKEY_size(evpKey);
    sign = (char*)malloc(size+1);
    memset(sign, 0, size+1);

    if (result == 1 && (result = EVP_SignFinal(&ctx,
                                 (unsigned char*)sign,
                                 &size, evpKey)) != 1) {
        //ERR("EVP_SignFinal failed");
        printf("EVP_SignFinal failed");
    }

    if (result == 1) {
        verify = true;
    } else {
        //ERR("verify failed");
        printf("verify failed");
    }

    //signStr = common_tool::base64_encode((const unsigned char*)sign, size);
    signStr = base64((const unsigned char*)sign, size);
    EVP_MD_CTX_cleanup(&ctx);
    free(sign);

safe_exit:
    if (rsa != NULL) {
        RSA_free(rsa);
        rsa = NULL;
    }

    if (evpKey != NULL) {
        EVP_PKEY_free(evpKey);
        evpKey = NULL;
    }

    if (bufio != NULL) {
        BIO_free_all(bufio);
        bufio = NULL;
    }

    return signStr;
    //return sign;
}

int main(int argc, char *argv[])
{
    std::cout << sign("", "data to sign") << std::endl;
    return 0;
}
