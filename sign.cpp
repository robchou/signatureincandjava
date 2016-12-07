#include <iostream>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include "common_tool.h"

static const char b64_table[] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
  'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
  'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
  'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
  'w', 'x', 'y', 'z', '0', '1', '2', '3',
  '4', '5', '6', '7', '8', '9', '+', '/'
};


char *b64_encode (const unsigned char *src, size_t len) {
  int i = 0;
  int j = 0;
  char *enc = NULL;
  size_t size = 0;
  unsigned char buf[4];
  unsigned char tmp[3];

  // alloc
  enc = (char *) malloc(0);
  if (NULL == enc) { return NULL; }

  // parse until end of source
  while (len--) {
    // read up to 3 bytes at a time into `tmp'
    tmp[i++] = *(src++);

    // if 3 bytes read then encode into `buf'
    if (3 == i) {
      buf[0] = (tmp[0] & 0xfc) >> 2;
      buf[1] = ((tmp[0] & 0x03) << 4) + ((tmp[1] & 0xf0) >> 4);
      buf[2] = ((tmp[1] & 0x0f) << 2) + ((tmp[2] & 0xc0) >> 6);
      buf[3] = tmp[2] & 0x3f;

      // allocate 4 new byts for `enc` and
      // then translate each encoded buffer
      // part by index from the base 64 index table
      // into `enc' unsigned char array
      enc = (char *) realloc(enc, size + 4);
      for (i = 0; i < 4; ++i) {
        enc[size++] = b64_table[buf[i]];
      }

      // reset index
      i = 0;
    }
  }

  // remainder
  if (i > 0) {
    // fill `tmp' with `\0' at most 3 times
    for (j = i; j < 3; ++j) {
      tmp[j] = '\0';
    }

    // perform same codec as above
    buf[0] = (tmp[0] & 0xfc) >> 2;
    buf[1] = ((tmp[0] & 0x03) << 4) + ((tmp[1] & 0xf0) >> 4);
    buf[2] = ((tmp[1] & 0x0f) << 2) + ((tmp[2] & 0xc0) >> 6);
    buf[3] = tmp[2] & 0x3f;

    // perform same write to `enc` with new allocation
    for (j = 0; (j < i + 1); ++j) {
      enc = (char *) realloc(enc, size + 1);
      enc[size++] = b64_table[buf[j]];
    }

    // while there is still a remainder
    // append `=' to `enc'
    while ((i++ < 3)) {
      enc = (char *) realloc(enc, size + 1);
      enc[size++] = '=';
    }
  }

  // Make sure we have enough space to add '\0' character at end.
  enc = (char *) realloc(enc, size + 1);
  enc[size] = '\0';

  return enc;
}

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
    BIO_read_filename(bufio, "rsa_private_key_pkcs8.pem");
    //BIO_read_filename(bufio, "rsa_private_key.pem");

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
    //std::cout << sign;
    //signStr = base64((const unsigned char*)sign, size);
    signStr = b64_encode((const unsigned char*)sign, size);
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
    //sign("", "data to sign");
    //std::string hello = "helloworld";
    //std::cout << base64((void*)hello.c_str(), hello.length()) << std::endl;
    //std::cout << b64_encode((const unsigned char*)hello.c_str(), hello.length()) << std::endl;
    return 0;
}
