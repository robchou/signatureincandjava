#ifndef COMMON_TOOL_H_ZRSI9NP3
#define COMMON_TOOL_H_ZRSI9NP3

#include <iostream>
#include <openssl/rsa.h>

class common_tool
{
public:
    common_tool () {}
    virtual ~common_tool () {}
    static std::string url_encode(const std::string& szToEncode);
    static std::string url_decode(const std::string& szToDecode);
    static bool verify_rsa(RSA *rsa ,const std::string &content, const std::string &sign);

private:
    /* data */
};

#endif /* end of include guard: COMMON_TOOL_H_ZRSI9NP3 */
