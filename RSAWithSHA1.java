import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSAWithSHA1 {

    public static final String KEY_ALGORITHM = "RSA";
    public static final String SIGNATURE_ALGORITHM = "SHA1WithRSA";
    /**
         * 用私钥对信息生成数字签名
         *
         * @param data
         *            加密数据
         * @param privateKey
         *            私钥
         *
         * @return
         * @throws Exception
         */
    public static String sign(byte[] data, String privateKey) throws Exception {
        // 解密由base64编码的私钥
        byte[] keyBytes = decryptBASE64(privateKey);

        // 构造PKCS8EncodedKeySpec对象
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);

        // KEY_ALGORITHM 指定的加密算法
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

        // 取私钥匙对象
        PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);

        // 用私钥对信息生成数字签名
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(priKey);
        signature.update(data);

        return encryptBASE64(signature.sign());
    }

    /**
     * 校验数字签名
     *
     * @param data
     *            加密数据
     * @param publicKey
     *            公钥
     * @param sign
     *            数字签名
     *
     * @return 校验成功返回true 失败返回false
     * @throws Exception
     *
     */
    public static boolean verify(byte[] data, String publicKey, String sign) throws Exception {

        // 解密由base64编码的公钥
        byte[] keyBytes = decryptBASE64(publicKey);

        // 构造X509EncodedKeySpec对象
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

        // KEY_ALGORITHM 指定的加密算法
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

        // 取公钥匙对象
        PublicKey pubKey = keyFactory.generatePublic(keySpec);

        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(pubKey);
        signature.update(data);

        // 验证签名是否正常
        return signature.verify(decryptBASE64(sign));
    }

    public static void main(String[] args) throws Exception {
        // 签名生成
        String content = "appId＝23232323&&testestesjfijfe12";

        String privateKey = "mbyKNDk+fpYHGZ8WMzGJjA6wWsFcWDxOtdIP4BR7W00Shvau/QJBALQxheLcK9s3CfnD+RtQK9MxKbk/oe0Pjf+UvmufUJOWzGNzThuwNA70EThKb0VBNMaXbeHxVicU0QquTdKQkH0CQG/VwLy00QjqwLv6oqZ+i6XpsSoCTlwe25Yp/pjsUrpq5+DnZ9mkw2s2WUi2sdwOpUogctQ5XlBbdjOLpoLhVjM=";
        String sign = sign(content.getBytes(), privateKey);
        String lastSign = URLEncoder.encode(sign.replace("\n", ""), "UTF-8");
        System.out.println("签名内容：" + content);
        System.out.println("最终签名：" + lastSign);

        // 签名验证
        String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA";
        boolean bverify = verify(content.getBytes(), publicKey, URLDecoder.decode(xiaoySign, "UTF-8"));

        System.out.println("验证结果：" + bverify +";decode sign="+URLDecoder.decode(xiaoySign, "UTF-8"));

    }
}
