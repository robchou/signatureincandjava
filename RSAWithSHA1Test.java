import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.*;

public class RSAWithSHA1Test {

    public static void main(String[] args) throws IOException,
           NoSuchAlgorithmException, InvalidKeySpecException,
    InvalidKeyException, SignatureException {

        byte[] encodedPrivateKey = readFile("private.der");
        byte[] content = readFile("data.txt");

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
        RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory
        .generatePrivate(keySpec);

        Signature signature = Signature.getInstance("SHA1WithRSA");
        signature.initSign(privateKey);
        //signature.update(content);
        signature.update("data to sign".getBytes("utf-8"));
        byte[] signatureBytes = signature.sign();

        FileOutputStream fos = new FileOutputStream("signature-java");
        fos.write(signatureBytes);
        fos.close();
    }

    private static byte[] readFile(String filename) throws IOException {
        File file = new File(filename);
        BufferedInputStream bis = new BufferedInputStream(new FileInputStream(
            file));
        byte[] bytes = new byte[(int) file.length()];
        bis.read(bytes);
        bis.close();
        return bytes;
    }

}
