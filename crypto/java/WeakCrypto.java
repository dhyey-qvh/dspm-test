// Intentionally insecure scan fixtures. Never use in an application.
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class WeakCrypto {
    public static byte[] md5Password(byte[] password) throws Exception {
        return MessageDigest.getInstance("MD5").digest(password);
    }

    public static byte[] sha1Signature(byte[] payload) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(payload);
    }

    public static byte[] desEncrypt(byte[] block) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec("12345678".getBytes("UTF-8"), "DES"));
        return cipher.doFinal(block);
    }

    public static byte[] aesFixedIv(byte[] block) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE,
            new SecretKeySpec("0123456789abcdef".getBytes("UTF-8"), "AES"),
            new IvParameterSpec(new byte[16]));
        return cipher.doFinal(block);
    }

    public static KeyPair smallRsaKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        return generator.generateKeyPair();
    }
}
