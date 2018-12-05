import org.bouncycastle.jce.ECNamedCurveTable;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

public class EC {

    public static byte[] iv = new SecureRandom().generateSeed(16);

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        //String curve = "brainpoolp256r1";
        String curve = "X25519";

        String plainText = "Look mah, I'm a message!";
        System.out.println("Original plaintext message: " + plainText);

        // Initialize two key pairs
        KeyPair keyPairA = generateECKeys(curve);
        KeyPair keyPairB = generateECKeys(curve);

        // Create two AES secret keys to encrypt/decrypt the message
        SecretKey secretKeyA;
        SecretKey secretKeyB;

        if (curve.startsWith("brain")) {
            secretKeyA = generateSharedSecret(keyPairA.getPrivate(), keyPairB.getPublic());
            secretKeyB = generateSharedSecret(keyPairB.getPrivate(), keyPairA.getPublic());
        }
        else {
            secretKeyA = generateSharedSecretXDH(keyPairA.getPrivate(), keyPairB.getPublic());
            secretKeyB = generateSharedSecretXDH(keyPairB.getPrivate(), keyPairA.getPublic());
        }

        System.out.println("Shared keys are identical: " + (Arrays.compare(secretKeyA.getEncoded(), secretKeyB.getEncoded()) == 0));

        // Encrypt the message using 'secretKeyA'
        String cipherText = encryptString(secretKeyA, plainText);
        System.out.println("Encrypted cipher text: " + cipherText);

        // Decrypt the message using 'secretKeyB'
        String decryptedPlainText = decryptString(secretKeyB, cipherText);
        System.out.println("Decrypted cipher text: " + decryptedPlainText);
    }

    public static KeyPair generateECKeys(String curve) {
        try {
            KeyPairGenerator keyPairGenerator;
            if (curve.startsWith("brain")) {
                ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(curve);
                keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");
                keyPairGenerator.initialize(parameterSpec);
            }
            else {
                keyPairGenerator = KeyPairGenerator.getInstance("XDH");
                ECGenParameterSpec ecsp = new ECGenParameterSpec(curve);
                keyPairGenerator.initialize(ecsp);
            }

            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            return keyPair;
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static SecretKey generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(publicKey, true);

            SecretKey key = keyAgreement.generateSecret("AES");
            return key;
        } catch (InvalidKeyException | NoSuchAlgorithmException
                | NoSuchProviderException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
    }

    public static SecretKey generateSharedSecretXDH(PrivateKey privateKey, PublicKey publicKey) {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("XDH");
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(publicKey, true);

            byte[] keyBytes = keyAgreement.generateSecret();
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

            return key;
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
    }

    public static String encryptString(SecretKey key, String plainText) {
        try {
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            byte[] plainTextBytes = plainText.getBytes("UTF-8");
            byte[] cipherText;

            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            cipherText = new byte[cipher.getOutputSize(plainTextBytes.length)];
            int encryptLength = cipher.update(plainTextBytes, 0,
                    plainTextBytes.length, cipherText, 0);
            encryptLength += cipher.doFinal(cipherText, encryptLength);

            return bytesToHex(cipherText);
        } catch (NoSuchAlgorithmException | NoSuchProviderException
                | NoSuchPaddingException | InvalidKeyException
                | InvalidAlgorithmParameterException
                | UnsupportedEncodingException | ShortBufferException
                | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String decryptString(SecretKey key, String cipherText) {
        try {
            Key decryptionKey = new SecretKeySpec(key.getEncoded(),
                    key.getAlgorithm());
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            byte[] cipherTextBytes = hexToBytes(cipherText);
            byte[] plainText;

            cipher.init(Cipher.DECRYPT_MODE, decryptionKey, ivSpec);
            plainText = new byte[cipher.getOutputSize(cipherTextBytes.length)];
            int decryptLength = cipher.update(cipherTextBytes, 0,
                    cipherTextBytes.length, plainText, 0);
            decryptLength += cipher.doFinal(plainText, decryptLength);

            return new String(plainText, "UTF-8");
        } catch (NoSuchAlgorithmException | NoSuchProviderException
                | NoSuchPaddingException | InvalidKeyException
                | InvalidAlgorithmParameterException
                | IllegalBlockSizeException | BadPaddingException
                | ShortBufferException | UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String bytesToHex(byte[] data, int length) {
        String digits = "0123456789ABCDEF";
        StringBuffer buffer = new StringBuffer();

        for (int i = 0; i != length; i++) {
            int v = data[i] & 0xff;

            buffer.append(digits.charAt(v >> 4));
            buffer.append(digits.charAt(v & 0xf));
        }

        return buffer.toString();
    }

    public static String bytesToHex(byte[] data) {
        return bytesToHex(data, data.length);
    }

    public static byte[] hexToBytes(String string) {
        int length = string.length();
        byte[] data = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            data[i / 2] = (byte) ((Character.digit(string.charAt(i), 16) << 4) + Character
                    .digit(string.charAt(i + 1), 16));
        }
        return data;
    }
}
