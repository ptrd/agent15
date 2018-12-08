package net.luminis.tls;

import at.favre.lib.crypto.HKDF;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static net.luminis.tls.ByteUtils.bytesToHex;

public class TlsState {

    private static final Charset ISO_8859_1 = Charset.forName("ISO-8859-1");
    private static byte[] P256_HEAD = Base64.getDecoder().decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE");

    private byte[] serverHello;
    private byte[] serverSharedKey;
    private PrivateKey clientPrivateKey;
    private byte[] clientHello;
    private byte[] serverHandshakeKey;
    private byte[] serverHandshakeIV;


    public void clientHelloSend(PrivateKey clientPrivateKey, byte[] sentClientHello) {
        this.clientPrivateKey = clientPrivateKey;
        clientHello = sentClientHello;
    }

    public void setServerSharedKey(byte[] serverHello, byte[] serverSharedKey) {
        this.serverHello = serverHello;
        this.serverSharedKey = serverSharedKey;

        byte[] handshakeHash = computeHandshakeMessagesHash(clientHello, serverHello);

        byte[] sharedSecret = computeSharedSecret(serverSharedKey);

        computeSecrets(handshakeHash, sharedSecret);

    }

    private byte[] computeHandshakeMessagesHash(byte[] clientHello, byte[] serverHello) {
        ByteBuffer helloData = ByteBuffer.allocate(clientHello.length - 5 + serverHello.length);
        helloData.put(clientHello, 5, clientHello.length - 5);
        helloData.put(serverHello, 0, serverHello.length);

        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing sha-256 support");
        }
        byte[] helloHash = digest.digest(helloData.array());

        System.out.println("Hello hash: " + bytesToHex(helloHash));
        return helloHash;
    }

    private byte[] computeSharedSecret(byte[] serverSharedKey) {
        ECPublicKey serverPublicKey = convertP256Key(serverSharedKey);

        try {
            //KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(clientPrivateKey);
            keyAgreement.doPhase(serverPublicKey, true);

            //SecretKey key = keyAgreement.generateSecret("AES");
            SecretKey key = keyAgreement.generateSecret("TlsPremasterSecret");
            System.out.println("Shared key: " + bytesToHex(key.getEncoded()));
            return key.getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Unsupported crypto: " + e);
        }
    }

    private void computeSecrets(byte[] helloHash, byte[] sharedSecret) {
        HKDF hkdf = HKDF.fromHmacSha256();
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing support for sha-256");
        }

        byte[] zeroSalt = new byte[32];
        byte[] zeroPSK = new byte[32];
        byte[] earlySecret = hkdf.extract(zeroSalt, zeroPSK);
        System.out.println("Early secret: " + bytesToHex(earlySecret));

        byte[] emptyHash = digest.digest(new byte[0]);
        System.out.println("Empty hash: " + bytesToHex(emptyHash));

        byte[] derivedSecret = hkdfExpandLabel(earlySecret, "derived", emptyHash, (short) 32);
        System.out.println("Derived secret: " + bytesToHex(derivedSecret));

        byte[] handshakeSecret = hkdf.extract(derivedSecret, sharedSecret);
        System.out.println("Handshake secret: " + bytesToHex(handshakeSecret));

        byte[] clientHandshakeTrafficSecret = hkdfExpandLabel(handshakeSecret, "c hs traffic", helloHash, (short) 32);
        System.out.println("Client handshake traffic secret: " + bytesToHex(clientHandshakeTrafficSecret));

        byte[] serverHandshakeTrafficSecret = hkdfExpandLabel(handshakeSecret, "s hs traffic", helloHash, (short) 32);
        System.out.println("Server handshake traffic secret: " + bytesToHex(serverHandshakeTrafficSecret));

        byte[] clientHandshakeKey = hkdfExpandLabel(clientHandshakeTrafficSecret, "key", "", (short) 16);
        System.out.println("Client handshake key: " + bytesToHex(clientHandshakeKey));

        serverHandshakeKey = hkdfExpandLabel(serverHandshakeTrafficSecret, "key", "", (short) 16);
        System.out.println("Server handshake key: " + bytesToHex(serverHandshakeKey));

        byte[] clientHandshakeIV = hkdfExpandLabel(clientHandshakeTrafficSecret, "iv", "", (short) 12);
        System.out.println("Client handshake iv: " + bytesToHex(clientHandshakeIV));

        serverHandshakeIV = hkdfExpandLabel(serverHandshakeTrafficSecret, "iv", "", (short) 12);
        System.out.println("Server handshake iv: " + bytesToHex(serverHandshakeIV));
    }

    public void decrypt(byte[] array) {
    }


    static byte[] hkdfExpandLabel(byte[] secret, String label, String context, short length) {
        // See https://tools.ietf.org/html/rfc8446#section-7.1 for definition of HKDF-Expand-Label.
        ByteBuffer hkdfLabel = ByteBuffer.allocate(2 + 1 + 6 + label.getBytes(ISO_8859_1).length + 1 + context.getBytes(ISO_8859_1).length);
        hkdfLabel.putShort(length);
        hkdfLabel.put((byte) (6 + label.getBytes().length));
        // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.1: 'the label for HKDF-Expand-Label uses the prefix "quic " rather than "tls13 "'
        hkdfLabel.put("tls13 ".getBytes(ISO_8859_1));
        hkdfLabel.put(label.getBytes(ISO_8859_1));
        hkdfLabel.put((byte) (context.getBytes(ISO_8859_1).length));
        hkdfLabel.put(context.getBytes(ISO_8859_1));
        HKDF hkdf = HKDF.fromHmacSha256();
        return hkdf.expand(secret, hkdfLabel.array(), length);
    }

    static byte[] hkdfExpandLabel(byte[] secret, String label, byte[] context, short length) {
        // See https://tools.ietf.org/html/rfc8446#section-7.1 for definition of HKDF-Expand-Label.
        ByteBuffer hkdfLabel = ByteBuffer.allocate(2 + 1 + 6 + label.getBytes(ISO_8859_1).length + 1 + context.length);
        hkdfLabel.putShort(length);
        hkdfLabel.put((byte) (6 + label.getBytes().length));
        // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.1: 'the label for HKDF-Expand-Label uses the prefix "quic " rather than "tls13 "'
        hkdfLabel.put("tls13 ".getBytes(ISO_8859_1));
        hkdfLabel.put(label.getBytes(ISO_8859_1));
        hkdfLabel.put((byte) (context.length));
        hkdfLabel.put(context);
        HKDF hkdf = HKDF.fromHmacSha256();
        return hkdf.expand(secret, hkdfLabel.array(), length);
    }


    public static ECPublicKey convertP256Key(byte[] w) {
        int keyLength = w.length;
        int startIndex = 0;
        if (w[0] == 4) {
            keyLength -= 1;
            startIndex = 1;
        }
        byte[] encodedKey = new byte[P256_HEAD.length + w.length];
        System.arraycopy(P256_HEAD, 0, encodedKey, 0, P256_HEAD.length);
        System.arraycopy(w, startIndex, encodedKey, P256_HEAD.length, keyLength);
        KeyFactory eckf;
        try {
            eckf = KeyFactory.getInstance("EC");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("EC key factory not present in runtime");
        }
        X509EncodedKeySpec ecpks = new X509EncodedKeySpec(encodedKey);
        try {
            return (ECPublicKey) eckf.generatePublic(ecpks);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    int recordCount = 0;

    byte[] decrypt(byte[] recordHeader, byte[] wrapper) {
        int recordSize = (recordHeader[3] & 0xff) << 8 | (recordHeader[4] & 0xff);
        System.out.println("Wrapper length: " + wrapper.length + " bytes, record size: " + recordSize);

        byte[] encryptedData = new byte[recordSize - 16];
        byte[] authTag = new byte[16];
        System.arraycopy(wrapper, 0, encryptedData, 0, encryptedData.length);
        System.arraycopy(wrapper, 0 + recordSize - 16, authTag, 0, authTag.length);

        System.out.println("Record data: " + bytesToHex(recordHeader));
        System.out.println("Encrypted data: " + bytesToHex(encryptedData, 8) + "..." + bytesToHex(encryptedData, encryptedData.length - 8, 8));
        System.out.println("Auth tag: " + bytesToHex(authTag));

        byte[] wrapped = decryptPayload(wrapper, recordHeader, recordCount);
        recordCount++;
        System.out.println("Decrypted data (" + wrapped.length + "): " + bytesToHex(wrapped, 8) + "..." + bytesToHex(wrapped, wrapped.length - 8, 8));
        return wrapped;
    }

    byte[] decryptPayload(byte[] message, byte[] associatedData, int recordNumber) {
        ByteBuffer nonceInput = ByteBuffer.allocate(12);
        nonceInput.putInt(0);
        nonceInput.putLong((long) recordNumber);

        byte[] nonce = new byte[12];
        int i = 0;
        for (byte b : nonceInput.array())
            nonce[i] = (byte) (b ^ serverHandshakeIV[i++]);

        try {
            SecretKeySpec secretKey = new SecretKeySpec(serverHandshakeKey, "AES");
            String AES_GCM_NOPADDING = "AES/GCM/NoPadding";
            Cipher aeadCipher = Cipher.getInstance(AES_GCM_NOPADDING);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, nonce);   // https://tools.ietf.org/html/rfc5116  5.3
            aeadCipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

            aeadCipher.updateAAD(associatedData);
            return aeadCipher.doFinal(message);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException
                | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Crypto error: " + e);
        }
    }

}
