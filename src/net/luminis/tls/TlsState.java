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

    enum Status {
        keyExchangeClient,
        keyExchangeServer,
        ServerParams,
        AuthServer,
        AuthServerFinished,
        AuthClient,
        AuthClientFinished,
        ApplicationData
    }

    private final MessageDigest hashFunction;
    private final HKDF hkdf;
    private final byte[] emptyHash;
    private Status status;
    private String labelPrefix;
    private byte[] serverHello;
    private byte[] serverSharedKey;
    private PrivateKey clientPrivateKey;
    private byte[] clientHello;
    private byte[] earlySecret;
    private byte[] resumptionMasterSecret;
    private byte[] serverHandshakeTrafficSecret;
    private byte[] serverHandshakeKey;
    private byte[] serverHandshakeIV;
    private byte[] clientHandshakeTrafficSecret;
    private byte[] encryptedExtensionsMessage;
    private byte[] certificateMessage;
    private byte[] certificateVerifyMessage;
    private byte[] serverFinishedMessage;
    private byte[] clientFinishedMessage;
    private byte[] clientHandshakeKey;
    private byte[] clientHandshakeIV;
    private byte[] handshakeSecret;
    private byte[] handshakeServerFinishedHash;
    private byte[] handshakeClientFinishedHash;
    private byte[] clientApplicationTrafficSecret;
    private byte[] serverApplicationTrafficSecret;
    private byte[] serverKey;
    private byte[] serverIv;
    private byte[] clientKey;
    private byte[] clientIv;
    private int serverRecordCount = 0;
    private int clientRecordCount = 0;


    public TlsState(String alternativeLabelPrefix) {
        labelPrefix = alternativeLabelPrefix;

        // https://tools.ietf.org/html/rfc8446#section-7.1
        // "The Hash function used by Transcript-Hash and HKDF is the cipher suite hash algorithm."
        try {
            hashFunction = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing sha-256 support");
        }
        hkdf = HKDF.fromHmacSha256();

        emptyHash = hashFunction.digest(new byte[0]);
        Logger.debug("Empty hash: " + bytesToHex(emptyHash));

        computeEarlySecret();
    }

    public TlsState() {
        this("tls13 ");
    }

    private byte[] computeEarlySecret() {
        byte[] zeroSalt = new byte[32];
        byte[] zeroPSK = new byte[32];
        earlySecret = hkdf.extract(zeroSalt, zeroPSK);
        Logger.debug("Early secret: " + bytesToHex(earlySecret));
        return earlySecret;
    }

    private byte[] computeHandshakeMessagesHash(byte[] clientHello, byte[] serverHello) {
        ByteBuffer helloData = ByteBuffer.allocate(clientHello.length + serverHello.length);
        helloData.put(clientHello, 0, clientHello.length);
        helloData.put(serverHello, 0, serverHello.length);

        hashFunction.reset();
        byte[] helloHash = hashFunction.digest(helloData.array());

        Logger.debug("Hello hash: " + bytesToHex(helloHash));
        return helloHash;
    }

    byte[] computeHandshakeFinishedHmac(boolean withClientFinished) {

        hashFunction.reset();
        hashFunction.update(clientHello);
        hashFunction.update(serverHello);
        hashFunction.update(encryptedExtensionsMessage);
        hashFunction.update(certificateMessage);
        hashFunction.update(certificateVerifyMessage);
        hashFunction.update(serverFinishedMessage);
        if (withClientFinished) {
            hashFunction.update(clientFinishedMessage);
            }
        byte[] hash = hashFunction.digest();
        if (withClientFinished) {
            handshakeClientFinishedHash = hash;
        }
        else {
            handshakeServerFinishedHash = hash;
        }

        byte[] finishedKey = hkdfExpandLabel(clientHandshakeTrafficSecret, "finished", "", (short) 32);
        SecretKeySpec hmacKey = new SecretKeySpec(finishedKey, "HmacSHA256");

        try {
            Mac hmacSHA256 = Mac.getInstance("HmacSHA256");
            hmacSHA256.init(hmacKey);
            hmacSHA256.update(handshakeServerFinishedHash);
            byte[] hmac = hmacSHA256.doFinal();
            return hmac;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing (hmac) sha-256 support");
        } catch (InvalidKeyException e) {
            throw new RuntimeException();
        }
    }

    private byte[] computeSharedSecret(byte[] serverSharedKey) {
        ECPublicKey serverPublicKey = convertP256Key(serverSharedKey);

        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(clientPrivateKey);
            keyAgreement.doPhase(serverPublicKey, true);

            SecretKey key = keyAgreement.generateSecret("TlsPremasterSecret");
            Logger.debug("Shared key: " + bytesToHex(key.getEncoded()));
            return key.getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Unsupported crypto: " + e);
        }
    }

    private void computeHandshakeSecrets(byte[] helloHash, byte[] sharedSecret) {
        byte[] derivedSecret = hkdfExpandLabel(earlySecret, "derived", emptyHash, (short) 32);
        Logger.debug("Derived secret: " + bytesToHex(derivedSecret));

        handshakeSecret = hkdf.extract(derivedSecret, sharedSecret);
        Logger.debug("Handshake secret: " + bytesToHex(handshakeSecret));

        clientHandshakeTrafficSecret = hkdfExpandLabel(handshakeSecret, "c hs traffic", helloHash, (short) 32);
        Logger.debug("Client handshake traffic secret: " + bytesToHex(clientHandshakeTrafficSecret));

        serverHandshakeTrafficSecret = hkdfExpandLabel(handshakeSecret, "s hs traffic", helloHash, (short) 32);
        Logger.debug("Server handshake traffic secret: " + bytesToHex(serverHandshakeTrafficSecret));

        clientHandshakeKey = hkdfExpandLabel(clientHandshakeTrafficSecret, "key", "", (short) 16);
        Logger.debug("Client handshake key: " + bytesToHex(clientHandshakeKey));
        clientKey = clientHandshakeKey;

        serverHandshakeKey = hkdfExpandLabel(serverHandshakeTrafficSecret, "key", "", (short) 16);
        Logger.debug("Server handshake key: " + bytesToHex(serverHandshakeKey));
        serverKey = serverHandshakeKey;

        clientHandshakeIV = hkdfExpandLabel(clientHandshakeTrafficSecret, "iv", "", (short) 12);
        Logger.debug("Client handshake iv: " + bytesToHex(clientHandshakeIV));
        clientIv = clientHandshakeIV;

        serverHandshakeIV = hkdfExpandLabel(serverHandshakeTrafficSecret, "iv", "", (short) 12);
        Logger.debug("Server handshake iv: " + bytesToHex(serverHandshakeIV));
        serverIv = serverHandshakeIV;
    }

    public void computeApplicationSecrets() {
        computeApplicationSecrets(handshakeSecret, handshakeServerFinishedHash);
        // Reset record counters
        serverRecordCount = 0;
        clientRecordCount = 0;
    }

    void computeApplicationSecrets(byte[] handshakeSecret, byte[] handshakeHash) {

        byte[] derivedSecret = hkdfExpandLabel(handshakeSecret, "derived", emptyHash, (short) 32);
        Logger.debug("Derived secret: " + bytesToHex(derivedSecret));

        byte[] zeroKey = new byte[32];
        byte[] masterSecret = hkdf.extract(derivedSecret, zeroKey);
        Logger.debug("Master secret: "+ bytesToHex(masterSecret));

        clientApplicationTrafficSecret = hkdfExpandLabel(masterSecret, "c ap traffic", handshakeHash, (short) 32);
        Logger.debug("Client application traffic secret: " + bytesToHex(clientApplicationTrafficSecret));

        serverApplicationTrafficSecret = hkdfExpandLabel(masterSecret, "s ap traffic", handshakeHash, (short) 32);
        Logger.debug("Server application traffic secret: " + bytesToHex(serverApplicationTrafficSecret));

        resumptionMasterSecret = hkdfExpandLabel(masterSecret, "res master", handshakeClientFinishedHash, (short) 32);
        Logger.debug("Resumption master secret: " + bytesToHex(resumptionMasterSecret));

        byte[] clientApplicationKey = hkdfExpandLabel(clientApplicationTrafficSecret, "key", "", (short) 16);
        Logger.debug("Client application key: " + bytesToHex(clientApplicationKey));
        clientKey = clientApplicationKey;

        byte[] serverApplicationKey = hkdfExpandLabel(serverApplicationTrafficSecret, "key", "", (short) 16);
        Logger.debug("Server application key: " + bytesToHex(serverApplicationKey));
        serverKey = serverApplicationKey;

        byte[] clientApplicationIv = hkdfExpandLabel(clientApplicationTrafficSecret, "iv", "", (short) 12);
        Logger.debug("Client application iv: " + bytesToHex(clientApplicationIv));
        clientIv = clientApplicationIv;

        byte[] serverApplicationIv = hkdfExpandLabel(serverApplicationTrafficSecret, "iv", "", (short) 12);
        Logger.debug("Server application iv: " + bytesToHex(serverApplicationIv));
        serverIv = serverApplicationIv;

        status = Status.ApplicationData;
    }

    // https://tools.ietf.org/html/rfc8446#section-4.6.1
    // "The PSK associated with the ticket is computed as:
    //       HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)"
    byte[] computePSK(byte[] ticketNonce) {
        byte[] psk = hkdfExpandLabel(resumptionMasterSecret, "resumption", ticketNonce, (short) 32);
        return psk;
    }

    byte[] hkdfExpandLabel(byte[] secret, String label, String context, short length) {
        return hkdfExpandLabel(secret, label, context.getBytes(ISO_8859_1), length);
    }

    byte[] hkdfExpandLabel(byte[] secret, String label, byte[] context, short length) {
        // See https://tools.ietf.org/html/rfc8446#section-7.1 for definition of HKDF-Expand-Label.
        ByteBuffer hkdfLabel = ByteBuffer.allocate(2 + 1 + labelPrefix.length() + label.getBytes(ISO_8859_1).length + 1 + context.length);
        hkdfLabel.putShort(length);
        hkdfLabel.put((byte) (labelPrefix.length() + label.getBytes().length));
        hkdfLabel.put(labelPrefix.getBytes(ISO_8859_1));
        hkdfLabel.put(label.getBytes(ISO_8859_1));
        hkdfLabel.put((byte) (context.length));
        hkdfLabel.put(context);
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

    byte[] decrypt(byte[] recordHeader, byte[] payload) {
        int recordSize = (recordHeader[3] & 0xff) << 8 | (recordHeader[4] & 0xff);
        Logger.debug("Payload length: " + payload.length + " bytes, size in record: " + recordSize);

        byte[] encryptedData = new byte[recordSize - 16];
        byte[] authTag = new byte[16];
        System.arraycopy(payload, 0, encryptedData, 0, encryptedData.length);
        System.arraycopy(payload, 0 + recordSize - 16, authTag, 0, authTag.length);

        Logger.debug("Record data: " + bytesToHex(recordHeader));
        Logger.debug("Encrypted data: " + bytesToHex(encryptedData, Math.min(8, encryptedData.length))
                + "..." + bytesToHex(encryptedData, Math.max(encryptedData.length - 8, 0), Math.min(8, encryptedData.length)));
        Logger.debug("Auth tag: " + bytesToHex(authTag));

        byte[] wrapped = decryptPayload(payload, recordHeader, serverRecordCount);
        serverRecordCount++;
        Logger.debug("Decrypted data (" + wrapped.length + "): " + bytesToHex(wrapped, Math.min(8, wrapped.length))
                + "..." + bytesToHex(wrapped, Math.max(wrapped.length - 8, 0), Math.min(8, wrapped.length)));
        return wrapped;
    }

    byte[] decryptPayload(byte[] message, byte[] associatedData, int recordNumber) {
        ByteBuffer nonceInput = ByteBuffer.allocate(12);
        nonceInput.putInt(0);
        nonceInput.putLong((long) recordNumber);

        byte[] nonce = new byte[12];
        int i = 0;
        for (byte b : nonceInput.array())
            nonce[i] = (byte) (b ^ serverIv[i++]);

        try {
            SecretKeySpec secretKey = new SecretKeySpec(serverKey, "AES");
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

    byte[] encryptPayload(byte[] message, byte[] associatedData) {
        ByteBuffer nonceInput = ByteBuffer.allocate(12);
        nonceInput.putInt(0);
        nonceInput.putLong((long) clientRecordCount);

        byte[] nonce = new byte[12];
        int i = 0;
        for (byte b : nonceInput.array())
            nonce[i] = (byte) (b ^ clientIv[i++]);

        try {
            SecretKeySpec secretKey = new SecretKeySpec(clientKey, "AES");
            String AES_GCM_NOPADDING = "AES/GCM/NoPadding";
            Cipher aeadCipher = Cipher.getInstance(AES_GCM_NOPADDING);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, nonce);   // https://tools.ietf.org/html/rfc5116  5.3
            aeadCipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

            aeadCipher.updateAAD(associatedData);
            return aeadCipher.doFinal(message);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException
                | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Crypto error: " + e);
        }
    }

    public byte[] getClientHandshakeTrafficSecret() {
        return clientHandshakeTrafficSecret;
    }

    public byte[] getServerHandshakeTrafficSecret() {
        return serverHandshakeTrafficSecret;
    }

    public byte[] getClientApplicationTrafficSecret() {
        return clientApplicationTrafficSecret;
    }

    public byte[] getServerApplicationTrafficSecret() {
        return serverApplicationTrafficSecret;
    }

    public void clientHelloSend(PrivateKey clientPrivateKey, byte[] sentClientHello) {
        this.clientPrivateKey = clientPrivateKey;
        clientHello = sentClientHello;
    }

    public void setServerSharedKey(byte[] serverHello, byte[] serverSharedKey) {
        this.serverHello = serverHello;
        this.serverSharedKey = serverSharedKey;

        byte[] handshakeHash = computeHandshakeMessagesHash(clientHello, serverHello);

        byte[] sharedSecret = computeSharedSecret(serverSharedKey);

        computeHandshakeSecrets(handshakeHash, sharedSecret);
    }

    public void setEncryptedExtensions(byte[] raw) {
        encryptedExtensionsMessage = raw;
    }

    public void setCertificate(byte[] raw) {
        certificateMessage = raw;
    }

    public void setCertificateVerify(byte[] raw) {
        certificateVerifyMessage = raw;
    }

    public void setServerFinished(byte[] raw) {
        serverFinishedMessage = raw;
        status = Status.AuthServerFinished;
    }

    public boolean isServerFinished() {
        return status == Status.AuthServerFinished;
    }

    public void setClientFinished(byte[] raw) {
        clientFinishedMessage = raw;
        computeHandshakeFinishedHmac(true);
    }
}
