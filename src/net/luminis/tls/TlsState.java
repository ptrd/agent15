package net.luminis.tls;

import at.favre.lib.crypto.HKDF;
import at.favre.lib.crypto.HkdfMacFactory;

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

    private static String labelPrefix = "tls13 ";

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
    private final short authenticationTagLength = 16;
    private final short keyLength = 16;   // Assuming AES-128, use 32 for AES-256
    private final short hashLength = 32;  // Assuming SHA-256, use 48 for SHA-384
    private final short iv_length = 12;
    private Status status;
    private boolean pskSelected;
    private PublicKey serverSharedKey;
    private PrivateKey clientPrivateKey;
    private final byte[] psk;
    private byte[] earlySecret;
    private byte[] binderKey;
    private byte[] resumptionMasterSecret;
    private byte[] serverHandshakeTrafficSecret;
    private byte[] clientEarlyTrafficSecret;
    private byte[] clientHandshakeTrafficSecret;
    private byte[] handshakeSecret;
    private byte[] clientApplicationTrafficSecret;
    private byte[] serverApplicationTrafficSecret;
    private byte[] serverKey;
    private byte[] serverIv;
    private byte[] clientKey;
    private byte[] clientIv;
    private int serverRecordCount = 0;
    private int clientRecordCount = 0;
    private final TranscriptHash transcriptHash;

    public TlsState(TranscriptHash transcriptHash, byte[] psk) {
        this.psk = psk;
        this.transcriptHash = transcriptHash;

        // https://tools.ietf.org/html/rfc8446#section-7.1
        // "The Hash function used by Transcript-Hash and HKDF is the cipher suite hash algorithm."
        String hashAlgorithm = "SHA-" + (hashLength * 8);
        try {
            hashFunction = MessageDigest.getInstance(hashAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing " + hashAlgorithm + " support");
        }
        String macAlgorithm = "HmacSHA" + (hashLength * 8);
        hkdf = HKDF.from(new HkdfMacFactory.Default(macAlgorithm, null));

        emptyHash = hashFunction.digest(new byte[0]);
        Logger.debug("Empty hash: " + bytesToHex(emptyHash));

        if (psk == null) {
            // https://tools.ietf.org/html/rfc8446#section-7.1
            // "If a given secret is not available, then the 0-value consisting of a
            //   string of Hash.length bytes set to zeros is used."
            psk = new byte[hashLength];
        }
        computeEarlySecret(psk);
    }

    public TlsState(TranscriptHash transcriptHash) {
        this(transcriptHash, null);
    }

    private byte[] computeEarlySecret(byte[] ikm) {
        byte[] zeroSalt = new byte[hashLength];
        earlySecret = hkdf.extract(zeroSalt, ikm);
        Logger.debug("Early secret: " + bytesToHex(earlySecret));

        binderKey = hkdfExpandLabel(earlySecret, "res binder", emptyHash, hashLength);
        Logger.debug("Binder key: " + bytesToHex(binderKey));

        return earlySecret;
    }

    byte[] computePskBinder(byte[] partialClientHello) {
        String macAlgorithmName = "HmacSHA" + (hashLength * 8);
        try {
            hashFunction.reset();
            hashFunction.update(partialClientHello);
            byte[] hash = hashFunction.digest();

            byte[] finishedKey = hkdfExpandLabel(binderKey, "finished", "", hashLength);
            SecretKeySpec hmacKey = new SecretKeySpec(finishedKey, macAlgorithmName);

            Mac hmacAlgorithm = Mac.getInstance(macAlgorithmName);
            hmacAlgorithm.init(hmacKey);
            hmacAlgorithm.update(hash);
            byte[] hmac = hmacAlgorithm.doFinal();
            return hmac;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing " + macAlgorithmName + " support");
        } catch (InvalidKeyException e) {
            throw new RuntimeException();
        }
    }

    private byte[] computeSharedSecret(PublicKey serverSharedKey) {
        ECPublicKey serverPublicKey = (ECPublicKey) serverSharedKey;

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

    private void computeEarlyTrafficSecret(byte[] clientHelloHash) {
        clientEarlyTrafficSecret = hkdfExpandLabel(earlySecret, "c e traffic", clientHelloHash, hashLength);
    }

    private void computeHandshakeSecrets(byte[] helloHash, byte[] sharedSecret) {
        byte[] derivedSecret = hkdfExpandLabel(earlySecret, "derived", emptyHash, hashLength);
        Logger.debug("Derived secret: " + bytesToHex(derivedSecret));

        handshakeSecret = hkdf.extract(derivedSecret, sharedSecret);
        Logger.debug("Handshake secret: " + bytesToHex(handshakeSecret));

        clientHandshakeTrafficSecret = hkdfExpandLabel(handshakeSecret, "c hs traffic", helloHash, hashLength);
        Logger.debug("Client handshake traffic secret: " + bytesToHex(clientHandshakeTrafficSecret));

        serverHandshakeTrafficSecret = hkdfExpandLabel(handshakeSecret, "s hs traffic", helloHash, hashLength);
        Logger.debug("Server handshake traffic secret: " + bytesToHex(serverHandshakeTrafficSecret));

        byte[] clientHandshakeKey = hkdfExpandLabel(clientHandshakeTrafficSecret, "key", "", keyLength);
        Logger.debug("Client handshake key: " + bytesToHex(clientHandshakeKey));
        clientKey = clientHandshakeKey;

        byte[] serverHandshakeKey = hkdfExpandLabel(serverHandshakeTrafficSecret, "key", "", keyLength);
        Logger.debug("Server handshake key: " + bytesToHex(serverHandshakeKey));
        serverKey = serverHandshakeKey;

        byte[] clientHandshakeIV = hkdfExpandLabel(clientHandshakeTrafficSecret, "iv", "", iv_length);
        Logger.debug("Client handshake iv: " + bytesToHex(clientHandshakeIV));
        clientIv = clientHandshakeIV;

        byte[] serverHandshakeIV = hkdfExpandLabel(serverHandshakeTrafficSecret, "iv", "", iv_length);
        Logger.debug("Server handshake iv: " + bytesToHex(serverHandshakeIV));
        serverIv = serverHandshakeIV;
    }

    public void computeApplicationSecrets() {
        computeApplicationSecrets(handshakeSecret);

        // Reset record counters
        serverRecordCount = 0;
        clientRecordCount = 0;
    }

    void computeApplicationSecrets(byte[] handshakeSecret) {
        byte[] serverFinishedHash = transcriptHash.getServerHash(TlsConstants.HandshakeType.finished);
        byte[] clientFinishedHash = transcriptHash.getClientHash(TlsConstants.HandshakeType.finished);

        byte[] derivedSecret = hkdfExpandLabel(handshakeSecret, "derived", emptyHash, hashLength);
        Logger.debug("Derived secret: " + bytesToHex(derivedSecret));

        byte[] zeroKey = new byte[hashLength];
        byte[] masterSecret = hkdf.extract(derivedSecret, zeroKey);
        Logger.debug("Master secret: "+ bytesToHex(masterSecret));

        clientApplicationTrafficSecret = hkdfExpandLabel(masterSecret, "c ap traffic", serverFinishedHash, hashLength);
        Logger.debug("Client application traffic secret: " + bytesToHex(clientApplicationTrafficSecret));

        serverApplicationTrafficSecret = hkdfExpandLabel(masterSecret, "s ap traffic", serverFinishedHash, hashLength);
        Logger.debug("Server application traffic secret: " + bytesToHex(serverApplicationTrafficSecret));

        resumptionMasterSecret = hkdfExpandLabel(masterSecret, "res master", clientFinishedHash, hashLength);
        Logger.debug("Resumption master secret: " + bytesToHex(resumptionMasterSecret));

        byte[] clientApplicationKey = hkdfExpandLabel(clientApplicationTrafficSecret, "key", "", keyLength);
        Logger.debug("Client application key: " + bytesToHex(clientApplicationKey));
        clientKey = clientApplicationKey;

        byte[] serverApplicationKey = hkdfExpandLabel(serverApplicationTrafficSecret, "key", "", keyLength);
        Logger.debug("Server application key: " + bytesToHex(serverApplicationKey));
        serverKey = serverApplicationKey;

        byte[] clientApplicationIv = hkdfExpandLabel(clientApplicationTrafficSecret, "iv", "", iv_length);
        Logger.debug("Client application iv: " + bytesToHex(clientApplicationIv));
        clientIv = clientApplicationIv;

        byte[] serverApplicationIv = hkdfExpandLabel(serverApplicationTrafficSecret, "iv", "", iv_length);
        Logger.debug("Server application iv: " + bytesToHex(serverApplicationIv));
        serverIv = serverApplicationIv;

        status = Status.ApplicationData;
    }

    // https://tools.ietf.org/html/rfc8446#section-4.6.1
    // "The PSK associated with the ticket is computed as:
    //       HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)"
    byte[] computePSK(byte[] ticketNonce) {
        byte[] psk = hkdfExpandLabel(resumptionMasterSecret, "resumption", ticketNonce, hashLength);
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
        ByteBuffer nonceInput = ByteBuffer.allocate(iv_length);
        nonceInput.putInt(0);
        nonceInput.putLong((long) recordNumber);

        byte[] nonce = new byte[iv_length];
        int i = 0;
        for (byte b : nonceInput.array())
            nonce[i] = (byte) (b ^ serverIv[i++]);

        try {
            SecretKeySpec secretKey = new SecretKeySpec(serverKey, "AES");
            String AES_GCM_NOPADDING = "AES/GCM/NoPadding";
            Cipher aeadCipher = Cipher.getInstance(AES_GCM_NOPADDING);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(authenticationTagLength * 8, nonce);
            aeadCipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

            aeadCipher.updateAAD(associatedData);
            return aeadCipher.doFinal(message);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException
                | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Crypto error: " + e);
        }
    }

    byte[] encryptPayload(byte[] message, byte[] associatedData) {
        ByteBuffer nonceInput = ByteBuffer.allocate(iv_length);
        nonceInput.putInt(0);
        nonceInput.putLong((long) clientRecordCount);

        byte[] nonce = new byte[iv_length];
        int i = 0;
        for (byte b : nonceInput.array())
            nonce[i] = (byte) (b ^ clientIv[i++]);

        try {
            SecretKeySpec secretKey = new SecretKeySpec(clientKey, "AES");
            String AES_GCM_NOPADDING = "AES/GCM/NoPadding";
            Cipher aeadCipher = Cipher.getInstance(AES_GCM_NOPADDING);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(authenticationTagLength * 8, nonce);
            aeadCipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

            aeadCipher.updateAAD(associatedData);
            return aeadCipher.doFinal(message);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException
                | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Crypto error: " + e);
        }
    }

    public short getHashLength() {
        return hashLength;
    }

    public byte[] getClientEarlyTrafficSecret() {
        return clientEarlyTrafficSecret;
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
        byte[] clientHelloHash = transcriptHash.getHash(TlsConstants.HandshakeType.client_hello);
        computeEarlyTrafficSecret(clientHelloHash);
    }

    public void setPskSelected(int selectedIdentity) {
        pskSelected = true;
    }

    public void setServerSharedKey(PublicKey serverSharedKey) {
        if (psk != null && !pskSelected) {
            // Recompute early secret, as psk is not accepted by server.
            // https://tools.ietf.org/html/rfc8446#section-7.1
            // "... if no PSK is selected, it will then need to compute the Early Secret corresponding to the zero PSK."
            computeEarlySecret(new byte[hashLength]);
        }
        this.serverSharedKey = serverSharedKey;
    }

    public void serverHelloReceived(byte[] serverHello) {
        byte[] handshakeHash = transcriptHash.getHash(TlsConstants.HandshakeType.server_hello);
        byte[] sharedSecret = computeSharedSecret(serverSharedKey);
        computeHandshakeSecrets(handshakeHash, sharedSecret);
    }

    public void setServerFinished(byte[] raw) {
        status = Status.AuthServerFinished;
    }

    public boolean isServerFinished() {
        return status == Status.AuthServerFinished;
    }

}
