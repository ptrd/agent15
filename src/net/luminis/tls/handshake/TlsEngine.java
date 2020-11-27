package net.luminis.tls.handshake;

import net.luminis.tls.TlsConstants;
import net.luminis.tls.TlsState;
import net.luminis.tls.TrafficSecrets;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;

import static net.luminis.tls.TlsConstants.NamedGroup.*;

public abstract class TlsEngine implements MessageProcessor, TrafficSecrets {

    protected PublicKey publicKey;
    protected PrivateKey privateKey;
    protected TlsState state;

    public abstract TlsConstants.CipherSuite getSelectedCipher();


    protected void generateKeys(TlsConstants.NamedGroup namedGroup) {
        try {
            KeyPairGenerator keyPairGenerator;
            if (namedGroup == secp256r1 || namedGroup == secp384r1 || namedGroup == secp521r1) {
                keyPairGenerator = KeyPairGenerator.getInstance("EC");
                keyPairGenerator.initialize(new ECGenParameterSpec(namedGroup.toString()));
            }
            else if (namedGroup == x25519 || namedGroup == x448) {
                keyPairGenerator = KeyPairGenerator.getInstance("XDH");
                NamedParameterSpec paramSpec = new NamedParameterSpec(namedGroup.toString().toUpperCase());  // x25519 => X25519
                keyPairGenerator.initialize(paramSpec);
            }
            else {
                throw new RuntimeException("unsupported group " + namedGroup);
            }

            KeyPair keyPair = keyPairGenerator.genKeyPair();
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();
        } catch (NoSuchAlgorithmException e) {
            // Invalid runtime
            throw new RuntimeException("missing key pair generator algorithm EC");
        } catch (InvalidAlgorithmParameterException e) {
            // Impossible, would be programming error
            throw new RuntimeException();
        }
    }

    // https://tools.ietf.org/html/rfc8446#section-4.4.4
    protected byte[] computeFinishedVerifyData(byte[] transcriptHash, byte[] baseKey) {
        short hashLength = state.getHashLength();
        byte[] finishedKey = state.hkdfExpandLabel(baseKey, "finished", "", hashLength);
        String macAlgorithmName = "HmacSHA" + (hashLength * 8);
        SecretKeySpec hmacKey = new SecretKeySpec(finishedKey, macAlgorithmName);

        try {
            Mac hmacAlgorithm = Mac.getInstance(macAlgorithmName);
            hmacAlgorithm.init(hmacKey);
            hmacAlgorithm.update(transcriptHash);
            byte[] hmac = hmacAlgorithm.doFinal();
            return hmac;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing " + macAlgorithmName + " support");
        } catch (InvalidKeyException e) {
            throw new RuntimeException();
        }
    }

    public byte[] getClientEarlyTrafficSecret() {
        if (state != null) {
            return state.getClientEarlyTrafficSecret();
        }
        else {
            throw new IllegalStateException("Traffic secret not yet available");
        }
    }

    public byte[] getClientHandshakeTrafficSecret() {
        if (state != null) {
            return state.getClientHandshakeTrafficSecret();
        }
        else {
            throw new IllegalStateException("Traffic secret not yet available");
        }
    }

    public byte[] getServerHandshakeTrafficSecret() {
        if (state != null) {
            return state.getServerHandshakeTrafficSecret();
        }
        else {
            throw new IllegalStateException("Traffic secret not yet available");
        }
    }

    public byte[] getClientApplicationTrafficSecret() {
        if (state != null) {
            return state.getClientApplicationTrafficSecret();
        }
        else {
            throw new IllegalStateException("Traffic secret not yet available");
        }
    }

    public byte[] getServerApplicationTrafficSecret() {
        if (state != null) {
            return state.getServerApplicationTrafficSecret();
        }
        else {
            throw new IllegalStateException("Traffic secret not yet available");
        }
    }

}

