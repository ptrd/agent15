/*
 * Copyright © 2026 Peter Doornbosch, Chris Burdess
 *
 * This file is part of Agent15, an implementation of TLS 1.3 in Java.
 *
 * Agent15 is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Agent15 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package tech.kwik.agent15.pqc;

import tech.kwik.agent15.alert.IllegalParameterAlert;
import tech.kwik.agent15.engine.KeyExchange;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * ML-KEM key exchange (FIPS 203), using the JDK's own KEM API
 * (javax.crypto.KEM). Common base for MLKEM768KeyExchange and
 * MLKEM1024KeyExchange -- the two parameter sets RFC 10024's hybrid
 * groups actually use -- which differ only in algorithm name and the
 * three fixed lengths below.
 *
 * <p>The JDK only exposes ML-KEM keys as X.509/PKCS#8-encoded PublicKey/
 * PrivateKey objects; there is no supported API to obtain or reconstruct
 * the raw encapsulation-key bytes the TLS key_share extension actually
 * carries (the concrete implementation class does have a getRawBytes()
 * method, but it is on the internal sun.security.x509.NamedX509Key, not
 * on any exported interface, so it is not used here). Instead, the fixed
 * DER envelope around the raw key is stripped/rebuilt using only the
 * standard PublicKey/KeyFactory/X509EncodedKeySpec API. The envelope
 * bytes are derived once per algorithm from a throwaway key pair rather
 * than hardcoded, so they can't silently drift from whatever this JVM's
 * provider actually produces -- each concrete subclass computes and
 * caches its own (the prefix differs by algorithm, so it can't live as
 * a single static field on this shared base).
 *
 * <p>The ciphertext (KEM.Encapsulated#encapsulation()) and shared secret
 * (KEM.Encapsulated#key()/KEM.Decapsulator's result, both symmetric
 * SecretKeys) need no such handling: their getEncoded() already returns
 * raw bytes with no ASN.1 wrapping.
 */
public abstract class MLKEMKeyExchange implements KeyExchange {

    public static final int SHARED_SECRET_LENGTH = 32;

    protected static byte[] computePublicKeyDerPrefix(String algorithm, int encapsulationKeyLength) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
            byte[] encoded = keyPairGenerator.generateKeyPair().getPublic().getEncoded();
            return Arrays.copyOfRange(encoded, 0, encoded.length - encapsulationKeyLength);
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("missing " + algorithm + " support", e);
        }
    }

    private final String algorithm;
    private final int encapsulationKeyLength;
    private final int ciphertextLength;
    private final byte[] publicKeyDerPrefix;

    private PrivateKey decapsulationKey;
    private PublicKey encapsulationKey;
    private byte[] serverKeyShare;

    protected MLKEMKeyExchange(String algorithm, int encapsulationKeyLength, int ciphertextLength, byte[] publicKeyDerPrefix) {
        this.algorithm = algorithm;
        this.encapsulationKeyLength = encapsulationKeyLength;
        this.ciphertextLength = ciphertextLength;
        this.publicKeyDerPrefix = publicKeyDerPrefix;
    }

    @Override
    public void generateClientKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            decapsulationKey = keyPair.getPrivate();
            encapsulationKey = keyPair.getPublic();
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("missing " + algorithm + " support", e);
        }
    }

    @Override
    public byte[] getClientKeyShare() {
        byte[] encoded = encapsulationKey.getEncoded();
        return Arrays.copyOfRange(encoded, encoded.length - encapsulationKeyLength, encoded.length);
    }

    @Override
    public byte[] clientComputeSharedSecret(byte[] serverKeyShare) throws IllegalParameterAlert {
        if (serverKeyShare.length != ciphertextLength) {
            throw new IllegalParameterAlert("invalid " + algorithm + " ciphertext length: " + serverKeyShare.length);
        }
        try {
            KEM kem = KEM.getInstance(algorithm);
            KEM.Decapsulator decapsulator = kem.newDecapsulator(decapsulationKey);
            return decapsulator.decapsulate(serverKeyShare).getEncoded();
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("missing " + algorithm + " support", e);
        }
        catch (InvalidKeyException e) {
            // decapsulationKey is our own, freshly generated key, not peer-controlled.
            throw new RuntimeException("invalid own " + algorithm + " decapsulation key", e);
        }
        catch (DecapsulateException e) {
            throw new IllegalParameterAlert("invalid " + algorithm + " ciphertext: " + e.getMessage());
        }
    }

    @Override
    public byte[] serverProcessClientKeyShare(byte[] clientKeyShare) throws IllegalParameterAlert {
        if (clientKeyShare.length != encapsulationKeyLength) {
            throw new IllegalParameterAlert("invalid " + algorithm + " encapsulation key length: " + clientKeyShare.length);
        }
        try {
            byte[] encoded = new byte[publicKeyDerPrefix.length + clientKeyShare.length];
            System.arraycopy(publicKeyDerPrefix, 0, encoded, 0, publicKeyDerPrefix.length);
            System.arraycopy(clientKeyShare, 0, encoded, publicKeyDerPrefix.length, clientKeyShare.length);
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            PublicKey peerEncapsulationKey = keyFactory.generatePublic(new X509EncodedKeySpec(encoded));

            KEM kem = KEM.getInstance(algorithm);
            KEM.Encapsulator encapsulator = kem.newEncapsulator(peerEncapsulationKey);
            KEM.Encapsulated encapsulated = encapsulator.encapsulate();
            serverKeyShare = encapsulated.encapsulation();
            return encapsulated.key().getEncoded();
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("missing " + algorithm + " support", e);
        }
        catch (InvalidKeySpecException e) {
            throw new IllegalParameterAlert("invalid " + algorithm + " encapsulation key encoding: " + e.getMessage());
        }
        catch (InvalidKeyException e) {
            throw new IllegalParameterAlert("invalid " + algorithm + " encapsulation key: " + e.getMessage());
        }
    }

    @Override
    public byte[] getServerKeyShare() {
        if (serverKeyShare == null) {
            throw new IllegalStateException("serverProcessClientKeyShare() must be called before getServerKeyShare()");
        }
        return serverKeyShare;
    }
}
