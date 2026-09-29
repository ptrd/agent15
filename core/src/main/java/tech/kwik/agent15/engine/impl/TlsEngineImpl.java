/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
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
package tech.kwik.agent15.engine.impl;

import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.alert.ErrorAlert;
import tech.kwik.agent15.alert.HandshakeFailureAlert;
import tech.kwik.agent15.engine.SignatureAlgorithm;
import tech.kwik.agent15.engine.SignatureAlgorithmFactory;
import tech.kwik.agent15.engine.TlsEngine;
import tech.kwik.agent15.extension.Extension;
import tech.kwik.agent15.extension.UnknownExtension;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;

public abstract class TlsEngineImpl implements TlsEngine {

    protected TlsState state;
    protected final SignatureAlgorithmFactory signatureAlgorithmFactory;

    public TlsEngineImpl(SignatureAlgorithmFactory signatureAlgorithmFactory) {
        this.signatureAlgorithmFactory = signatureAlgorithmFactory;
    }

    public abstract TlsConstants.CipherSuite getSelectedCipher();

    public static int hashLength(TlsConstants.CipherSuite cipher) {
        switch (cipher) {
            case TLS_AES_128_GCM_SHA256:
                return 256 / 8;
            case TLS_AES_256_GCM_SHA384:
                return 384 / 8;
            case TLS_CHACHA20_POLY1305_SHA256:
                return 256 / 8;
            case TLS_AES_128_CCM_SHA256:
                return 256 / 8;
            case TLS_AES_128_CCM_8_SHA256:
                return 256 / 8;
            default:
                // Impossible, as all enum values are covered
                throw new RuntimeException();
        }
    }

    public static int keyLength(TlsConstants.CipherSuite cipher) {
        switch (cipher) {
            case TLS_AES_128_GCM_SHA256:
                return 128 / 8;
            case TLS_AES_256_GCM_SHA384:
                return 256 / 8;
            case TLS_CHACHA20_POLY1305_SHA256:
                return 256 / 8;
            case TLS_AES_128_CCM_SHA256:
                return 128 / 8;
            case TLS_AES_128_CCM_8_SHA256:
                return 128 / 8;
            default:
                // Impossible, as all enum values are covered
                throw new RuntimeException();
        }
    }

    /**
     * Compute the signature used in certificate verify message to proof possession of private key.
     * @param content  the content to be signed (transcript hash)
     * @param certificatePrivateKey  the private key associated with the certificate
     * @param signatureScheme
     * @param client  whether the signature must be computed
     * @return
     */
    protected byte[] computeSignature(byte[] content, PrivateKey certificatePrivateKey, TlsConstants.SignatureScheme signatureScheme, boolean client) throws ErrorAlert {
        // https://tools.ietf.org/html/rfc8446#section-4.4.3

        //   The digital signature is then computed over the concatenation of:
        //   -  A string that consists of octet 32 (0x20) repeated 64 times
        //   -  The context string
        //   -  A single 0 byte which serves as the separator
        //   -  The content to be signed"
        ByteArrayOutputStream signatureInput = new ByteArrayOutputStream();
        try {
            signatureInput.write(new String(new byte[] { 0x20 }).repeat(64).getBytes(StandardCharsets.US_ASCII));
            String contextString = "TLS 1.3, " + (client? "client": "server") + " CertificateVerify";
            signatureInput.write(contextString.getBytes(StandardCharsets.US_ASCII));
            signatureInput.write(0x00);
            signatureInput.write(content);
        }
        catch (IOException e) {
            // Impossible
            throw new RuntimeException();
        }

        return getSignatureAlgorithm(signatureScheme).sign(signatureInput.toByteArray(), certificatePrivateKey);
    }

    /**
     * Returns the signature algorithm implementing the given signature scheme.
     * @param signatureScheme
     * @return  the signature algorithm, never null
     * @throws HandshakeFailureAlert  when the scheme is not supported (i.e. no factory provides an implementation)
     */
    protected SignatureAlgorithm getSignatureAlgorithm(TlsConstants.SignatureScheme signatureScheme) throws HandshakeFailureAlert {
        SignatureAlgorithm signatureAlgorithm = signatureAlgorithmFactory.forSignatureScheme(signatureScheme);
        if (signatureAlgorithm == null) {
            // Bad luck, not (yet) supported.
            throw new HandshakeFailureAlert("Signature algorithm not supported " + signatureScheme);
        }
        return signatureAlgorithm;
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

    @Override
    public byte[] getClientEarlyTrafficSecret() {
        if (state != null) {
            return state.getClientEarlyTrafficSecret();
        }
        else {
            throw new IllegalStateException("Traffic secret not yet available");
        }
    }

    @Override
    public byte[] getClientHandshakeTrafficSecret() {
        if (state != null) {
            return state.getClientHandshakeTrafficSecret();
        }
        else {
            throw new IllegalStateException("Traffic secret not yet available");
        }
    }

    @Override
    public byte[] getServerHandshakeTrafficSecret() {
        if (state != null) {
            return state.getServerHandshakeTrafficSecret();
        }
        else {
            throw new IllegalStateException("Traffic secret not yet available");
        }
    }

    @Override
    public byte[] getClientApplicationTrafficSecret() {
        if (state != null) {
            return state.getClientApplicationTrafficSecret();
        }
        else {
            throw new IllegalStateException("Traffic secret not yet available");
        }
    }

    @Override
    public byte[] getServerApplicationTrafficSecret() {
        if (state != null) {
            return state.getServerApplicationTrafficSecret();
        }
        else {
            throw new IllegalStateException("Traffic secret not yet available");
        }
    }

    protected boolean recognizedExtension(Extension extension) {
        return ! (extension instanceof UnknownExtension);
    }
}
