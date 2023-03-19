/*
 * Copyright © 2019, 2020, 2021, 2022, 2023 Peter Doornbosch
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
package net.luminis.tls;

import at.favre.lib.crypto.HKDF;
import at.favre.lib.crypto.HkdfMacFactory;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.XECPublicKey;

import static net.luminis.tls.util.ByteUtils.bytesToHex;


public class TlsState {

    private static final Charset ISO_8859_1 = Charset.forName("ISO-8859-1");

    private static String labelPrefix = "tls13 ";

    private final MessageDigest hashFunction;
    private final HKDF hkdf;
    private final byte[] emptyHash;
    private final short keyLength;
    private final short hashLength;
    private final short iv_length = 12;
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
    private final TranscriptHash transcriptHash;
    private byte[] sharedSecret;
    private byte[] masterSecret;

    public TlsState(TranscriptHash transcriptHash, byte[] psk, int keyLength, int hashLength) {
        this.psk = psk;
        this.transcriptHash = transcriptHash;
        this.keyLength = (short) keyLength;
        this.hashLength = (short) hashLength;

        // https://tools.ietf.org/html/rfc8446#section-7.1
        // "The Hash function used by Transcript-Hash and HKDF is the cipher suite hash algorithm."
        String hashAlgorithm = "SHA-" + (this.hashLength * 8);
        try {
            hashFunction = MessageDigest.getInstance(hashAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing " + hashAlgorithm + " support");
        }
        String macAlgorithm = "HmacSHA" + (this.hashLength * 8);
        hkdf = HKDF.from(new HkdfMacFactory.Default(macAlgorithm, null));

        emptyHash = hashFunction.digest(new byte[0]);
        Logger.debug("Empty hash: " + bytesToHex(emptyHash));

        if (psk == null) {
            // https://tools.ietf.org/html/rfc8446#section-7.1
            // "If a given secret is not available, then the 0-value consisting of a
            //   string of Hash.length bytes set to zeros is used."
            psk = new byte[this.hashLength];
        }
        computeEarlySecret(psk);
    }

    public TlsState(TranscriptHash transcriptHash, int keyLength, int hashLength) {
        this(transcriptHash, null, keyLength, hashLength);
    }

    private byte[] computeEarlySecret(byte[] ikm) {
        byte[] zeroSalt = new byte[hashLength];
        earlySecret = hkdf.extract(zeroSalt, ikm);
        Logger.debug("Early secret: " + bytesToHex(earlySecret));

        binderKey = hkdfExpandLabel(earlySecret, "res binder", emptyHash, hashLength);
        Logger.debug("Binder key: " + bytesToHex(binderKey));

        return earlySecret;
    }

    public byte[] computePskBinder(byte[] partialClientHello) {
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

    public void computeSharedSecret() {
        try {
            KeyAgreement keyAgreement;
            if (serverSharedKey instanceof ECPublicKey) {
                keyAgreement = KeyAgreement.getInstance("ECDH");
            }
            else if (serverSharedKey instanceof XECPublicKey) {
                keyAgreement = KeyAgreement.getInstance("XDH");
            }
            else {
                throw new RuntimeException("Unsupported key type");
            }

            keyAgreement.init(clientPrivateKey);
            keyAgreement.doPhase(serverSharedKey, true);

            sharedSecret = keyAgreement.generateSecret();
            Logger.debug("Shared key: " + bytesToHex(sharedSecret));
        }
        catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Unsupported crypto: " + e);
        }
    }

    public void computeEarlyTrafficSecret() {
        byte[] clientHelloHash = transcriptHash.getHash(TlsConstants.HandshakeType.client_hello);

        clientEarlyTrafficSecret = hkdfExpandLabel(earlySecret, "c e traffic", clientHelloHash, hashLength);
    }

    public void computeHandshakeSecrets() {
        byte[] derivedSecret = hkdfExpandLabel(earlySecret, "derived", emptyHash, hashLength);
        Logger.debug("Derived secret: " + bytesToHex(derivedSecret));

        handshakeSecret = hkdf.extract(derivedSecret, sharedSecret);
        Logger.debug("Handshake secret: " + bytesToHex(handshakeSecret));

        byte[] handshakeHash = transcriptHash.getHash(TlsConstants.HandshakeType.server_hello);

        clientHandshakeTrafficSecret = hkdfExpandLabel(handshakeSecret, "c hs traffic", handshakeHash, hashLength);
        Logger.debug("Client handshake traffic secret: " + bytesToHex(clientHandshakeTrafficSecret));

        serverHandshakeTrafficSecret = hkdfExpandLabel(handshakeSecret, "s hs traffic", handshakeHash, hashLength);
        Logger.debug("Server handshake traffic secret: " + bytesToHex(serverHandshakeTrafficSecret));

        byte[] clientHandshakeKey = hkdfExpandLabel(clientHandshakeTrafficSecret, "key", "", keyLength);
        Logger.debug("Client handshake key: " + bytesToHex(clientHandshakeKey));

        byte[] serverHandshakeKey = hkdfExpandLabel(serverHandshakeTrafficSecret, "key", "", keyLength);
        Logger.debug("Server handshake key: " + bytesToHex(serverHandshakeKey));

        byte[] clientHandshakeIV = hkdfExpandLabel(clientHandshakeTrafficSecret, "iv", "", iv_length);
        Logger.debug("Client handshake iv: " + bytesToHex(clientHandshakeIV));

        byte[] serverHandshakeIV = hkdfExpandLabel(serverHandshakeTrafficSecret, "iv", "", iv_length);
        Logger.debug("Server handshake iv: " + bytesToHex(serverHandshakeIV));
    }

    public void computeApplicationSecrets() {
        computeApplicationSecrets(handshakeSecret);
    }

    void computeApplicationSecrets(byte[] handshakeSecret) {
        byte[] serverFinishedHash = transcriptHash.getServerHash(TlsConstants.HandshakeType.finished);

        byte[] derivedSecret = hkdfExpandLabel(handshakeSecret, "derived", emptyHash, hashLength);
        Logger.debug("Derived secret: " + bytesToHex(derivedSecret));

        byte[] zeroKey = new byte[hashLength];
        masterSecret = hkdf.extract(derivedSecret, zeroKey);
        Logger.debug("Master secret: "+ bytesToHex(masterSecret));

        clientApplicationTrafficSecret = hkdfExpandLabel(masterSecret, "c ap traffic", serverFinishedHash, hashLength);
        Logger.debug("Client application traffic secret: " + bytesToHex(clientApplicationTrafficSecret));

        serverApplicationTrafficSecret = hkdfExpandLabel(masterSecret, "s ap traffic", serverFinishedHash, hashLength);
        Logger.debug("Server application traffic secret: " + bytesToHex(serverApplicationTrafficSecret));

        byte[] clientApplicationKey = hkdfExpandLabel(clientApplicationTrafficSecret, "key", "", keyLength);
        Logger.debug("Client application key: " + bytesToHex(clientApplicationKey));

        byte[] serverApplicationKey = hkdfExpandLabel(serverApplicationTrafficSecret, "key", "", keyLength);
        Logger.debug("Server application key: " + bytesToHex(serverApplicationKey));

        byte[] clientApplicationIv = hkdfExpandLabel(clientApplicationTrafficSecret, "iv", "", iv_length);
        Logger.debug("Client application iv: " + bytesToHex(clientApplicationIv));

        byte[] serverApplicationIv = hkdfExpandLabel(serverApplicationTrafficSecret, "iv", "", iv_length);
        Logger.debug("Server application iv: " + bytesToHex(serverApplicationIv));
    }

    public void computeResumptionMasterSecret() {
        byte[] clientFinishedHash = transcriptHash.getClientHash(TlsConstants.HandshakeType.finished);

        resumptionMasterSecret = hkdfExpandLabel(masterSecret, "res master", clientFinishedHash, hashLength);
        Logger.debug("Resumption master secret: " + bytesToHex(resumptionMasterSecret));
    }

    // https://tools.ietf.org/html/rfc8446#section-4.6.1
    // "The PSK associated with the ticket is computed as:
    //       HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)"
    public byte[] computePSK(byte[] ticketNonce) {
        byte[] psk = hkdfExpandLabel(resumptionMasterSecret, "resumption", ticketNonce, hashLength);
        return psk;
    }

    public byte[] hkdfExpandLabel(byte[] secret, String label, String context, short length) {
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

    public void setOwnKey(PrivateKey clientPrivateKey) {
        this.clientPrivateKey = clientPrivateKey;
    }

    public void setPskSelected(int selectedIdentity) {
        pskSelected = true;
    }

    public void setNoPskSelected() {
        if (psk != null && !pskSelected) {
            // Recompute early secret, as psk is not accepted by server.
            // https://tools.ietf.org/html/rfc8446#section-7.1
            // "... if no PSK is selected, it will then need to compute the Early Secret corresponding to the zero PSK."
            computeEarlySecret(new byte[hashLength]);
        }
    }

    public void setPeerKey(PublicKey serverSharedKey) {
        this.serverSharedKey = serverSharedKey;
    }
}
