/*
 * Copyright © 2019, 2020, 2021 Peter Doornbosch
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

import net.luminis.tls.handshake.HandshakeMessage;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

// https://tools.ietf.org/html/rfc8446#section-4.4.1
// "Many of the cryptographic computations in TLS make use of a
//   transcript hash.  This value is computed by hashing the concatenation
//   of each included handshake message, including the handshake message
//   header carrying the handshake message type and length fields, but not
//   including record layer headers."
public class TranscriptHash {

    enum ExtendedHandshakeType {
        client_hello(1),
        server_hello(2),
        new_session_ticket(4),
        end_of_early_data(5),
        encrypted_extensions(8),
        certificate(11),
        certificate_request(13),
        certificate_verify(15),
        finished(20),
        key_update(24),
        client_finished(251),
        server_finished(252),
        ;

        public final byte value;

        ExtendedHandshakeType(int value) {
            this.value = (byte) value;
        }
    }

    // https://tools.ietf.org/html/rfc8446#section-4.4.1
    // "For concreteness, the transcript hash is always taken from the
    //   following sequence of handshake messages, starting at the first
    //   ClientHello and including only those messages that were sent:
    //   ClientHello, HelloRetryRequest, ClientHello, ServerHello,
    //   EncryptedExtensions, server CertificateRequest, server Certificate,
    //   server CertificateVerify, server Finished, EndOfEarlyData, client
    //   Certificate, client CertificateVerify, client Finished."
    private static ExtendedHandshakeType[] hashedMessages = {
            ExtendedHandshakeType.client_hello,
            ExtendedHandshakeType.server_hello,
            ExtendedHandshakeType.encrypted_extensions,
            ExtendedHandshakeType.certificate,
            ExtendedHandshakeType.certificate_verify,
            ExtendedHandshakeType.server_finished,
            ExtendedHandshakeType.client_finished
    };

    private final MessageDigest hashFunction;

    private Map<ExtendedHandshakeType, byte[]> msgData = new ConcurrentHashMap<>();
    private Map<ExtendedHandshakeType, byte[]> hashes = new ConcurrentHashMap<>();


    public TranscriptHash(int hashLength) {
        // https://tools.ietf.org/html/rfc8446#section-7.1
        // "The Hash function used by Transcript-Hash and HKDF is the cipher suite hash algorithm."
        String hashAlgorithm = "SHA-" + (hashLength * 8);
        try {
            hashFunction = MessageDigest.getInstance(hashAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing " + hashAlgorithm + " support");
        }
    }

    public byte[] getHash(TlsConstants.HandshakeType msgType) {
        return getHash(convert(msgType));
    }

    public byte[] getClientHash(TlsConstants.HandshakeType msgType) {
        if (msgType == TlsConstants.HandshakeType.finished) {
            return getHash(ExtendedHandshakeType.client_finished);
        }
        else {
            return getHash(msgType);
        }
    }

    public byte[] getServerHash(TlsConstants.HandshakeType msgType) {
        if (msgType == TlsConstants.HandshakeType.finished) {
            return getHash(ExtendedHandshakeType.server_finished);
        }
        else {
            return getHash(msgType);
        }
    }

    private byte[] getHash(ExtendedHandshakeType type) {
        if (! hashes.containsKey(type)) {
            computeHash(type);
        }
        return hashes.get(type);
    }

    public void record(HandshakeMessage msg) {
        msgData.put(convert(msg.getType()), msg.getBytes());
    }

    public void recordClient(HandshakeMessage msg) {
        if (msg.getType() == TlsConstants.HandshakeType.finished) {
            msgData.put(ExtendedHandshakeType.client_finished, msg.getBytes());
        }
        else {
            msgData.put(convert(msg.getType()), msg.getBytes());
        }
    }

    public void recordServer(HandshakeMessage msg) {
        if (msg.getType() == TlsConstants.HandshakeType.finished) {
            msgData.put(ExtendedHandshakeType.server_finished, msg.getBytes());
        }
        else {
            msgData.put(convert(msg.getType()), msg.getBytes());
        }
    }

    private void computeHash(ExtendedHandshakeType requestedType) {
        for (ExtendedHandshakeType type: hashedMessages) {
            if (msgData.containsKey(type)) {
                hashFunction.update(msgData.get(type));
            }
            if (type == requestedType) {
                break;
            }
        }
        hashes.put(requestedType, hashFunction.digest());
    }

    private ExtendedHandshakeType convert(TlsConstants.HandshakeType type) {
        if (type == TlsConstants.HandshakeType.finished) {
            throw new IllegalArgumentException("cannot convert ambiguous type 'finished'");
        }
        return ExtendedHandshakeType.values()[type.ordinal()];
    }
}
