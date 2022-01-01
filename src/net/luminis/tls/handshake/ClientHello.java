/*
 * Copyright © 2019, 2020, 2021, 2022 Peter Doornbosch
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
package net.luminis.tls.handshake;

import net.luminis.tls.TlsState;
import net.luminis.tls.extension.ClientHelloPreSharedKeyExtension;
import net.luminis.tls.alert.DecodeErrorException;
import net.luminis.tls.TlsConstants;
import net.luminis.tls.TlsProtocolException;
import net.luminis.tls.alert.IllegalParameterAlert;
import net.luminis.tls.extension.*;

import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.util.*;
import java.util.stream.Collectors;

import static net.luminis.tls.TlsConstants.NamedGroup.secp256r1;


public class ClientHello extends HandshakeMessage {

    public enum PskKeyEstablishmentMode {
        none,
        PSKonly,
        PSKwithDHE,
        both
    };

    private static final int MAX_CLIENT_HELLO_SIZE = 3000;
    public static final List<TlsConstants.CipherSuite> SUPPORTED_CIPHERS = List.of(TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256);
    private static final int MINIMAL_MESSAGE_LENGTH = 1 + 3 + 2 + 32 + 1 + 2 + 2 + 2 + 2;
    private static final List<TlsConstants.SignatureScheme> SUPPORTED_SIGNATURES = List.of(TlsConstants.SignatureScheme.rsa_pss_rsae_sha256);

    private static Random random = new Random();
    private static SecureRandom secureRandom = new SecureRandom();
    private final byte[] data;
    private final int pskExtensionStartPosition;
    private byte[] clientRandom;

    private List<TlsConstants.CipherSuite> cipherSuites = new ArrayList<>();
    private List<Extension> extensions;

    /**
     * Parses a ClientHello message from a byte stream.
     * @param buffer
     * @throws TlsProtocolException
     * @throws IllegalParameterAlert
     */
    public ClientHello(ByteBuffer buffer, ExtensionParser customExtensionParser) throws TlsProtocolException, IllegalParameterAlert {
        int startPosition = buffer.position();

        if (buffer.remaining() < 4) {
            throw new DecodeErrorException("message underflow");
        }
        if (buffer.remaining() < MINIMAL_MESSAGE_LENGTH) {
            throw new DecodeErrorException("message underflow");
        }

        int messageType = buffer.get();
        if (messageType != TlsConstants.HandshakeType.client_hello.value) {
            throw new RuntimeException();  // Programming error
        }
        int length = ((buffer.get() & 0xff) << 16) | ((buffer.get() & 0xff) << 8) | (buffer.get() & 0xff);
        if (buffer.remaining() < length) {
            throw new DecodeErrorException("message underflow");
        }

        int legacyVersion = buffer.getShort();
        if (legacyVersion != 0x0303) {
            throw new DecodeErrorException("legacy version must be 0303");
        }

        clientRandom = new byte[32];
        buffer.get(clientRandom);

        int sessionIdLength = buffer.get();
        if (sessionIdLength > 0) {
            buffer.get(new byte[sessionIdLength]);
        }

        int cipherSuitesLength = buffer.getShort();
        for (int i = 0; i < cipherSuitesLength; i += 2) {
            int cipherSuiteValue = buffer.getShort();
            Arrays.stream(TlsConstants.CipherSuite.values())
                    .filter(item -> item.value == cipherSuiteValue)
                    .findFirst()
                    // https://tools.ietf.org/html/rfc8446#section-4.1.2
                    // "If the list contains cipher suites that the server does not recognize, support, or wish to use,
                    // the server MUST ignore those cipher suites and process the remaining ones as usual."
                    .ifPresent(item -> cipherSuites.add(item));
        }

        int legacyCompressionMethodsLength = buffer.get();
        int legacyCompressionMethod = buffer.get();
        if (legacyCompressionMethodsLength != 1 || legacyCompressionMethod != 0) {
            throw new IllegalParameterAlert("Invalid legacy compression method");
        }

        int extensionStart = buffer.position();
        extensions = parseExtensions(buffer, TlsConstants.HandshakeType.client_hello, customExtensionParser);
        if (extensions.stream().anyMatch(ext -> ext instanceof PreSharedKeyExtension)) {
            buffer.position(extensionStart);
            pskExtensionStartPosition = findPositionLastExtension(buffer);
            // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11
            // "The "pre_shared_key" extension MUST be the last extension in the ClientHello (...). Servers MUST check
            //  that it is the last extension and otherwise fail the handshake with an "illegal_parameter" alert."
            if (! (extensions.get(extensions.size() - 1) instanceof PreSharedKeyExtension)) {
                throw new IllegalParameterAlert("pre_shared_key extension MUST be the last extension in the ClientHello");
            }
        }
        else {
            pskExtensionStartPosition = -1;
        }

        data = new byte[buffer.position() - startPosition];
        buffer.position(startPosition);
        buffer.get(data);
    }

    public ClientHello(String serverName, ECPublicKey publicKey) {
        this(serverName, publicKey, true, SUPPORTED_CIPHERS, SUPPORTED_SIGNATURES, secp256r1, Collections.emptyList(), null, PskKeyEstablishmentMode.both);
    }

    public ClientHello(String serverName, ECPublicKey publicKey, boolean compatibilityMode, List<Extension> extraExtensions) {
        this(serverName, publicKey, compatibilityMode, SUPPORTED_CIPHERS, SUPPORTED_SIGNATURES, secp256r1, extraExtensions, null, PskKeyEstablishmentMode.both);
    }

    /**
     *  @param serverName
     * @param publicKey
     * @param compatibilityMode
     * @param supportedCiphers
     * @param supportedSignatures
     * @param ecCurve
     * @param extraExtensions
     * @param tlsState              can be null when no ClientHelloPreSharedKeyExtension is present, must be non-null when ClientHelloPreSharedKeyExtension is present.
     * @param pskKeyEstablishmentMode
     */
    public ClientHello(String serverName, PublicKey publicKey, boolean compatibilityMode, List<TlsConstants.CipherSuite> supportedCiphers,
                       List<TlsConstants.SignatureScheme> supportedSignatures, TlsConstants.NamedGroup ecCurve, List<Extension> extraExtensions, TlsState tlsState, PskKeyEstablishmentMode pskKeyEstablishmentMode) {
        this.cipherSuites = supportedCiphers;

        ByteBuffer buffer = ByteBuffer.allocate(MAX_CLIENT_HELLO_SIZE);

        // HandshakeType client_hello(1),
        buffer.put((byte) 1);

        // Reserve 3 bytes for length
        byte[] length = new byte[3];
        buffer.put(length);

        // client version
        buffer.put((byte) 0x03);
        buffer.put((byte) 0x03);

        // client random 32 bytes
        clientRandom = new byte[32];
        secureRandom.nextBytes(clientRandom);
        buffer.put(clientRandom);

        byte[] sessionId;
        if (compatibilityMode) {
            sessionId = new byte[32];
            random.nextBytes(sessionId);
        }
        else {
            sessionId = new byte[0];
        }
        buffer.put((byte) sessionId.length);
        if (sessionId.length > 0)
            buffer.put(sessionId);

        buffer.putShort((short) (supportedCiphers.size() * 2));
        for (TlsConstants.CipherSuite cipher: supportedCiphers) {
            buffer.putShort(cipher.value);
        }

        // Compression
        // "For every TLS 1.3 ClientHello, this vector MUST contain exactly one byte, set to zero, which corresponds to
        // the "null" compression method in prior versions of TLS. "
        buffer.put(new byte[] {
                (byte) 0x01, (byte) 0x00
        });

        Extension[] defaultExtensions = new Extension[] {
                new ServerNameExtension(serverName),
                new SupportedVersionsExtension(TlsConstants.HandshakeType.client_hello),
                new SupportedGroupsExtension(ecCurve),
                new SignatureAlgorithmsExtension(supportedSignatures),
                new KeyShareExtension(publicKey, ecCurve, TlsConstants.HandshakeType.client_hello),
        };

        extensions = new ArrayList<>();
        extensions.addAll(List.of(defaultExtensions));
        if (pskKeyEstablishmentMode != PskKeyEstablishmentMode.none) {
            extensions.add(createPskKeyExchangeModesExtension(pskKeyEstablishmentMode));
        }
        extensions.addAll(extraExtensions);

        ClientHelloPreSharedKeyExtension pskExtension = null;
        int extensionsLength = extensions.stream().mapToInt(ext -> ext.getBytes().length).sum();
        buffer.putShort((short) extensionsLength);
        int pskExtensionStartPosition = -1;
        for (Extension extension: extensions) {
            if (extension instanceof ClientHelloPreSharedKeyExtension) {
                pskExtension = (ClientHelloPreSharedKeyExtension) extension;
                pskExtensionStartPosition = buffer.position();
            }
            buffer.put(extension.getBytes());
        }
        this.pskExtensionStartPosition = pskExtensionStartPosition;  // Copy value into member field, necessary because field is final.

        buffer.limit(buffer.position());
        int clientHelloLength = buffer.position() - 4;
        buffer.putShort(2, (short) clientHelloLength);
        
        data = new byte[clientHelloLength + 4];
        buffer.rewind();
        buffer.get(data);

        if (pskExtension != null) {
            if (tlsState == null) {
                throw new IllegalArgumentException("TlsState cannot be null when ClientHelloPreSharedKeyExtension is present");
            }
            pskExtension.calculateBinder(data, pskExtensionStartPosition, tlsState);
            buffer.position(pskExtensionStartPosition);
            buffer.put(pskExtension.getBytes());
            buffer.rewind();
            buffer.get(data);
        }
    }

    private PskKeyExchangeModesExtension createPskKeyExchangeModesExtension(PskKeyEstablishmentMode pskKeyEstablishmentMode) {
        switch (pskKeyEstablishmentMode) {
            case PSKonly:
                return new PskKeyExchangeModesExtension(TlsConstants.PskKeyExchangeMode.psk_ke);
            case PSKwithDHE:
                return new PskKeyExchangeModesExtension(TlsConstants.PskKeyExchangeMode.psk_dhe_ke);
            case both:
                return new PskKeyExchangeModesExtension(TlsConstants.PskKeyExchangeMode.psk_ke, TlsConstants.PskKeyExchangeMode.psk_dhe_ke);
            default:
                throw new IllegalArgumentException();
        }
    }

    @Override
    public TlsConstants.HandshakeType getType() {
        return TlsConstants.HandshakeType.client_hello;
    }

    @Override
    public byte[] getBytes() {
        return data;
    }

    public byte[] getClientRandom() {
        return clientRandom;
    }

    public List<TlsConstants.CipherSuite> getCipherSuites() {
        return cipherSuites;
    }

    public List<Extension> getExtensions() {
        return extensions;
    }

    /**
     * Returns the start position of the PreSharedKeyExtension in the serialized ClientHello. This is needed for computing binders.
     * @return  the start position or -1 if not present.
     */
    public int getPskExtensionStartPosition() {
        return pskExtensionStartPosition;
    }

    @Override
    public String toString() {
        return "ClientHello["
                + cipherSuites.stream().map(cs -> cs.toString()).collect(Collectors.joining(",")) + "|"
                + extensions.stream().map(ex -> ex.toString()).collect(Collectors.joining(","))
                + "]";
    }

}
