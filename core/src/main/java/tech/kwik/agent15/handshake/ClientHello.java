/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
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
package tech.kwik.agent15.handshake;

import tech.kwik.agent15.BinderCalculator;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.TlsProtocolException;
import tech.kwik.agent15.alert.DecodeErrorException;
import tech.kwik.agent15.alert.IllegalParameterAlert;
import tech.kwik.agent15.extension.*;
import tech.kwik.agent15.util.ListUtils;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;


/**
 * https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
 */
public class ClientHello extends HandshakeMessage {

    public enum PskKeyEstablishmentMode {
        none,
        PSKonly,
        PSKwithDHE,
        both
    };

    public static final List<TlsConstants.CipherSuite> SUPPORTED_CIPHERS = List.of(TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256);
    private static final int MINIMAL_MESSAGE_LENGTH = 1 + 3 + 2 + 32 + 1 + 2 + 2 + 2 + 2;
    private static final List<TlsConstants.SignatureScheme> SUPPORTED_SIGNATURES = List.of(TlsConstants.SignatureScheme.rsa_pss_rsae_sha256);

    private static SecureRandom secureRandom = new SecureRandom();
    private final byte[] serialized;
    private final int pskExtensionStartPosition;
    private final byte[] clientRandom;
    private final byte[] sessionId;
    private final List<TlsConstants.CipherSuite> cipherSuites;
    private final List<Extension> extensions;


    private ClientHello(byte[] serializedCH, int pskExtensionStartPosition, byte[] clientRandom, byte[] sessionId,
                        List<TlsConstants.CipherSuite> cipherSuites, List<Extension> extensions) {
        this.serialized = serializedCH;
        this.pskExtensionStartPosition = pskExtensionStartPosition;
        this.clientRandom = clientRandom;
        this.sessionId = sessionId;
        this.cipherSuites = cipherSuites;
        this.extensions = extensions;
    }

    /**
     * Creates a (first) ClientHello that offers a key share for each of the given groups.
     * https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8
     * "Clients MAY send an empty client_shares vector in order to request group selection from the server, at the cost
     *  of an additional round trip"; this implementation always sends at least one key share.
     *
     * @param serverName
     * @param keyShares               the key shares to offer, in descending order of preference; must not be empty and
     *                                each of its groups must occur in supportedGroups, in the same order.
     * @param compatibilityMode
     * @param supportedCiphers
     * @param supportedSignatures
     * @param supportedGroups
     * @param extraExtensions
     * @param binderCalculator        can be null when no ClientHelloPreSharedKeyExtension is present, must be non-null when ClientHelloPreSharedKeyExtension is present.
     * @param pskKeyEstablishmentMode
     */
    public ClientHello(String serverName, List<KeyShareExtension.KeyShareEntry> keyShares, boolean compatibilityMode,
                       List<TlsConstants.CipherSuite> supportedCiphers, List<TlsConstants.SignatureScheme> supportedSignatures,
                       List<TlsConstants.NamedGroup> supportedGroups, List<Extension> extraExtensions, BinderCalculator binderCalculator, PskKeyEstablishmentMode pskKeyEstablishmentMode) {
        this(generateClientRandom(), generateSessionId(compatibilityMode), supportedCiphers,
                assembleExtensions(serverName, keyShares, supportedSignatures, supportedGroups, extraExtensions,
                        pskKeyEstablishmentMode),
                binderCalculator);
    }

    /**
     * Creates a ClientHello message from its constituent parts. In contrast to the other constructors, this one does
     * not add any extension by itself: the given extensions are serialized as they are, in the order given. This is
     * what makes it possible to create the second ClientHello that must be sent in response to a HelloRetryRequest,
     * which must be identical to the first one except for a limited set of changes, see
     * https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2.
     *
     * @param clientRandom      the client random; 32 bytes
     * @param sessionId         the legacy session id; empty when not using compatibility mode
     * @param cipherSuites      the symmetric cipher options supported, in descending order of preference
     * @param extensions        the extensions, in the order in which they must be serialized
     * @param binderCalculator  can be null when no ClientHelloPreSharedKeyExtension is present, must be non-null when ClientHelloPreSharedKeyExtension is present.
     */
    public ClientHello(byte[] clientRandom, byte[] sessionId, List<TlsConstants.CipherSuite> cipherSuites,
                       List<Extension> extensions, BinderCalculator binderCalculator) {
        this(clientRandom, sessionId, cipherSuites, extensions, new byte[0], binderCalculator);
    }

    /**
     * Creates a ClientHello message from its constituent parts, with a transcript prefix for computing the binder of a
     * pre-shared key extension. This is what the second ClientHello (the one sent in response to a HelloRetryRequest)
     * needs, see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11.2.
     *
     * @param clientRandom      the client random; 32 bytes
     * @param sessionId         the legacy session id; empty when not using compatibility mode
     * @param cipherSuites      the symmetric cipher options supported, in descending order of preference
     * @param extensions        the extensions, in the order in which they must be serialized
     * @param transcriptPrefix  the transcript that precedes this client hello; empty for a first client hello
     * @param binderCalculator  can be null when no ClientHelloPreSharedKeyExtension is present, must be non-null when ClientHelloPreSharedKeyExtension is present.
     */
    public ClientHello(byte[] clientRandom, byte[] sessionId, List<TlsConstants.CipherSuite> cipherSuites,
                       List<Extension> extensions, byte[] transcriptPrefix, BinderCalculator binderCalculator) {
        this.clientRandom = clientRandom;
        this.sessionId = sessionId;
        this.cipherSuites = cipherSuites;
        this.extensions = extensions;

        int extensionsLength = extensions.stream().mapToInt(ext -> ext.getBytes().length).sum();
        // Message type (1) + length (3) + legacy version (2) + client random (32) + legacy session id length (1) +
        // legacy session id + cipher suites length (2) + cipher suites + legacy compression methods (2) +
        // extensions length (2) + extensions.
        int messageSize = 1 + 3 + 2 + 32 + 1 + sessionId.length + 2 + 2 * cipherSuites.size() + 2 + 2 + extensionsLength;
        ByteBuffer buffer = ByteBuffer.allocate(messageSize);

        // HandshakeType client_hello(1),
        buffer.put((byte) 1);

        // Reserve 3 bytes for length
        byte[] length = new byte[3];
        buffer.put(length);

        // client version
        buffer.put((byte) 0x03);
        buffer.put((byte) 0x03);

        // client random 32 bytes
        buffer.put(clientRandom);

        buffer.put((byte) sessionId.length);
        if (sessionId.length > 0)
            buffer.put(sessionId);

        buffer.putShort((short) (cipherSuites.size() * 2));
        for (TlsConstants.CipherSuite cipher: cipherSuites) {
            buffer.putShort(cipher.value);
        }

        // Compression
        // "For every TLS 1.3 ClientHello, this vector MUST contain exactly one byte, set to zero, which corresponds to
        // the "null" compression method in prior versions of TLS. "
        buffer.put(new byte[] {
                (byte) 0x01, (byte) 0x00
        });

        ClientHelloPreSharedKeyExtension pskExtension = null;
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
        
        serialized = new byte[clientHelloLength + 4];
        buffer.rewind();
        buffer.get(serialized);

        if (pskExtension != null) {
            if (binderCalculator == null) {
                throw new IllegalArgumentException("BinderCalculator cannot be null when ClientHelloPreSharedKeyExtension is present");
            }
            pskExtension.calculateBinder(serialized, pskExtensionStartPosition, transcriptPrefix, binderCalculator);
            buffer.position(pskExtensionStartPosition);
            buffer.put(pskExtension.getBytes());
            buffer.rewind();
            buffer.get(serialized);
        }
    }

    /**
     * Parses a ClientHello message from a byte stream.
     *
     * @param buffer                  the buffer to read the message from
     * @param customExtensionParser   parser for extensions not known to this implementation; may be null
     * @throws TlsProtocolException
     * @throws IllegalParameterAlert
     */
    public static ClientHello parse(ByteBuffer buffer, ExtensionParser customExtensionParser) throws TlsProtocolException, IllegalParameterAlert {
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

        byte[] clientRandom = new byte[32];
        buffer.get(clientRandom);

        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
        // "opaque legacy_session_id<0..32>;"
        int sessionIdLength = buffer.get() & 0xff;
        if (sessionIdLength > 32 || buffer.remaining() < sessionIdLength) {
            throw new DecodeErrorException("legacy session id length out of bounds: " + sessionIdLength);
        }
        byte[] sessionId = new byte[sessionIdLength];
        if (sessionIdLength > 0) {
            buffer.get(sessionId);
        }

        int cipherSuitesLength = buffer.getShort() & 0xffff;
        int compressionBytes = 1 + 1;  // Compression methods length (1 byte) + compression method (1 byte)
        if (buffer.remaining() < cipherSuitesLength + compressionBytes || cipherSuitesLength % 2 != 0) {
            throw new DecodeErrorException("message underflow");
        }
        List<TlsConstants.CipherSuite> cipherSuites = new ArrayList<>();
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

        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
        // "For every TLS 1.3 ClientHello, this vector MUST contain exactly one byte, set to zero, which corresponds to
        //  the "null" compression method in prior versions of TLS.  If a TLS 1.3 ClientHello is received with any other
        //  value in this field, the server MUST abort the handshake with an "illegal_parameter" alert."
        int legacyCompressionMethodsLength = buffer.get();
        int legacyCompressionMethod = buffer.get();
        if (legacyCompressionMethodsLength != 1 || legacyCompressionMethod != 0) {
            throw new IllegalParameterAlert("Invalid legacy compression method");
        }

        int extensionStart = buffer.position();
        List<Extension> extensions = parseExtensions(buffer, TlsConstants.HandshakeType.client_hello, customExtensionParser);
        int pskExtensionStartPosition;
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

        byte[] data = new byte[buffer.position() - startPosition];
        buffer.position(startPosition);
        buffer.get(data);

        return new ClientHello(data, pskExtensionStartPosition, clientRandom, sessionId, cipherSuites, extensions);
    }

    private static byte[] generateClientRandom() {
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
        // "random: 32 bytes generated by a secure random number generator."
        byte[] clientRandom = new byte[32];
        secureRandom.nextBytes(clientRandom);
        return clientRandom;
    }

    private static byte[] generateSessionId(boolean compatibilityMode) {
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
        // "In compatibility mode (see Appendix D.4), this field MUST be non-empty, so a client not offering a
        //  pre-TLS 1.3 session MUST generate a new 32-byte value."
        if (compatibilityMode) {
            byte[] sessionId = new byte[32];
            secureRandom.nextBytes(sessionId);
            return sessionId;
        }
        else {
            return new byte[0];
        }
    }

    /**
     * Assembles the extensions of a (first) ClientHello: the extensions that are always sent, followed by the
     * extensions provided by the caller.
     */
    private static List<Extension> assembleExtensions(String serverName, List<KeyShareExtension.KeyShareEntry> keyShares,
                                                      List<TlsConstants.SignatureScheme> supportedSignatures,
                                                      List<TlsConstants.NamedGroup> supportedGroups,
                                                      List<Extension> extraExtensions,
                                                      PskKeyEstablishmentMode pskKeyEstablishmentMode) {
        if (keyShares.isEmpty()) {
            throw new IllegalArgumentException("at least one key share is required");
        }
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8
        // "Each KeyShareEntry value MUST correspond to a group offered in the "supported_groups" extension and MUST
        //  appear in the same order."
        if (! ListUtils.isSubSequence(keyShares.stream().map(KeyShareExtension.KeyShareEntry::getNamedGroup).collect(Collectors.toList()), supportedGroups)) {
            throw new IllegalArgumentException("the key share groups must occur in supportedGroups, in the same order");
        }

        Extension[] defaultExtensions = new Extension[] {
                new ServerNameExtension(serverName),
                new SupportedVersionsExtension(TlsConstants.HandshakeType.client_hello),
                new SupportedGroupsExtension(supportedGroups),
                new SignatureAlgorithmsExtension(supportedSignatures),
                new KeyShareExtension(keyShares, TlsConstants.HandshakeType.client_hello),
        };

        List<Extension> extensions = new ArrayList<>();
        extensions.addAll(List.of(defaultExtensions));
        if (pskKeyEstablishmentMode != PskKeyEstablishmentMode.none) {
            extensions.add(createPskKeyExchangeModesExtension(pskKeyEstablishmentMode));
        }
        extensions.addAll(extraExtensions);
        return extensions;
    }

    private static PskKeyExchangeModesExtension createPskKeyExchangeModesExtension(PskKeyEstablishmentMode pskKeyEstablishmentMode) {
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
        return serialized;
    }

    public byte[] getClientRandom() {
        return clientRandom;
    }

    public byte[] getSessionId() {
        return sessionId;
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
