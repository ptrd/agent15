/*
 * Copyright © 2026 Peter Doornbosch
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

import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.extension.CookieExtension;
import tech.kwik.agent15.extension.Extension;
import tech.kwik.agent15.extension.KeyShareExtension;
import tech.kwik.agent15.extension.SupportedVersionsExtension;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.4
 * "As discussed in Section 4.1.3, the HelloRetryRequest has the same format as a ServerHello message, and the
 *  legacy_version, legacy_session_id_echo, cipher_suite, and legacy_compression_method fields have the same meaning.
 *  However, for convenience we discuss "HelloRetryRequest" throughout this document as if it were a distinct message."
 *
 * On the wire it is a server_hello message whose random field has a fixed value (see
 * https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3); ServerHello.parse returns an instance of this class
 * when it encounters that value.
 */
public class HelloRetryRequest extends HandshakeMessage {

    /**
     * https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3
     * "For reasons of backward compatibility with middleboxes (see Appendix D.4), the HelloRetryRequest message uses the
     *  same structure as the ServerHello, but with Random set to the special value of the SHA-256 of "HelloRetryRequest"
     */
    static final byte[] HelloRetryRequest_SHA256 = new byte[] {
            (byte) 0xCF, (byte) 0x21, (byte) 0xAD, (byte) 0x74, (byte) 0xE5, (byte) 0x9A, (byte) 0x61, (byte) 0x11,
            (byte) 0xBE, (byte) 0x1D, (byte) 0x8C, (byte) 0x02, (byte) 0x1E, (byte) 0x65, (byte) 0xB8, (byte) 0x91,
            (byte) 0xC2, (byte) 0xA2, (byte) 0x11, (byte) 0x16, (byte) 0x7A, (byte) 0xBB, (byte) 0x8C, (byte) 0x5E,
            (byte) 0x07, (byte) 0x9E, (byte) 0x09, (byte) 0xE2, (byte) 0xC8, (byte) 0xA8, (byte) 0x33, (byte) 0x9C
    };

    private final byte[] raw;
    private final byte[] legacySessionIdEcho;
    private final TlsConstants.CipherSuite cipherSuite;
    private final List<Extension> extensions;

    HelloRetryRequest(byte[] raw, byte[] legacySessionIdEcho, TlsConstants.CipherSuite cipherSuite, List<Extension> extensions) {
        this.raw = raw;
        this.legacySessionIdEcho = legacySessionIdEcho;
        this.cipherSuite = cipherSuite;
        this.extensions = extensions;
    }

    public HelloRetryRequest(TlsConstants.CipherSuite cipherSuite, List<Extension> extensions) {
        this(cipherSuite, new byte[0], extensions);
    }

    public HelloRetryRequest(TlsConstants.CipherSuite cipherSuite, byte[] legacySessionIdEcho, List<Extension> extensions) {
        this.legacySessionIdEcho = legacySessionIdEcho;
        this.cipherSuite = cipherSuite;
        this.extensions = extensions;

        int extensionsSize = extensions.stream().mapToInt(extension -> extension.getBytes().length).sum();
        raw = new byte[1 + 3 + 2 + 32 + 1 + legacySessionIdEcho.length + 2 + 1 + 2 + extensionsSize];
        ByteBuffer buffer = ByteBuffer.wrap(raw);
        // https://tools.ietf.org/html/rfc8446#section-4
        // "uint24 length;             /* remaining bytes in message */"
        // A HelloRetryRequest is sent as a server_hello message (type 2).
        buffer.putInt((raw.length - 4) | 0x02000000);
        buffer.putShort((short) 0x0303);
        buffer.put(HelloRetryRequest_SHA256);
        buffer.put((byte) legacySessionIdEcho.length);
        buffer.put(legacySessionIdEcho);
        buffer.putShort(cipherSuite.value);
        buffer.put((byte) 0);
        buffer.putShort((short) extensionsSize);
        extensions.forEach(extension -> buffer.put(extension.getBytes()));
    }

    @Override
    public TlsConstants.HandshakeType getType() {
        // A HelloRetryRequest is sent as a server_hello message, see https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.4.
        return TlsConstants.HandshakeType.server_hello;
    }

    @Override
    public byte[] getBytes() {
        return raw;
    }

    public byte[] getLegacySessionIdEcho() {
        return legacySessionIdEcho;
    }

    public TlsConstants.CipherSuite getCipherSuite() {
        return cipherSuite;
    }

    public List<Extension> getExtensions() {
        return extensions;
    }

    /**
     * Returns whether this message carries a key share extension.
     * Note that the extension can be present whilst <code>getSelectedGroup</code> returns an empty optional; that is
     * the case when the server selected a group that is not known to this implementation.
     */
    public boolean hasKeyShareExtension() {
        return extensions.stream().anyMatch(extension -> extension instanceof KeyShareExtension);
    }

    /**
     * Returns the group the server selected for the key exchange, as indicated by the key share extension.
     * @return  the selected group, or empty when there is no key share extension or the selected group is unknown to
     *          this implementation.
     */
    public Optional<TlsConstants.NamedGroup> getSelectedGroup() {
        return extensions.stream()
                .filter(extension -> extension instanceof KeyShareExtension)
                .map(extension -> ((KeyShareExtension) extension).getKeyShareEntries())
                .flatMap(List::stream)
                .map(KeyShareExtension.KeyShareEntry::getNamedGroup)
                .findFirst();
    }

    /**
     * Returns the contents of the cookie extension.
     */
    public Optional<byte[]> getCookie() {
        return extensions.stream()
                .filter(extension -> extension instanceof CookieExtension)
                .map(extension -> ((CookieExtension) extension).getCookie())
                .findFirst();
    }

    /**
     * Returns the TLS version the server selected, as indicated by the supported versions extension. This extension is
     * mandatory in a HelloRetryRequest (https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.4), so an empty
     * optional means the message is not conformant.
     */
    public Optional<Short> getSelectedVersion() {
        return extensions.stream()
                .filter(extension -> extension instanceof SupportedVersionsExtension)
                .map(extension -> ((SupportedVersionsExtension) extension).getTlsVersion())
                .findFirst();
    }

    @Override
    public String toString() {
        return "HelloRetryRequest["
                + cipherSuite + "|"
                + extensions.stream().map(extension -> extension.toString()).collect(Collectors.joining(","))
                + "]";
    }
}
