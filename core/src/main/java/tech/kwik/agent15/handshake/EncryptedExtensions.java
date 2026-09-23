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

import tech.kwik.agent15.extension.ExtensionParser;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.TlsProtocolException;
import tech.kwik.agent15.alert.DecodeErrorException;
import tech.kwik.agent15.extension.Extension;

import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * https://tools.ietf.org/html/rfc8446#section-4.3.1
 */
public class EncryptedExtensions extends HandshakeMessage {

    private static final int MINIMAL_MESSAGE_LENGTH = 1 + 3 + 2;

    private final List<Extension> extensions;
    private final byte[] raw;

    public EncryptedExtensions() {
        this(Collections.emptyList());
    }

    public EncryptedExtensions(List<Extension> extensions) {
        this.extensions = extensions;
        raw = serialize(extensions);
    }

    private EncryptedExtensions(List<Extension> extensions, byte[] raw) {
        this.extensions = extensions;
        this.raw = raw;
    }

    @Override
    public TlsConstants.HandshakeType getType() {
        return TlsConstants.HandshakeType.encrypted_extensions;
    }

    private static byte[] serialize(List<Extension> extensions) {
        List<byte[]> extensionBytes = extensions.stream().map(extension -> extension.getBytes()).collect(Collectors.toList());
        int extensionsSize = extensionBytes.stream().mapToInt(data -> data.length).sum();

        byte[] raw = new byte[1 + 3 + 2 + extensionsSize];
        ByteBuffer buffer = ByteBuffer.wrap(raw);
        buffer.putInt(0x08000000 | (2 + extensionsSize));
        buffer.putShort((short) extensionsSize);
        extensionBytes.forEach(bytes -> buffer.put(bytes));
        return raw;
    }

    /**
     * Parses an encrypted extensions message from a byte stream.
     * @param buffer
     * @param length  the length of the message (including the handshake header)
     * @throws TlsProtocolException
     */
    public static EncryptedExtensions parse(ByteBuffer buffer, int length) throws TlsProtocolException {
        return parse(buffer, length, null);
    }

    /**
     * Parses an encrypted extensions message from a byte stream.
     * @param buffer
     * @param length                  the length of the message (including the handshake header)
     * @param customExtensionParser   parser for extensions not known to this implementation; may be null
     * @throws TlsProtocolException
     */
    public static EncryptedExtensions parse(ByteBuffer buffer, int length, ExtensionParser customExtensionParser) throws TlsProtocolException {
        if (buffer.remaining() < MINIMAL_MESSAGE_LENGTH) {
            throw new DecodeErrorException("Message too short");
        }

        int start = buffer.position();
        int msgLength = buffer.getInt() & 0x00ffffff;
        if (buffer.remaining() < msgLength || msgLength < 2) {
            throw new DecodeErrorException("Incorrect message length");
        }

        List<Extension> extensions = parseExtensions(buffer, TlsConstants.HandshakeType.encrypted_extensions, customExtensionParser);

        // Raw bytes are needed for computing the transcript hash
        buffer.position(start);
        byte[] raw = new byte[length];
        buffer.mark();
        buffer.get(raw);

        return new EncryptedExtensions(extensions, raw);
    }

    public List<Extension> getExtensions() {
        return extensions;
    }

    @Override
    public byte[] getBytes() {
        return raw;
    }
}
