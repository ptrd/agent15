/*
 * Copyright © 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
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
import tech.kwik.agent15.TlsProtocolException;
import tech.kwik.agent15.alert.DecodeErrorException;
import tech.kwik.agent15.extension.Extension;
import tech.kwik.agent15.extension.ExtensionBlockParser;

import java.nio.ByteBuffer;
import java.util.List;

import static tech.kwik.agent15.extension.ExtensionBlockParser.parseExtensionBlock;

// https://tools.ietf.org/html/rfc8446#section-4.3.2
public class CertificateRequestMessage extends HandshakeMessage {

    private static final int MINIMUM_MESSAGE_SIZE = 1 + 3 + 1 + 2;

    private final byte[] certificateRequestContext;
    private final List<Extension> extensions;
    private final byte[] raw;

    public CertificateRequestMessage(Extension extension) {
        extensions = List.of(extension);
        certificateRequestContext = new byte[0];

        raw = serialize(certificateRequestContext, extensions);
    }

    private CertificateRequestMessage(byte[] certificateRequestContext, List<Extension> extensions, byte[] raw) {
        this.certificateRequestContext = certificateRequestContext;
        this.extensions = extensions;
        this.raw = raw;
    }

    /**
     * Parses a certificate request message from a byte stream.
     * @param buffer
     * @throws TlsProtocolException
     */
    public static CertificateRequestMessage parse(ByteBuffer buffer) throws TlsProtocolException {
        int startPosition = buffer.position();
        int remainingLength = parseHandshakeHeader(buffer, TlsConstants.HandshakeType.certificate_request, MINIMUM_MESSAGE_SIZE);

        int contextLength = buffer.get() & 0xff;
        if (buffer.remaining() < contextLength + 2) {
            throw new DecodeErrorException("invalid certificate_request_context length");
        }
        byte[] certificateRequestContext = new byte[contextLength];
        if (contextLength > 0) {
            buffer.get(certificateRequestContext);
        }

        List<Extension> extensions = parseExtensionBlock(buffer, TlsConstants.HandshakeType.certificate_request, null);

        if (buffer.position() - (startPosition + 4) != remainingLength) {
            throw new DecodeErrorException("inconsistent length");
        }

        byte[] raw = new byte[4 + remainingLength];
        buffer.position(startPosition);
        buffer.get(raw);

        return new CertificateRequestMessage(certificateRequestContext, extensions, raw);
    }

    private static byte[] serialize(byte[] certificateRequestContext, List<Extension> extensions) {
        int extensionsLength = extensions.stream().mapToInt(ext -> ext.getBytes().length).sum();
        int messageLength = 4 + 1 + certificateRequestContext.length + 2 + extensionsLength;
        ByteBuffer buffer = ByteBuffer.allocate(messageLength);
        buffer.put(TlsConstants.HandshakeType.certificate_request.value);
        buffer.put((byte) 0x00);
        buffer.putShort((short) (messageLength - 4));
        buffer.put((byte) certificateRequestContext.length);
        if (certificateRequestContext.length > 0) {
            buffer.put(certificateRequestContext);
        }
        buffer.putShort((short) extensionsLength);
        for (Extension extension: extensions) {
            buffer.put(extension.getBytes());
        }
        return buffer.array();
    }


    @Override
    public TlsConstants.HandshakeType getType() {
        return TlsConstants.HandshakeType.certificate_request;
    }

    @Override
    public byte[] getBytes() {
        return raw;
    }

    public List<Extension> getExtensions() {
        return extensions;
    }
}
