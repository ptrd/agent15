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
package tech.kwik.agent15.extension;

import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.TlsProtocolException;

import java.nio.ByteBuffer;

/**
 * A functional interface for parsing (custom) TLS extensions from a byte stream.
 */
@FunctionalInterface
public interface ExtensionParser {

    /**
     * @deprecated Use {@link #parse(ByteBuffer, TlsConstants.HandshakeType)} instead.
     * @param byteBuffer
     * @param handshakeType
     * @return
     * @throws TlsProtocolException
     */
    @Deprecated(forRemoval = true)
    Extension apply(ByteBuffer byteBuffer, TlsConstants.HandshakeType handshakeType) throws TlsProtocolException;

    /**
     * Parses an extension from a byte stream.
     * @param byteBuffer     the byte stream containing the extension data
     * @param handshakeType  the handshake type of the message that contains this extension
     * @return  the parsed extension
     * @throws TlsProtocolException
     */
    default Extension parse(ByteBuffer byteBuffer, TlsConstants.HandshakeType handshakeType) throws TlsProtocolException {
        return apply(byteBuffer, handshakeType);
    }
}

