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

import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.alert.DecodeErrorException;

import java.nio.ByteBuffer;

/**
 * https://datatracker.ietf.org/doc/html/rfc8446#section-4
 */
public abstract class HandshakeMessage {

    public abstract TlsConstants.HandshakeType getType();

    protected static int parseHandshakeHeader(ByteBuffer buffer, TlsConstants.HandshakeType expectedType, int minimumMessageSize) throws DecodeErrorException {
        if (buffer.remaining() < 4) {
            throw new DecodeErrorException("handshake message underflow");
        }
        int handshakeType = buffer.get() & 0xff;
        if (handshakeType != expectedType.value) {
            throw new IllegalStateException();  // i.e. programming error
        }
        int messageDataLength = ((buffer.get() & 0xff) << 16) | ((buffer.get() & 0xff) << 8) | (buffer.get() & 0xff);
        if (4 + messageDataLength < minimumMessageSize) {
            throw new DecodeErrorException(expectedType + " message can't be less than " + minimumMessageSize + " bytes");
        }
        if (buffer.remaining() < messageDataLength) {
            throw new DecodeErrorException("handshake message underflow");
        }
        return messageDataLength;
    }

    public abstract byte[] getBytes();

}
