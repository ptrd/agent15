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
package tech.kwik.agent15.extension;

import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.alert.DecodeErrorException;

import java.nio.ByteBuffer;

/**
 * The TLS cookie extension.
 *
 * <p>A server can send a cookie in a HelloRetryRequest; the client must copy its contents into a cookie extension
 * in the new ClientHello.</p>
 *
 * <p>Structure (RFC 8446 §4.2.2):
 * <pre>
 * struct {
 *     opaque cookie&lt;1..2^16-1&gt;;
 * } Cookie;
 * </pre>
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.2">RFC 8446 §4.2.2</a>
 */
public class CookieExtension extends Extension {

    private final byte[] cookie;

    public CookieExtension(byte[] cookie) {
        if (cookie.length < 1) {
            throw new IllegalArgumentException("cookie must not be empty");
        }
        this.cookie = cookie;
    }

    public CookieExtension(ByteBuffer buffer) throws DecodeErrorException {
        int extensionDataLength = parseExtensionHeader(buffer, TlsConstants.ExtensionType.cookie, 2 + 1);
        int cookieLength = buffer.getShort() & 0xffff;
        if (extensionDataLength != 2 + cookieLength) {
            throw new DecodeErrorException("inconsistent length");
        }
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.2
        // "opaque cookie<1..2^16-1>;", so an empty cookie is not allowed.
        if (cookieLength < 1) {
            throw new DecodeErrorException("cookie must not be empty");
        }
        cookie = new byte[cookieLength];
        buffer.get(cookie);
    }

    @Override
    public byte[] getBytes() {
        int extensionLength = 2 + cookie.length;
        ByteBuffer buffer = ByteBuffer.allocate(4 + extensionLength);
        buffer.putShort(TlsConstants.ExtensionType.cookie.value);
        buffer.putShort((short) extensionLength);  // Extension data length (in bytes)
        buffer.putShort((short) cookie.length);
        buffer.put(cookie);
        return buffer.array();
    }

    public byte[] getCookie() {
        return cookie;
    }

    @Override
    public String toString() {
        return "CookieExtension[" + cookie.length + " bytes]";
    }

    @Override
    public int getType() {
        return TlsConstants.ExtensionType.cookie.value;
    }
}
