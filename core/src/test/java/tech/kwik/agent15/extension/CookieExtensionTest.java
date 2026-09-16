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

import org.junit.jupiter.api.Test;
import tech.kwik.agent15.alert.DecodeErrorException;
import tech.kwik.agent15.util.ByteUtils;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CookieExtensionTest {

    @Test
    void parseCookieExtension() throws Exception {
        //                                                 type  length cookie length  cookie
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002c" + "0006" + "0004" + "cafebabe"));

        CookieExtension cookieExtension = new CookieExtension(buffer);

        assertThat(cookieExtension.getCookie()).isEqualTo(ByteUtils.hexToBytes("cafebabe"));
        assertThat(buffer.remaining()).isEqualTo(0);
    }

    @Test
    void serializeCookieExtension() throws Exception {
        byte[] cookie = ByteUtils.hexToBytes("0123456789");

        byte[] serialized = new CookieExtension(cookie).getBytes();

        assertThat(serialized).isEqualTo(ByteUtils.hexToBytes("002c" + "0007" + "0005" + "0123456789"));
    }

    @Test
    void serializedCookieExtensionCanBeParsedBack() throws Exception {
        byte[] cookie = ByteUtils.hexToBytes("f00dbaadf00dbaad");

        CookieExtension parsed = new CookieExtension(ByteBuffer.wrap(new CookieExtension(cookie).getBytes()));

        assertThat(parsed.getCookie()).isEqualTo(cookie);
    }

    @Test
    void parseCookieExtensionWithInconsistentLengthShouldThrow() throws Exception {
        // Extension data length (0x0006) does not match the cookie length (0x0003) plus the 2 length bytes.
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002c" + "0006" + "0003" + "cafebabe"));

        assertThatThrownBy(() -> new CookieExtension(buffer))
                .isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseTruncatedCookieExtensionShouldThrow() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002c" + "0006" + "0004" + "cafe"));

        assertThatThrownBy(() -> new CookieExtension(buffer))
                .isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseEmptyCookieShouldThrow() throws Exception {
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.2
        // "opaque cookie<1..2^16-1>;"
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002c" + "0002" + "0000"));

        assertThatThrownBy(() -> new CookieExtension(buffer))
                .isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void creatingExtensionWithEmptyCookieShouldThrow() {
        assertThatThrownBy(() -> new CookieExtension(new byte[0]))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
