/*
 * Copyright © 2021, 2022 Peter Doornbosch
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
package net.luminis.tls.extension;


import net.luminis.tls.TlsConstants;
import net.luminis.tls.alert.DecodeErrorException;
import net.luminis.tls.util.ByteUtils;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class EarlyDataExtensionTest {

    @Test
    void testNewSessionTicketMessageEarlyDataExtension() throws Exception {
        byte[] data = ByteUtils.hexToBytes("002a 0004 8000 0000");
        var extension = new EarlyDataExtension(ByteBuffer.wrap(data), TlsConstants.HandshakeType.new_session_ticket);

        assertThat(extension.getMaxEarlyDataSize()).isEqualTo(2147483648L);
    }

    @Test
    void clientHelloEarlyDataExtensionShouldByEmpty() throws Exception {
        assertThatThrownBy(() ->
                new EarlyDataExtension(ByteBuffer.wrap(ByteUtils.hexToBytes("002a 0004 0000")), TlsConstants.HandshakeType.client_hello)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void serializeEarlyDataExtensionWithEarlyDataSize() {
        var earlyDataExtension = new EarlyDataExtension(1024 * 1024);
        assertThat(earlyDataExtension.getBytes()).isEqualTo(ByteUtils.hexToBytes("002a 0004 00100000"));
    }

    @Test
    void serializeEarlyDataExtensionWithLargeEarlyDataSize() {
        var earlyDataExtension = new EarlyDataExtension(0x80000000L);
        assertThat(earlyDataExtension.getBytes()).isEqualTo(ByteUtils.hexToBytes("002a 0004 80000000"));
    }
}