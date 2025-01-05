/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
import tech.kwik.agent15.alert.IllegalParameterAlert;
import tech.kwik.agent15.util.ByteUtils;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


class HandshakeMessageTest {

    @Test
    void parsingPreSharedKeyExtensionInEncryptedExtensionsShouldAbortHandshake() {
        byte[] rawData = ByteUtils.hexToBytes("0006 0029 0002 0000");

        assertThatThrownBy(() ->
                HandshakeMessage.parseExtensions(ByteBuffer.wrap(rawData), TlsConstants.HandshakeType.encrypted_extensions)
        )
                .isInstanceOf(IllegalParameterAlert.class)
                .hasMessageContaining("Extension not allowed")
                .hasMessageContaining("encrypted_extensions");
    }

    @Test
    void findPositionLastExtensionIfThereIsOnlyOne() {
        // ...                                 size
        byte[] rawData = ByteUtils.hexToBytes("0006 0029 0002 0000 cafebabe");

        assertThat(HandshakeMessage.findPositionLastExtension(ByteBuffer.wrap(rawData))).isEqualTo(2);
    }

    @Test
    void findPositionLastExtensionWithMultipleExtenions() {
        // ...                                 size 18 bytes                             24 bytes                                         6 bytes      not part of extensions
        byte[] rawData = ByteUtils.hexToBytes("0030 0000000e000c0000096c6f63616c686f7374 000d00140012040308040401050308050501080606010201 002900020000 cafebabe");

        assertThat(HandshakeMessage.findPositionLastExtension(ByteBuffer.wrap(rawData))).isEqualTo(44);
    }

    @Test
    void findPositionLastExtensionWithLargeLength() {
        // ...                                 size
        byte[] rawData = new byte[6 + 32768];
        System.arraycopy(ByteUtils.hexToBytes("0006 0029 8000"), 0, rawData, 0, 6);

        assertThat(HandshakeMessage.findPositionLastExtension(ByteBuffer.wrap(rawData))).isEqualTo(2);
    }
}