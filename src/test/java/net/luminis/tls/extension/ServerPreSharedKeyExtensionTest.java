/*
 * Copyright © 2021, 2022, 2023 Peter Doornbosch
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

import net.luminis.tls.alert.DecodeErrorException;
import net.luminis.tls.util.ByteUtils;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


class ServerPreSharedKeyExtensionTest {

    @Test
    void testParseValidExtension() throws Exception {
        byte[] data = ByteUtils.hexToBytes("0029 0002 0007");
        ServerPreSharedKeyExtension extension = new ServerPreSharedKeyExtension().parse(ByteBuffer.wrap(data));

        assertThat(extension.getSelectedIdentity()).isEqualTo(7);
    }

    @Test
    void parsingExtensionWithInvalidLengthFieldShouldThrow() {
        byte[] data = ByteUtils.hexToBytes("0029 0000 0007");
        assertThatThrownBy(
                () -> new ServerPreSharedKeyExtension().parse(ByteBuffer.wrap(data))
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseSerializedMessage() throws DecodeErrorException {
        byte[] data = new ServerPreSharedKeyExtension(89).getBytes();
        ServerPreSharedKeyExtension extension = new ServerPreSharedKeyExtension().parse(ByteBuffer.wrap(data));

        assertThat(extension.getSelectedIdentity()).isEqualTo(89);
    }
}