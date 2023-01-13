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


import net.luminis.tls.util.ByteUtils;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;

class ExtensionTest {

    @Test
    void testLargeExtensionDataLength() throws Exception {
        var ext = new Extension() {
            @Override
            public byte[] getBytes() {
                return new byte[0];
            }
        };

        byte[] data = new byte[4 + 0x8000];
        System.arraycopy(ByteUtils.hexToBytes("0000 8000"), 0, data, 0, 4);
        int extensionDataLength = ext.parseExtensionHeader(ByteBuffer.wrap(data), 0x00, 4);

        assertThat(extensionDataLength).isEqualTo(0x8000);
    }
}