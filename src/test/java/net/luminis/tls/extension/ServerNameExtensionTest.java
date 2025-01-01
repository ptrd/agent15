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
package net.luminis.tls.extension;

import net.luminis.tls.alert.DecodeErrorException;
import net.luminis.tls.util.ByteUtils;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ServerNameExtensionTest {

    @Test
    void parseServerNameExtension() throws Exception {
        //                                                        type    ext sz    list sz enum   length   hostname
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("0000" + "000e" + "000c" + "00" + "0009" + "6c6f63616c686f7374"));

        ServerNameExtension serverNameExtension = new ServerNameExtension(buffer);

        assertThat(serverNameExtension.getHostName()).isEqualToIgnoringCase("localhost");
    }

    @Test
    void serializeServerNameExtension() throws Exception {
        byte[] serializedData = new ServerNameExtension("localhost").getBytes();

        ServerNameExtension serverNameExtension = new ServerNameExtension(ByteBuffer.wrap(serializedData));

        assertThat(serverNameExtension.getHostName()).isEqualToIgnoringCase("localhost");
        assertThat(serializedData).startsWith(0x00, 0x00, 0x00, 0x0e, 0x00, 0x0c, 0x00, 0x00, 0x09);
    }

    @Test
    void parseUnderflow1() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("0000" + "000e" + "000c" + "00" + "0009"));

        assertThatThrownBy(() ->
                new ServerNameExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseUnderflow2() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("0000" + "000e" + "000c" + "00" + "0009" + "6c6f63616c686f73"));

        assertThatThrownBy(() ->
                new ServerNameExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseUnderflow3() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("0000" + "0003" + "0001" + "00"));

        assertThatThrownBy(() ->
                new ServerNameExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseOverflow() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("0000" + "000e" + "000c" + "00" + "000a" + "6c6f63616c686f737475"));

        assertThatThrownBy(() ->
                new ServerNameExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseInconsistentLength1() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("0000" + "000e" + "000b" + "00" + "0009" + "6c6f63616c686f7374"));

        assertThatThrownBy(() ->
                new ServerNameExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseInconsistentLength2() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("0000" + "000e" + "000c" + "00" + "0007" + "6c6f63616c686f7374"));

        assertThatThrownBy(() ->
                new ServerNameExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseEmptyExtension() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("00000000"));

        ServerNameExtension serverNameExtension = new ServerNameExtension(buffer);

        assertThat(serverNameExtension.getHostName()).isNull();
    }

    @Test
    void parseBufferLargerThenExtension() throws Exception {
        //                                                        type    ext sz    list sz enum   length   hostname
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("0000" + "000e" + "000c" + "00" + "0009" + "6c6f63616c686f7374"
                + "cafebabe"));

        ServerNameExtension serverNameExtension = new ServerNameExtension(buffer);

        assertThat(serverNameExtension.getHostName()).isEqualToIgnoringCase("localhost");
    }

    @Test
    void whenDuringParsingUnknownNameTypeIsEncounteredIsShouldBeIgnored() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(
                // type  ext sz   list sz   enum  length  name
                "0000" + "0014" + "0012" + "ff" + "0003" + "abcdef"
                        // enum name sz  name
                        + "00" + "0009" + "6c6f63616c686f7374"));

        ServerNameExtension serverNameExtension = new ServerNameExtension(buffer);

        assertThat(serverNameExtension.getHostName()).isNotNull();
    }

    @Test
    void extensionShouldHaveAtLeastSizeTwoWhenNotEmpty() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("0000000100"));

        assertThatThrownBy(() ->
                new ServerNameExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseExtensionWithVeryLargeHostname() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("0000" + "000e" + "000c" + "00" + "8009" + "6c6f63616c686f7374"));

        assertThatThrownBy(() ->
                new ServerNameExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);
    }
}