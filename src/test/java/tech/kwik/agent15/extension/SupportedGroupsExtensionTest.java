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
package tech.kwik.agent15.extension;

import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.alert.DecodeErrorException;
import tech.kwik.agent15.util.ByteUtils;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


class SupportedGroupsExtensionTest {

    @Test
    void testParseSingleGroup() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("000a000400020017"));

        SupportedGroupsExtension supportedGroupsExtension = new SupportedGroupsExtension(buffer);

        assertThat(supportedGroupsExtension.getNamedGroups()).contains(TlsConstants.NamedGroup.secp256r1);
    }

    @Test
    void testParseMultipleGroups() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("000a000800060017001d0100"));

        SupportedGroupsExtension supportedGroupsExtension = new SupportedGroupsExtension(buffer);

        assertThat(supportedGroupsExtension.getNamedGroups())
                .contains(TlsConstants.NamedGroup.secp256r1, TlsConstants.NamedGroup.x25519, TlsConstants.NamedGroup.ffdhe2048);
    }

    @Test
    void testSerializeSingleGroup() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(new SupportedGroupsExtension(TlsConstants.NamedGroup.secp384r1).getBytes());

        SupportedGroupsExtension supportedGroupsExtension = new SupportedGroupsExtension(buffer);

        assertThat(supportedGroupsExtension.getNamedGroups()).contains(TlsConstants.NamedGroup.secp384r1);
    }

    @Test
    void parsingDataMissingExtensionLengthThrows() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("000a00"));

        assertThatThrownBy(
                () -> new SupportedGroupsExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parsingDataUnderflowThrows() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("000a000800020017"));

        assertThatThrownBy(
                () -> new SupportedGroupsExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parsingDataWithInvalidDataLengthThrows() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("000a000300020017"));

        assertThatThrownBy(
                () -> new SupportedGroupsExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);

    }

    @Test
    void parsingDataWithInvalidGroupsLengthThrows() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("000a000400010017"));

        assertThatThrownBy(
                () -> new SupportedGroupsExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);

    }

    @Test
    void parsingDataWithInvalidGroupsLength() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("000a000300010017"));

        assertThatThrownBy(
                () -> new SupportedGroupsExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);

    }

    @Test
    void unkownCodePointForGroupShouldBeIgnored() throws Exception {
        // Given     (0x17 == secp256r1, 0x100 == ffdhe2048, 1a -> unknown      17  1a 100
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("000a000800060017001a0100"));

        // When
        SupportedGroupsExtension supportedGroupsExtension = new SupportedGroupsExtension(buffer);

        // Then
        assertThat(supportedGroupsExtension.getNamedGroups())
                .containsExactlyInAnyOrder(TlsConstants.NamedGroup.secp256r1, TlsConstants.NamedGroup.ffdhe2048);
    }
}