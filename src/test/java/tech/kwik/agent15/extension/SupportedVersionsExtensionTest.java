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

import tech.kwik.agent15.util.ByteUtils;
import tech.kwik.agent15.alert.DecodeErrorException;
import tech.kwik.agent15.TlsConstants;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


class SupportedVersionsExtensionTest {

    @Test
    void testParseVersionExtensionInServerHello() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002b00020304"));

        SupportedVersionsExtension supportedVersionsExtension = new SupportedVersionsExtension(buffer, TlsConstants.HandshakeType.server_hello);

        assertThat(supportedVersionsExtension.getTlsVersion()).isEqualTo((short) 0x0304);
    }

    @Test
    void testParseVersionExtensionInClientHello() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002b0003020304"));

        SupportedVersionsExtension supportedVersionsExtension = new SupportedVersionsExtension(buffer, TlsConstants.HandshakeType.client_hello);

        assertThat(supportedVersionsExtension.getTlsVersion()).isEqualTo((short) 0x0304);
    }

    @Test
    void testSerializeVersionExtensionInClientHello() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(new SupportedVersionsExtension(TlsConstants.HandshakeType.client_hello).getBytes());

        SupportedVersionsExtension supportedVersionsExtension = new SupportedVersionsExtension(buffer, TlsConstants.HandshakeType.client_hello);

        assertThat(supportedVersionsExtension.getTlsVersion()).isEqualTo((short) 0x0304);
    }

    @Test
    void testSerializeVersionExtensionInServerHello() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello).getBytes());

        SupportedVersionsExtension supportedVersionsExtension = new SupportedVersionsExtension(buffer, TlsConstants.HandshakeType.server_hello);

        assertThat(supportedVersionsExtension.getTlsVersion()).isEqualTo((short) 0x0304);
    }

    @Test
    void parsingDataMissingExtensionLengthThrows() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002b00"));

        assertThatThrownBy(
                () -> new SupportedVersionsExtension(buffer, TlsConstants.HandshakeType.client_hello)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parsingDataUnderflowThrows() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002b00030203"));

        assertThatThrownBy(
                () -> new SupportedVersionsExtension(buffer, TlsConstants.HandshakeType.client_hello)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parsingDataUnderflowClientHelloVariant() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002b00020103"));

        assertThatThrownBy(
                () -> new SupportedVersionsExtension(buffer, TlsConstants.HandshakeType.client_hello)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parsingDataUnderflowServerHelloVariant() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002b000103"));

        assertThatThrownBy(
                () -> new SupportedVersionsExtension(buffer, TlsConstants.HandshakeType.server_hello)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parsingDataWithInconsistentLengthsClientHelloVariant() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002b00030403040303"));

        assertThatThrownBy(
                () -> new SupportedVersionsExtension(buffer, TlsConstants.HandshakeType.client_hello)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parsingDataWithInconsistentLengthsServerHelloVariant() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002b000403040303"));

        assertThatThrownBy(
                () -> new SupportedVersionsExtension(buffer, TlsConstants.HandshakeType.server_hello)
        ).isInstanceOf(DecodeErrorException.class);
    }
}