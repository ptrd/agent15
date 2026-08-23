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
package tech.kwik.agent15.extension;

import org.junit.jupiter.api.Test;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.TlsProtocolException;
import tech.kwik.agent15.alert.DecodeErrorException;
import tech.kwik.agent15.util.ByteUtils;

import java.nio.ByteBuffer;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KeyShareExtensionTest {

    @Test
    void parseClientKeyShareWithOneEntry() throws Exception {
        String rawData = "0033" + "0047" + "0045" + "0017" + "0041" + "045d58e52e3deee2e8b78ec51e2d0cedb5080c8244bd3f651219cc48f3d3d404399d6748ab3eaaca0e32b927fc5e8107628e636b614cab332d8637c1d61caccdda";
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(rawData));

        KeyShareExtension keyShareExtension = new KeyShareExtension(buffer, TlsConstants.HandshakeType.client_hello);

        assertThat(keyShareExtension.getKeyShareEntries()).hasSize(1);
        assertThat(keyShareExtension.getKeyShareEntries().get(0).getNamedGroup()).isEqualTo(TlsConstants.NamedGroup.secp256r1);
        assertThat(keyShareExtension.getKeyShareEntries().get(0).getKeyExchangeData()).startsWith(0x04, 0x5d, 0x58, 0xe5, 0x2e, 0x3d, 0xee, 0xe2);
    }

    @Test
    void parseClientKeyShareWithMultipleEntries() throws Exception {
        String rawData = "0033008c" + "008a"
        + "00170041045d58e52e3deee2e8b78ec51e2d0cedb5080c8244bd3f651219cc48f3d3d404399d6748ab3eaaca0e32b927fc5e8107628e636b614cab332d8637c1d61caccdda"
        + "00170041045d58e52e3deee2e8b78ec51e2d0cedb5080c8244bd3f651219cc48f3d3d404399d6748ab3eaaca0e32b927fc5e8107628e636b614cab332d8637c1d61caccdda";
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(rawData));

        KeyShareExtension keyShareExtension = new KeyShareExtension(buffer, TlsConstants.HandshakeType.client_hello);

        assertThat(keyShareExtension.getKeyShareEntries()).hasSize(2);
        for (int i = 0; i < 2; i++) {
            assertThat(keyShareExtension.getKeyShareEntries().get(i).getNamedGroup()).isEqualTo(TlsConstants.NamedGroup.secp256r1);
            assertThat(keyShareExtension.getKeyShareEntries().get(0).getKeyExchangeData()).startsWith(0x04, 0x5d, 0x58, 0xe5, 0x2e, 0x3d, 0xee, 0xe2);
        }
    }

    @Test
    void parseClientKeyShareWithSingleEntryLargerBuffer() throws Exception {
        String rawData = "00330047" + "0045"
        + "00170041045d58e52e3deee2e8b78ec51e2d0cedb5080c8244bd3f651219cc48f3d3d404399d6748ab3eaaca0e32b927fc5e8107628e636b614cab332d8637c1d61caccdda"
        + "00170041045d58e52e3deee2e8b78ec51e2d0cedb5080c8244bd3f651219cc48f3d3d404399d6748ab3eaaca0e32b927fc5e8107628e636b614cab332d8637c1d61caccdda";
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(rawData));

        KeyShareExtension keyShareExtension = new KeyShareExtension(buffer, TlsConstants.HandshakeType.client_hello);

        assertThat(keyShareExtension.getKeyShareEntries()).hasSize(1);
    }

    @Test
    void parseEmptyClientKeyShare() throws Exception {
        String rawData = "0033" + "0002" + "0000";
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(rawData));

        KeyShareExtension keyShareExtension = new KeyShareExtension(buffer, TlsConstants.HandshakeType.client_hello);

        assertThat(keyShareExtension.getKeyShareEntries()).hasSize(0);
    }

    @Test
    void parseServerKeyShare() throws Exception {
        String rawData = "0033" + "0045" + "0017"
                + "004104ace3b035eba5dd75860925b2c9b206656f2d1590f8c596d96a2a91adb442b378240002c8ef8360ba6104033c02eb3ab9ebcce036c735892697dda158f91c786e002b00020304";
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(rawData));

        KeyShareExtension keyShareExtension = new KeyShareExtension(buffer, TlsConstants.HandshakeType.server_hello);

        assertThat(keyShareExtension.getKeyShareEntries()).hasSize(1);
        assertThat(keyShareExtension.getKeyShareEntries().get(0).getNamedGroup()).isEqualTo(TlsConstants.NamedGroup.secp256r1);
        assertThat(keyShareExtension.getKeyShareEntries().get(0).getKeyExchangeData()).startsWith(0x04, 0xac, 0xe3, 0xb0, 0x35, 0xeb, 0xa5, 0xdd);
    }

    @Test
    void parseHelloRetryRequestKeyShareExtension() throws Exception {
        String rawData = "003300020017";
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(rawData));

        KeyShareExtension keyShareExtension = new KeyShareExtension(buffer, TlsConstants.HandshakeType.server_hello, true);

        assertThat(keyShareExtension.getKeyShareEntries()).hasSize(1);
        assertThat(keyShareExtension.getKeyShareEntries().get(0).getNamedGroup()).isEqualTo(TlsConstants.NamedGroup.secp256r1);
        assertThat(keyShareExtension.getKeyShareEntries().get(0).getKeyExchangeData()).isNull();
    }

    @Test
    void parsingDataMissingExtensionLengthThrows() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("003300"));

        assertThatThrownBy(
                () -> new KeyShareExtension(buffer, TlsConstants.HandshakeType.client_hello)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parsingZeroExtensionLengthThrows() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("00330000"));

        assertThatThrownBy(
                () -> new KeyShareExtension(buffer, TlsConstants.HandshakeType.client_hello)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parsingDataUnderflowThrows() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("00330047004500170041045d58e52e3deee2e8b78ec51e2d"));

        assertThatThrownBy(
                () -> new KeyShareExtension(buffer, TlsConstants.HandshakeType.client_hello)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parsingInconsistentLengths1Throws() {
        String rawData = "0033" + "0047" + "0041"
                + "00170041045d58e52e3deee2e8b78ec51e2d0cedb5080c8244bd3f651219cc48f3d3d404399d6748ab3eaaca0e32b927fc5e8107628e636b614cab332d8637c1d61caccdda";
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(rawData));

        assertThatThrownBy(
                () -> new KeyShareExtension(buffer, TlsConstants.HandshakeType.client_hello)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parsingInconsistentLengths2Throws() {
        String rawData = "0033" + "0046" + "0044" + "0017" + "0041"
                + "045d58e52e3deee2e8b78ec51e2d0cedb5080c8244bd3f651219cc48f3d3d404399d6748ab3eaaca0e32b927fc5e8107628e636b614cab332d8637c1d61caccdda0f0f0f0f";
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(rawData));

        assertThatThrownBy(
                () -> new KeyShareExtension(buffer, TlsConstants.HandshakeType.client_hello)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parsingIncorrectKeyEntryLengthThrows() {
        String rawData = "0033" + "0049" + "0047" + "0017" + "0041"
                + "045d58e52e3deee2e8b78ec51e2d0cedb5080c8244bd3f651219cc48f3d3d404399d6748ab3eaaca0e32b927fc5e8107628e636b614cab332d8637c1d61caccdda"
        + "0017";
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(rawData));

        assertThatThrownBy(
                () -> new KeyShareExtension(buffer, TlsConstants.HandshakeType.client_hello)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parsingInvalidNamedGroupShouldBeIgnored() throws TlsProtocolException {
        String rawData = "0033" + "008c" + "008a"
                + "00130041045d58e52e3deee2e8b78ec51e2d0cedb5080c8244bd3f651219cc48f3d3d404399d6748ab3eaaca0e32b927fc5e8107628e636b614cab332d8637c1d61caccdda"
                + "00170041045d58e52e3deee2e8b78ec51e2d0cedb5080c8244bd3f651219cc48f3d3d404399d6748ab3eaaca0e32b927fc5e8107628e636b614cab332d8637c1d61caccdda";
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(rawData));

        // When
        List<KeyShareExtension.KeyShareEntry> keyShareEntries = new KeyShareExtension(buffer, TlsConstants.HandshakeType.client_hello).getKeyShareEntries();

        // Then
        assertThat(keyShareEntries)
                .hasSize(1)
                .anyMatch(entry -> entry.getNamedGroup() == TlsConstants.NamedGroup.secp256r1);
    }

    @Test
    void parsingUnsupportedNamedGroupShouldWork() throws TlsProtocolException {
        String rawData = "0033" + "008c" + "008a"
                // ffdhe2048(0x0100)
                + "01000041045d58e52e3deee2e8b78ec51e2d0cedb5080c8244bd3f651219cc48f3d3d404399d6748ab3eaaca0e32b927fc5e8107628e636b614cab332d8637c1d61caccdda"
                // secp256r1(0x0017)
                + "00170041045d58e52e3deee2e8b78ec51e2d0cedb5080c8244bd3f651219cc48f3d3d404399d6748ab3eaaca0e32b927fc5e8107628e636b614cab332d8637c1d61caccdda";
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(rawData));

        // When
        List<KeyShareExtension.KeyShareEntry> keyShareEntries = new KeyShareExtension(buffer, TlsConstants.HandshakeType.client_hello).getKeyShareEntries();

        // Then
        assertThat(keyShareEntries)
                .hasSize(2)
                .anyMatch(entry ->
                        entry.getNamedGroup() == TlsConstants.NamedGroup.secp256r1 || entry.getNamedGroup() == TlsConstants.NamedGroup.ffdhe2048);
    }

    @Test
    void parsingKeyLengthHighBitSetForUnknownGroupShouldThrow() {
        String rawData = "0033" + "0006" + "0004" + "fafa" + "8000";
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(rawData));

        assertThatThrownBy(
                () -> new KeyShareExtension(buffer, TlsConstants.HandshakeType.client_hello)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parsingIllegalSecp256r1KeyLengthThrows() {
        String rawData = "0033" + "0046" + "0044" + "0017"
                + "0042045d58e52e3deee2e8b78ec51e2d0cedb5080c8244bd3f651219cc48f3d3d404399d6748ab3eaaca0e32b927fc5e8107628e636b614cab332d8637c1d61caccdda0f0f";
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes(rawData));

        assertThatThrownBy(
                () -> new KeyShareExtension(buffer, TlsConstants.HandshakeType.client_hello)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void serializeClientKeyShare() throws Exception {
        byte[] rawKeyExchangeData = ByteUtils.hexToBytes(
                "045d58e52e3deee2e8b78ec51e2d0cedb5080c8244bd3f651219cc48f3d3d404399d6748ab3eaaca0e32b927fc5e8107628e636b614cab332d8637c1d61caccdda");

        KeyShareExtension keyShareExtension = new KeyShareExtension(rawKeyExchangeData, TlsConstants.NamedGroup.secp256r1, TlsConstants.HandshakeType.client_hello);
        byte[] serialized = keyShareExtension.getBytes();

        assertThat(serialized).isEqualTo(ByteUtils.hexToBytes("0033" + "0047" + "0045" + "0017" + "0041"
                + "045d58e52e3deee2e8b78ec51e2d0cedb5080c8244bd3f651219cc48f3d3d404399d6748ab3eaaca0e32b927fc5e8107628e636b614cab332d8637c1d61caccdda"));
    }

    @Test
    void serializeServerKeyShare() throws Exception {
        byte[] rawKeyExchangeData = ByteUtils.hexToBytes(
                "045d58e52e3deee2e8b78ec51e2d0cedb5080c8244bd3f651219cc48f3d3d404399d6748ab3eaaca0e32b927fc5e8107628e636b614cab332d8637c1d61caccdda");
        KeyShareExtension keyShareExtension = new KeyShareExtension(rawKeyExchangeData, TlsConstants.NamedGroup.secp256r1, TlsConstants.HandshakeType.server_hello);
        byte[] serialized = keyShareExtension.getBytes();

        assertThat(serialized).isEqualTo(ByteUtils.hexToBytes("0033" + "0045" + "0017" + "0041"
                + "045d58e52e3deee2e8b78ec51e2d0cedb5080c8244bd3f651219cc48f3d3d404399d6748ab3eaaca0e32b927fc5e8107628e636b614cab332d8637c1d61caccdda"));
    }

    @Test
    void serializeKeyShareWithKeyOfDifferentLength() throws Exception {
        // The length of the key exchange data is determined by the key exchange method, not by this extension.
        byte[] rawKeyExchangeData = ByteUtils.hexToBytes("0001020304050607");

        KeyShareExtension keyShareExtension = new KeyShareExtension(rawKeyExchangeData, TlsConstants.NamedGroup.x25519, TlsConstants.HandshakeType.server_hello);
        byte[] serialized = keyShareExtension.getBytes();

        assertThat(serialized).isEqualTo(ByteUtils.hexToBytes("0033" + "000c" + "001d" + "0008" + "0001020304050607"));
    }

    @Test
    void serializedKeyShareIsNotLongerThanItsContent() throws Exception {
        byte[] rawKeyExchangeData = ByteUtils.hexToBytes("0001020304050607");

        KeyShareExtension keyShareExtension = new KeyShareExtension(rawKeyExchangeData, TlsConstants.NamedGroup.x25519, TlsConstants.HandshakeType.client_hello);
        byte[] serialized = keyShareExtension.getBytes();

        // Extension type (2) + extension length (2) + entries length (2) + named group (2) + key length (2) + key
        assertThat(serialized).hasSize(10 + rawKeyExchangeData.length);
        int extensionDataLength = ByteBuffer.wrap(serialized).getShort(2) & 0xffff;
        assertThat(serialized).hasSize(4 + extensionDataLength);
    }
}
