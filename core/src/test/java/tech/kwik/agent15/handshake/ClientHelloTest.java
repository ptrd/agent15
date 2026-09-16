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
package tech.kwik.agent15.handshake;

import org.junit.jupiter.api.Test;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.alert.DecodeErrorException;
import tech.kwik.agent15.alert.IllegalParameterAlert;
import tech.kwik.agent15.extension.ApplicationLayerProtocolNegotiationExtension;
import tech.kwik.agent15.extension.Extension;
import tech.kwik.agent15.extension.KeyShareExtension;
import tech.kwik.agent15.extension.PskKeyExchangeModesExtension;
import tech.kwik.agent15.extension.ServerNameExtension;
import tech.kwik.agent15.extension.SignatureAlgorithmsExtension;
import tech.kwik.agent15.extension.SupportedGroupsExtension;
import tech.kwik.agent15.extension.SupportedVersionsExtension;
import tech.kwik.agent15.util.ByteUtils;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static tech.kwik.agent15.TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256;
import static tech.kwik.agent15.TlsConstants.CipherSuite.TLS_AES_256_GCM_SHA384;
import static tech.kwik.agent15.TlsConstants.NamedGroup.secp256r1;
import static tech.kwik.agent15.TlsConstants.NamedGroup.secp384r1;
import static tech.kwik.agent15.TlsConstants.NamedGroup.x25519;
import static tech.kwik.agent15.TlsConstants.NamedGroup.x448;
import static tech.kwik.agent15.TlsConstants.SignatureScheme.rsa_pss_rsae_sha256;

class ClientHelloTest {

    private static final byte[] KEY_EXCHANGE_DATA = ByteUtils.hexToBytes("045d58e52e3deee2e8b78ec51e2d0cedb5080c8244bd3f651219cc48f3d3d404399d6748ab3eaaca0e32b927fc5e8107628e636b614cab332d8637c1d61caccdda");

    @Test
    void parseClientHello() throws Exception {
        //                                      length v1.2 random
        byte[] data = ByteUtils.hexToBytes(("01 000103 0303 2411ec38adb041713ca81a04182a655b567ecc8c4935e082ec20bb233d57aff2"
                //    cipher         comp ext's length
                + "00 0004 1301 1302 0100 00d6"
                // server name extension                version ext    supported groups extension
                + "0000000e000c0000096c6f63616c686f7374 002b0003020304 000a000400020017"
                // signature algorithms extension
                + "000d00140012040308040401050308050501080606010201"
                // key share extension
                + "00330047004500170041045d58e52e3deee2e8b78ec51e2d0cedb5080c8244bd3f651219cc48f3d3d404399d6748ab3eaaca0e32b927fc5e8107628e636b614cab332d8637c1d61caccdda"
                // psk key exchange modes extension
                + "002d00020101"
                // unknown extension (QUIC transport parameters)
                + "ffa500340032000100048000ea6000040004802625a0000500048003d090000600048003d090000700048003d09000080001010009000101"
                // unknown extension (ec_point_formats)  alpn extension
                + "000b000403000102" +                  "0010000800060568712d3234").replaceAll(" ", ""));
        ClientHello ch = new ClientHello(ByteBuffer.wrap(data), null);

        assertThat(ch.getClientRandom()).isEqualTo(ByteUtils.hexToBytes("2411ec38adb041713ca81a04182a655b567ecc8c4935e082ec20bb233d57aff2"));
        assertThat(ch.getCipherSuites()).containsExactly(TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384);
        assertThat(ch.getExtensions()).hasAtLeastOneElementOfType(ServerNameExtension.class);
        assertThat(ch.getExtensions()).hasAtLeastOneElementOfType(SignatureAlgorithmsExtension.class);
        assertThat(ch.getExtensions()).hasAtLeastOneElementOfType(KeyShareExtension.class);
        assertThat(ch.getExtensions()).hasAtLeastOneElementOfType(PskKeyExchangeModesExtension.class);
        assertThat(ch.getExtensions()).hasAtLeastOneElementOfType(ApplicationLayerProtocolNegotiationExtension.class);
        assertThat(ch.getExtensions()).hasSize(9);
    }

    @Test
    void parseMinimalClientHello() throws Exception {
        byte[] data = ByteUtils.hexToBytes(("01 00002b 0303 2411ec38adb041713ca81a04182a655b567ecc8c4935e082ec20bb233d57aff2"
                //    cipher    comp ext's length
                + "00 0002 1301 0100 0000").replaceAll(" ", ""));
        ClientHello ch = new ClientHello(ByteBuffer.wrap(data), null);
        assertThat(ch.getClientRandom()).isEqualTo(ByteUtils.hexToBytes("2411ec38adb041713ca81a04182a655b567ecc8c4935e082ec20bb233d57aff2"));
        assertThat(ch.getCipherSuites()).containsExactly(TLS_AES_128_GCM_SHA256);
        assertThat(ch.getExtensions()).hasSize(0);
    }

    @Test
    void parseClientHelloFromBufferWithNonZeroStartPosition() throws Exception {
        byte[] clientHelloData = ByteUtils.hexToBytes(("01 00002b 0303 2411ec38adb041713ca81a04182a655b567ecc8c4935e082ec20bb233d57aff2"
                //    cipher    comp ext's length
                + "00 0002 1301 0100 0000").replaceAll(" ", ""));

        // Place the ClientHello message in a buffer that is preceded by some other bytes, so its start position is not 0.
        byte[] prefix = new byte[] { 0x16, 0x03, 0x01, 0x00, 0x2f };
        ByteBuffer buffer = ByteBuffer.allocate(prefix.length + clientHelloData.length);
        buffer.put(prefix);
        buffer.put(clientHelloData);
        buffer.position(prefix.length);  // position the buffer at the start of the ClientHello message

        ClientHello ch = new ClientHello(buffer, null);

        // The raw bytes captured during parsing should be exactly the ClientHello message
        assertThat(ch.getBytes()).isEqualTo(clientHelloData);
    }

    @Test
    void parseClientHelloWithInvalidLength() throws Exception {
        byte[] data = ByteUtils.hexToBytes(("01 00092b 0303 2411ec38adb041713ca81a04182a655b567ecc8c4935e082ec20bb233d57aff2"
                //    cipher    comp ext's length
                + "00 0002 1301 0100 0000").replaceAll(" ", ""));

        assertThatThrownBy(() ->
                new ClientHello(ByteBuffer.wrap(data), null)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseClientHelloWithIncorrectClientRamdom() throws Exception {
        byte[] data = ByteUtils.hexToBytes(("01 00092b 0303 2411ec38adb04171"  // 8 bytes instead of 32
                //    cipher    comp ext's length
                + "00 0002 1301 0100 0000").replaceAll(" ", ""));

        assertThatThrownBy(() ->
                new ClientHello(ByteBuffer.wrap(data), null)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseClientHelloWithInValidCipher() throws Exception {
        byte[] data = ByteUtils.hexToBytes(("01 00002b 0303 2411ec38adb041713ca81a04182a655b567ecc8c4935e082ec20bb233d57aff2"
                //    cipher    comp ext's length
                + "00 0002 130f 0100 0000").replaceAll(" ", ""));

        ClientHello ch = new ClientHello(ByteBuffer.wrap(data), null);
        assertThat(ch.getCipherSuites()).isEmpty();
    }

    @Test
    void clientHelloWithSessionIdLengthWithHighBitSetShouldBeRejected() throws Exception {
        byte[] data = ByteUtils.hexToBytes(("01 000122 0303 2411ec38adb041713ca81a04182a655b567ecc8c4935e082ec20bb233d57aff2"
                // sessionIdLength byte = 0xff
                + "ff"
                // 255 bytes that — read as cipher_suites/compression/extensions after the desync — parse as:
                // empty ciphers, valid compression, empty extensions, and trailing padding.
                + "000001000000" + "00".repeat(249)).replaceAll(" ", ""));

        assertThatThrownBy(() ->
                new ClientHello(ByteBuffer.wrap(data), null)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void clientHelloWithCipherSuitesLengthExceedingBufferShouldBeRejected() throws Exception {
        byte[] data = ByteUtils.hexToBytes(("01 00002b 0303 2411ec38adb041713ca81a04182a655b567ecc8c4935e082ec20bb233d57aff2"
                //    ciphers length 0x7ffe
                + "00 7ffe 130113021303").replaceAll(" ", ""));

        assertThatThrownBy(() ->
                new ClientHello(ByteBuffer.wrap(data), null)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void clientHelloWithCipherSuitesLengthHighBitSetShouldBeRejected() throws Exception {
        byte[] data = ByteUtils.hexToBytes(("01 00002b 0303 2411ec38adb041713ca81a04182a655b567ecc8c4935e082ec20bb233d57aff2"
                //    ciphers length 8000
                + "00 8000 0100 0000      0000").replaceAll(" ", ""));

        assertThatThrownBy(() ->
                new ClientHello(ByteBuffer.wrap(data), null)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void clientHelloTruncatedInSessionIdShouldThrow() throws Exception {
        byte[] data = ByteUtils.hexToBytes(("01 00002b 0303 2411ec38adb041713ca81a04182a655b567ecc8c4935e082ec20bb233d57aff2"
                // sessionIdLength = 10, but only 8 bytes remain in the buffer after that byte
                + "0a 0000000000000000").replaceAll(" ", ""));

        assertThatThrownBy(() ->
                new ClientHello(ByteBuffer.wrap(data), null)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void clientHelloTruncatedAfterCipherSuitesShouldThrowDecodeError() throws Exception {
        // Buffer ends exactly after cipher suites — no room for the 2 compression-method bytes.
        byte[] data = ByteUtils.hexToBytes(("01 00002b 0303 2411ec38adb041713ca81a04182a655b567ecc8c4935e082ec20bb233d57aff2"
                //    ciphersLen  3 ciphers — buffer ends here, no compression bytes
                + "00 0006 130113021303").replaceAll(" ", ""));

        assertThatThrownBy(() ->
                new ClientHello(ByteBuffer.wrap(data), null)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseClientHelloWithPreSharedKeyExtensionNotAsLast() throws Exception {
        byte[] data = ByteUtils.hexToBytes(("01 00002b 0303 2411ec38adb041713ca81a04182a655b567ecc8c4935e082ec20bb233d57aff2"
                //    cipher    comp ext's length
                + "00 0002 1301 0100 0046"
                // pre shared key ext
                + "0029 003b 0016 0010 000102030405060708090a0b0c0d0e0f ffffffff 0021 20 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"
                // version ext
                + "002b0003020304"));

        assertThatThrownBy(() ->
                new ClientHello(ByteBuffer.wrap(data), null)
        )
                .isInstanceOf(IllegalParameterAlert.class)
                .hasMessageContaining("last extensio");
    }

    @Test
    void clientHelloWithoutExplicitSupportedGroupsOffersOnlyTheKeyShareGroup() {
        // When
        ClientHello ch = createClientHello(secp256r1);

        // Then
        assertThat(supportedGroupsOf(ch)).containsExactly(secp256r1);
    }

    @Test
    void clientHelloOffersExactlyTheGivenSupportedGroups() {
        // When
        ClientHello ch = createClientHello(secp256r1, List.of(secp256r1, x448, x25519));

        // Then
        assertThat(supportedGroupsOf(ch)).containsExactly(secp256r1, x448, x25519);
    }

    @Test
    void supportedGroupsAreOfferedInGivenOrderEvenWhenKeyShareGroupIsNotFirst() {
        // When
        ClientHello ch = createClientHello(x25519, List.of(x448, x25519, secp256r1));

        // Then
        assertThat(supportedGroupsOf(ch)).containsExactly(x448, x25519, secp256r1);
    }

    @Test
    void keyShareUsesTheGivenGroupIndependentOfTheSupportedGroups() {
        // When
        ClientHello ch = createClientHello(x25519, List.of(secp256r1, x448, x25519));

        // Then
        KeyShareExtension keyShare = (KeyShareExtension) extensionOfType(ch, KeyShareExtension.class);
        assertThat(keyShare.getKeyShareEntries())
                .extracting(KeyShareExtension.KeyShareEntry::getNamedGroup)
                .containsExactly(x25519);
    }

    @Test
    void supportedGroupsSurviveSerializationRoundTrip() throws Exception {
        // Given
        ClientHello ch = createClientHello(secp256r1, List.of(secp256r1, x448, x25519));

        // When
        ClientHello parsed = new ClientHello(ByteBuffer.wrap(ch.getBytes()), null);

        // Then
        assertThat(supportedGroupsOf(parsed)).containsExactly(secp256r1, x448, x25519);
    }

    @Test
    void keyShareGroupThatIsNotInSupportedGroupsThrows() {
        assertThatThrownBy(() ->
                // When
                createClientHello(secp384r1, List.of(secp256r1, x448, x25519))
        )
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("supportedGroups");
    }

    @Test
    void emptySupportedGroupsThrows() {
        assertThatThrownBy(() ->
                // When
                createClientHello(secp256r1, Collections.emptyList())
        ).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void clientHelloCreatedFromPartsUsesGivenRandomSessionIdAndExtensions() throws Exception {
        // Given
        byte[] clientRandom = new byte[32];
        Arrays.fill(clientRandom, (byte) 0x5a);
        byte[] sessionId = new byte[32];
        Arrays.fill(sessionId, (byte) 0xa5);
        List<Extension> extensions = List.of(
                new ServerNameExtension("localhost"),
                new SupportedVersionsExtension(TlsConstants.HandshakeType.client_hello));

        // When
        ClientHello clientHello = new ClientHello(clientRandom, sessionId, List.of(TLS_AES_128_GCM_SHA256), extensions, null);

        // Then
        assertThat(clientHello.getClientRandom()).isEqualTo(clientRandom);
        assertThat(clientHello.getSessionId()).isEqualTo(sessionId);
        assertThat(clientHello.getCipherSuites()).containsExactly(TLS_AES_128_GCM_SHA256);
        // No extension is added on top of the ones given.
        assertThat(clientHello.getExtensions()).isEqualTo(extensions);

        // And the serialized message can be parsed back into an equivalent message.
        ClientHello parsed = new ClientHello(ByteBuffer.wrap(clientHello.getBytes()), null);
        assertThat(parsed.getClientRandom()).isEqualTo(clientRandom);
        assertThat(parsed.getCipherSuites()).containsExactly(TLS_AES_128_GCM_SHA256);
        assertThat(parsed.getExtensions()).hasSize(2);
        assertThat(parsed.getBytes()).isEqualTo(clientHello.getBytes());
    }

    @Test
    void clientHelloCreatedFromPartsCanRepeatTheExtensionsOfAnotherClientHello() {
        // Given
        ClientHello first = createClientHello(secp256r1);

        // When: build a second client hello the way it must be done after a hello retry request: same random, same
        // session id, same cipher suites, and the extensions of the first one.
        ClientHello second = new ClientHello(first.getClientRandom(), first.getSessionId(), first.getCipherSuites(),
                first.getExtensions(), null);

        // Then
        assertThat(second.getBytes()).isEqualTo(first.getBytes());
    }

    private ClientHello createClientHello(TlsConstants.NamedGroup keyShareGroup) {
        return new ClientHello("localhost", keyShareGroup, KEY_EXCHANGE_DATA, false,
                List.of(TLS_AES_128_GCM_SHA256), List.of(rsa_pss_rsae_sha256),
                Collections.emptyList(), null, ClientHello.PskKeyEstablishmentMode.none);
    }

    private ClientHello createClientHello(TlsConstants.NamedGroup keyShareGroup, List<TlsConstants.NamedGroup> supportedGroups) {
        return new ClientHello("localhost", keyShareGroup, KEY_EXCHANGE_DATA, false,
                List.of(TLS_AES_128_GCM_SHA256), List.of(rsa_pss_rsae_sha256), supportedGroups,
                Collections.emptyList(), null, ClientHello.PskKeyEstablishmentMode.none);
    }

    private List<TlsConstants.NamedGroup> supportedGroupsOf(ClientHello clientHello) {
        return ((SupportedGroupsExtension) extensionOfType(clientHello, SupportedGroupsExtension.class)).getNamedGroups();
    }

    private Extension extensionOfType(ClientHello clientHello, Class<? extends Extension> type) {
        return clientHello.getExtensions().stream()
                .filter(type::isInstance)
                .findFirst()
                .orElseThrow(() -> new AssertionError("ClientHello does not contain a " + type.getSimpleName()));
    }
}
