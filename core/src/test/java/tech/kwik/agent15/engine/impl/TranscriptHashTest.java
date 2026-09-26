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
package tech.kwik.agent15.engine.impl;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.handshake.CertificateMessage;
import tech.kwik.agent15.handshake.ClientHello;
import tech.kwik.agent15.handshake.EncryptedExtensions;
import tech.kwik.agent15.handshake.FinishedMessage;
import tech.kwik.agent15.handshake.HelloRetryRequest;
import tech.kwik.agent15.handshake.ServerHello;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TranscriptHashTest {

    // Message types that occur both as a client and as a server message, and thus have two positions in the transcript.
    private static final List<TlsConstants.HandshakeType> AMBIGUOUS_TYPES = List.of(
            TlsConstants.HandshakeType.certificate,
            TlsConstants.HandshakeType.certificate_verify,
            TlsConstants.HandshakeType.finished);

    private TranscriptHash transcriptHash;

    @BeforeEach
    void initObjectUnderTest() {
        transcriptHash = new TranscriptHash(32);
    }

    @Test
    void computeSingleMessageHash() throws Exception {
        ClientHello ch = mock(ClientHello.class);
        when(ch.getType()).thenReturn(TlsConstants.HandshakeType.client_hello);
        when(ch.getBytes()).thenReturn(new byte[] { 0x01 });

        transcriptHash.record(ch);

        assertThat(transcriptHash.getHash(TlsConstants.HandshakeType.client_hello)).isEqualTo(computeHash(new byte[] { 0x01 }));
    }

    @Test
    void computeMessageSequenceHash() throws Exception {
        ClientHello ch = mock(ClientHello.class);
        when(ch.getType()).thenReturn(TlsConstants.HandshakeType.client_hello);
        when(ch.getBytes()).thenReturn(new byte[] { 0x01 });

        ServerHello sh = mock(ServerHello.class);
        when(sh.getType()).thenReturn(TlsConstants.HandshakeType.server_hello);
        when(sh.getBytes()).thenReturn(new byte[] { 0x02 });

        EncryptedExtensions ee = mock(EncryptedExtensions.class);
        when(ee.getType()).thenReturn(TlsConstants.HandshakeType.encrypted_extensions);
        when(ee.getBytes()).thenReturn(new byte[] { 0x03 });

        CertificateMessage cm = mock(CertificateMessage.class);
        when(cm.getType()).thenReturn(TlsConstants.HandshakeType.certificate);
        when(cm.getBytes()).thenReturn(new byte[] { 0x04 });

        transcriptHash.record(ch);
        transcriptHash.record(sh);
        transcriptHash.record(ee);
        transcriptHash.recordServer(cm);

        byte[] expected = computeHash(new byte[]{ 0x01 }, new byte[]{ 0x02 }, new byte[]{ 0x03 }, new byte[]{ 0x04 });
        assertThat(transcriptHash.getServerHash(TlsConstants.HandshakeType.certificate)).isEqualTo(expected);
    }

    @Test
    void computeMessageSequenceWithMissingMessagesHash() throws Exception {
        ClientHello ch = mock(ClientHello.class);
        when(ch.getType()).thenReturn(TlsConstants.HandshakeType.client_hello);
        when(ch.getBytes()).thenReturn(new byte[] { 0x01 });

        ServerHello sh = mock(ServerHello.class);
        when(sh.getType()).thenReturn(TlsConstants.HandshakeType.server_hello);
        when(sh.getBytes()).thenReturn(new byte[] { 0x02 });

        EncryptedExtensions ee = mock(EncryptedExtensions.class);
        when(ee.getType()).thenReturn(TlsConstants.HandshakeType.encrypted_extensions);
        when(ee.getBytes()).thenReturn(new byte[] { 0x03 });

        // No certificate message
        // No certificate verify message

        FinishedMessage sf = mock(FinishedMessage.class);
        when(sf.getType()).thenReturn(TlsConstants.HandshakeType.finished);
        when(sf.getBytes()).thenReturn(new byte[] { 0x06 });

        transcriptHash.record(ch);
        transcriptHash.record(sh);
        transcriptHash.record(ee);
        transcriptHash.recordServer(sf);

        byte[] expected = computeHash(new byte[]{ 0x01 }, new byte[]{ 0x02 }, new byte[]{ 0x03 }, new byte[]{ 0x06 });
        assertThat(transcriptHash.getServerHash(TlsConstants.HandshakeType.finished)).isEqualTo(expected);
    }

    @Test
    void afterHelloRetryRequestFirstClientHelloIsReplacedBySyntheticMessage() throws Exception {
        // Given
        ClientHello ch1 = mockClientHello(new byte[] { 0x01 });
        HelloRetryRequest hrr = mock(HelloRetryRequest.class);
        when(hrr.getBytes()).thenReturn(new byte[] { 0x11 });
        ClientHello ch2 = mockClientHello(new byte[] { 0x21 });
        ServerHello sh = mockServerHello(new byte[] { 0x02 });

        // When
        transcriptHash.record(ch1);
        transcriptHash.recordHelloRetryRequest(ch1, hrr);
        transcriptHash.record(ch2);
        transcriptHash.record(sh);

        // Then
        byte[] expected = computeHash(syntheticMessageHash(new byte[] { 0x01 }),
                new byte[] { 0x11 }, new byte[] { 0x21 }, new byte[] { 0x02 });
        assertThat(transcriptHash.getHash(TlsConstants.HandshakeType.server_hello)).isEqualTo(expected);
    }

    @Test
    void hashComputedBeforeHelloRetryRequestDoesNotAffectHashComputedAfterwards() throws Exception {
        // Given
        ClientHello ch1 = mockClientHello(new byte[] { 0x01 });
        transcriptHash.record(ch1);
        byte[] hashOfFirstClientHello = transcriptHash.getHash(TlsConstants.HandshakeType.client_hello);

        // When
        HelloRetryRequest hrr = mock(HelloRetryRequest.class);
        when(hrr.getBytes()).thenReturn(new byte[] { 0x11 });
        transcriptHash.recordHelloRetryRequest(ch1, hrr);
        transcriptHash.record(mockClientHello(new byte[] { 0x21 }));

        // Then
        byte[] expected = computeHash(syntheticMessageHash(new byte[] { 0x01 }), new byte[] { 0x11 }, new byte[] { 0x21 });
        assertThat(transcriptHash.getHash(TlsConstants.HandshakeType.client_hello))
                .isEqualTo(expected)
                .isNotEqualTo(hashOfFirstClientHello);
    }

    @Test
    void helloRetryRequestPrefixIsSyntheticMessageFollowedByHelloRetryRequest() throws Exception {
        // Given
        ClientHello ch1 = mockClientHello(new byte[] { 0x01 });
        HelloRetryRequest hrr = mock(HelloRetryRequest.class);
        when(hrr.getBytes()).thenReturn(new byte[] { 0x11, 0x12 });

        // When
        transcriptHash.recordHelloRetryRequest(ch1, hrr);

        // Then
        byte[] syntheticMessage = syntheticMessageHash(new byte[] { 0x01 });
        byte[] expected = ByteBuffer.allocate(syntheticMessage.length + 2)
                .put(syntheticMessage)
                .put(new byte[] { 0x11, 0x12 })
                .array();
        assertThat(transcriptHash.getHelloRetryRequestPrefix()).isEqualTo(expected);
    }

    @Test
    void withoutHelloRetryRequestThePrefixIsEmpty() {
        transcriptHash.record(mockClientHello(new byte[] { 0x01 }));

        assertThat(transcriptHash.getHelloRetryRequestPrefix()).isEmpty();
    }

    @Test
    void unambiguousHandshakeTypesMapOnExtendedTypeWithSameValue() {
        for (TlsConstants.HandshakeType handshakeType : TlsConstants.HandshakeType.values()) {
            if (AMBIGUOUS_TYPES.contains(handshakeType) || handshakeType == TlsConstants.HandshakeType.message_hash) {
                continue;
            }
            assertThat(TranscriptHash.convert(handshakeType).value)
                    .as("mapping of %s", handshakeType)
                    .isEqualTo(handshakeType.value);
        }
    }

    @Test
    void ambiguousHandshakeTypesCannotBeMappedWithoutClientOrServerIndication() {
        for (TlsConstants.HandshakeType handshakeType : AMBIGUOUS_TYPES) {
            assertThatThrownBy(() -> TranscriptHash.convert(handshakeType))
                    .as("mapping of %s", handshakeType)
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void ambiguousHandshakeTypesMapOnClientOrServerVariant() {
        for (TlsConstants.HandshakeType handshakeType : AMBIGUOUS_TYPES) {
            assertThat(TranscriptHash.convert(handshakeType, true).name())
                    .as("client variant of %s", handshakeType)
                    .isEqualTo("client_" + handshakeType.name());
            assertThat(TranscriptHash.convert(handshakeType, false).name())
                    .as("server variant of %s", handshakeType)
                    .isEqualTo("server_" + handshakeType.name());
        }
    }

    @Test
    void messageHashTypeHasNoPositionOfItsOwnInTheTranscript() {
        // The synthetic message_hash message replaces the first client hello, see
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.1; it is not a message that can be recorded as such.
        assertThatThrownBy(() -> TranscriptHash.convert(TlsConstants.HandshakeType.message_hash))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void recordingAnAmbiguousMessageTypeIsNotAllowed() {
        CertificateMessage cm = mock(CertificateMessage.class);
        when(cm.getType()).thenReturn(TlsConstants.HandshakeType.certificate);

        assertThatThrownBy(() -> transcriptHash.record(cm))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private ClientHello mockClientHello(byte[] bytes) {
        ClientHello ch = mock(ClientHello.class);
        when(ch.getType()).thenReturn(TlsConstants.HandshakeType.client_hello);
        when(ch.getBytes()).thenReturn(bytes);
        return ch;
    }

    private ServerHello mockServerHello(byte[] bytes) {
        ServerHello sh = mock(ServerHello.class);
        when(sh.getType()).thenReturn(TlsConstants.HandshakeType.server_hello);
        when(sh.getBytes()).thenReturn(bytes);
        return sh;
    }

    /**
     * Creates the synthetic message that replaces the first client hello in the transcript, see
     * https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.1: the message_hash handshake type, a uint24 length
     * and the hash of the first client hello.
     */
    private byte[] syntheticMessageHash(byte[] clientHello1) throws Exception {
        byte[] hash = computeHash(clientHello1);
        return ByteBuffer.allocate(4 + hash.length)
                .put(new byte[] { (byte) 0xfe, 0x00, 0x00, (byte) hash.length })
                .put(hash)
                .array();
    }

    private byte[] computeHash(byte[]... elements) throws Exception {
        String hashAlgorithm = "SHA-256";
        MessageDigest hashFunction = MessageDigest.getInstance(hashAlgorithm);
        for (byte[] data: elements) {
            hashFunction.update(data);
        }
        return hashFunction.digest();
    }

}