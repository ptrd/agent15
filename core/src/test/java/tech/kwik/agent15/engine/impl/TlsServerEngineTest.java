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
import org.mockito.ArgumentCaptor;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import tech.kwik.agent15.NewSessionTicket;
import tech.kwik.agent15.ProtectionKeysType;
import tech.kwik.agent15.alert.DecryptErrorAlert;
import tech.kwik.agent15.alert.HandshakeFailureAlert;
import tech.kwik.agent15.alert.IllegalParameterAlert;
import tech.kwik.agent15.alert.MissingExtensionAlert;
import tech.kwik.agent15.alert.ProtocolVersionAlert;
import tech.kwik.agent15.engine.KeyExchange;
import tech.kwik.agent15.engine.KeyExchangeFactory;
import tech.kwik.agent15.engine.ServerMessageSender;
import tech.kwik.agent15.engine.TlsStatusEventHandler;
import tech.kwik.agent15.extension.*;
import tech.kwik.agent15.handshake.ClientHello;
import tech.kwik.agent15.handshake.EncryptedExtensions;
import tech.kwik.agent15.handshake.FinishedMessage;
import tech.kwik.agent15.handshake.NewSessionTicketMessage;
import tech.kwik.agent15.handshake.ServerHello;
import tech.kwik.agent15.util.ByteUtils;
import tech.kwik.agent15.util.CertificateUtils;
import tech.kwik.agent15.util.KeyUtils;

import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;
import static tech.kwik.agent15.TlsConstants.*;
import static tech.kwik.agent15.TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256;
import static tech.kwik.agent15.TlsConstants.CipherSuite.TLS_CHACHA20_POLY1305_SHA256;
import static tech.kwik.agent15.TlsConstants.SignatureScheme.*;
import static tech.kwik.agent15.util.CertificateUtils.encodedKwikDotTechRsaCertificate;
import static tech.kwik.agent15.util.CertificateUtils.encodedKwikDotTechRsaCertificatePrivateKey;
import static tech.kwik.agent15.util.TestUtils.regardless;


public class TlsServerEngineTest {

    public static final byte[] KEY_EXCHANGE_DATA = ByteUtils.hexToBytes("045d58e52e3deee2e8b78ec51e2d0cedb5080c8244bd3f651219cc48f3d3d404399d6748ab3eaaca0e32b927fc5e8107628e636b614cab332d8637c1d61caccdda");

    private TlsServerEngineImpl engine;
    private ECPublicKey publicKey;
    private ServerMessageSender messageSender;
    private X509Certificate serverCertificate;
    private TlsStatusEventHandler tlsStatusHandler;
    private TlsSessionRegistryImpl tlsSessionRegistry;

    @BeforeEach
    void initObjectUnderTest() throws Exception {
        messageSender = mock(ServerMessageSender.class);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(encodedKwikDotTechRsaCertificatePrivateKey));
        PrivateKey privateKey = keyFactory.generatePrivate(keySpecPKCS8);

        serverCertificate = CertificateUtils.inflateCertificate(encodedKwikDotTechRsaCertificate);
        tlsStatusHandler = mock(TlsStatusEventHandler.class);
        tlsSessionRegistry = new TlsSessionRegistryImpl();
        engine = new TlsServerEngineImpl(List.of(serverCertificate), privateKey, List.of(rsa_pss_rsae_sha256), messageSender, tlsStatusHandler, tlsSessionRegistry) {
            protected boolean validateBinder(ClientHelloPreSharedKeyExtension.PskBinderEntry pskBinderEntry, int binderPosition, ClientHello clientHello) {
                return true;
            }
        };
        engine.addSupportedCiphers(List.of(TLS_AES_128_GCM_SHA256));

        publicKey = KeyUtils.generatePublicKey();
    }

    @Test
    void secondClientHelloMessageShouldBeIgnored() throws Exception {
        // Given
        engine.addSupportedCiphers(List.of(TLS_CHACHA20_POLY1305_SHA256));

        ClientHello clientHello1 =  new ClientHello("localhost", KEY_EXCHANGE_DATA, false,
                List.of(TLS_AES_128_GCM_SHA256),
                List.of(rsa_pss_rsae_sha256),
                NamedGroup.secp256r1, Collections.emptyList(), null, ClientHello.PskKeyEstablishmentMode.none);
        engine.received(clientHello1, ProtectionKeysType.None);

        // When
        ClientHello clientHello2 =  new ClientHello("localhost", KEY_EXCHANGE_DATA, false,
                List.of(TLS_CHACHA20_POLY1305_SHA256),   // Intentionally different cipher, this is the crux of the test!
                List.of(rsa_pss_rsae_sha256),
                NamedGroup.secp256r1, Collections.emptyList(), null, ClientHello.PskKeyEstablishmentMode.none);
        regardless(() ->
                engine.received(clientHello2, ProtectionKeysType.None)
        );

        // Then
        assertThat(engine.getSelectedCipher()).isEqualTo(TLS_AES_128_GCM_SHA256);
    }

    @Test
    void failingCipherNegotiationLeadsToHandshakeException() throws Exception {
        // Given
        ClientHello clientHello = new ClientHello("localhost", KEY_EXCHANGE_DATA, false,
                List.of(TLS_CHACHA20_POLY1305_SHA256),
                List.of(rsa_pss_rsae_sha256),
                NamedGroup.secp256r1, Collections.emptyList(), null, ClientHello.PskKeyEstablishmentMode.both);

        assertThatThrownBy(() ->
                // When
                engine.received(clientHello, ProtectionKeysType.None))
                // Then
                .isInstanceOf(HandshakeFailureAlert.class);
    }

    @Test
    void missingSupportedGroupsExtensionLeadsToMissingExtensionError() {
        // Given
        ClientHello clientHello = createDefaultClientHello();
        // Hack: remove supported groups extension
        for (int i = 0; i < clientHello.getExtensions().size(); i++) {
            if (clientHello.getExtensions().get(i) instanceof SupportedGroupsExtension) {
                clientHello.getExtensions().remove(i);
            }
        }

        assertThatThrownBy(() ->
                // When
                engine.received(clientHello, ProtectionKeysType.None))
                // Then
                .isInstanceOf(MissingExtensionAlert.class);
    }

    @Test
    void missingKeyShareExtensionLeadsToMissingExtensionError() {
        // Given
        ClientHello clientHello = createDefaultClientHello();
        // Hack: remove key share extension
        for (int i = 0; i < clientHello.getExtensions().size(); i++) {
            if (clientHello.getExtensions().get(i) instanceof KeyShareExtension) {
                clientHello.getExtensions().remove(i);
            }
        }

        assertThatThrownBy(() ->
                // When
                engine.received(clientHello, ProtectionKeysType.None))
                // Then
                .isInstanceOf(MissingExtensionAlert.class);
    }

    @Test
    void missingSignatureAlgorithmMissingExtensionError() {
        // Given
        ClientHello clientHello = createDefaultClientHello();
        // Hack: remove signature algorithm extension
        for (int i = 0; i < clientHello.getExtensions().size(); i++) {
            if (clientHello.getExtensions().get(i) instanceof SignatureAlgorithmsExtension) {
                clientHello.getExtensions().remove(i);
            }
        }

        assertThatThrownBy(() ->
                // When
                engine.received(clientHello, ProtectionKeysType.None))
                // Then
                .isInstanceOf(MissingExtensionAlert.class);
    }

    @Test
    void allClientHelloExtensionsArePassedToStatusHandler() throws Exception {
        // Given
        ClientHello clientHello = createDefaultClientHello();

        // When
        engine.received(clientHello, ProtectionKeysType.None);

        // Then
        ArgumentCaptor<List<Extension>> captor = ArgumentCaptor.forClass(List.class);
        verify(tlsStatusHandler).extensionsReceived(captor.capture());
        List<Extension> clientExtensions = captor.getValue();
        assertThat(clientExtensions).hasAtLeastOneElementOfType(SupportedVersionsExtension.class);
        assertThat(clientExtensions).hasAtLeastOneElementOfType(SupportedGroupsExtension.class);
        assertThat(clientExtensions).hasAtLeastOneElementOfType(KeyShareExtension.class);
    }

    @Test
    void processingProperClientHelloLeadsToEarlySecretsCallback() throws Exception {
        // Given
        ClientHello clientHello = createDefaultClientHello();

        // When
        engine.received(clientHello, ProtectionKeysType.None);

        // Then
        verify(tlsStatusHandler).earlySecretsKnown();
        assertThat(engine.getClientEarlyTrafficSecret()).isNotNull();
    }

    @Test
    void serverSelectsCipherFromOptionsGivenByClientHello() throws Exception {
        // Given
        ClientHello clientHello = new ClientHello("localhost", KEY_EXCHANGE_DATA, false,
                List.of(TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256),
                List.of(rsa_pss_rsae_sha256),
                NamedGroup.secp256r1, Collections.emptyList(), null, ClientHello.PskKeyEstablishmentMode.both);

        // When
        engine.received(clientHello, ProtectionKeysType.None);

        // Then
        verify(messageSender).send(argThat((ServerHello sh) -> sh.getCipherSuite().equals(TLS_AES_128_GCM_SHA256)));
    }

    @Test
    void processingProperClientHelloLeadsToHandshakeSecretsCallback() throws Exception {
        // Given
        ClientHello clientHello = createDefaultClientHello();

        // When
        engine.received(clientHello, ProtectionKeysType.None);

        // Then
        verify(tlsStatusHandler).handshakeSecretsKnown();
        assertThat(engine.getServerHandshakeTrafficSecret()).isNotNull();
    }

    @Test
    void serverExtensionsShouldBeIncludedInEncryptedExtensions() throws Exception {
        // Given
        ClientHello clientHello = createDefaultClientHello();
        engine.addServerExtensions(new ApplicationLayerProtocolNegotiationExtension("foobar"));

        // When
        engine.received(clientHello, ProtectionKeysType.None);

        // Then
        ArgumentCaptor<EncryptedExtensions> captor = ArgumentCaptor.forClass(EncryptedExtensions.class);
        verify(messageSender).send(captor.capture());
        assertThat(captor.getValue().getExtensions()).hasAtLeastOneElementOfType(ApplicationLayerProtocolNegotiationExtension.class);
    }

    @Test
    void incorrectClientFinishedMessageLeadsToDecryptError() throws Exception {
        // Given
        ClientHello clientHello = createDefaultClientHello();
        engine.received(clientHello, ProtectionKeysType.None);

        assertThatThrownBy(() ->
                // When
                engine.received(new FinishedMessage(new byte[32]), ProtectionKeysType.Handshake))
        // Then
        .isInstanceOf(DecryptErrorAlert.class);
    }

    @Test
    void clientProvidingPreSharedKeyShouldAlsoProvidePskKeyExchangeMode() throws Exception {
        // Given
        TlsState tlsState = mock(TlsState.class);
        when(tlsState.computePskBinder(any())).thenReturn(new byte[32]);
        NewSessionTicket ticket = new NewSessionTicket(new byte[32],
                new NewSessionTicketMessage(3600, 0xffffffff, new byte[]{ 0x00 }, new byte[]{ 0x00, 0x01, 0x02, 0x03 }), CipherSuite.TLS_AES_128_GCM_SHA256);
        ClientHello clientHello = createDefaultClientHello(List.of(new ClientHelloPreSharedKeyExtension(ticket)), tlsState);

        assertThatThrownBy(() ->
                // When
                engine.received(clientHello, ProtectionKeysType.None))
                // Then
                .isInstanceOf(MissingExtensionAlert.class);
    }

    @Test
    void whenALPNsMatchEarlyDataShouldBeEnabled() throws Exception {
        // Given
        TlsState tlsState = mock(TlsState.class);
        when(tlsState.computePskBinder(any())).thenReturn(new byte[32]);
        NewSessionTicketMessage ticketMessage = tlsSessionRegistry.createNewSessionTicketMessage((byte) 0, TLS_AES_128_GCM_SHA256, tlsState, "h3");
        // And given a server that implements application protocol layer negotiation and sets the selected protocol....
        simulateAlpnNegotation();

        // When
        ClientHello clientHello = createDefaultClientHello(List.of(
                new PskKeyExchangeModesExtension(PskKeyExchangeMode.psk_dhe_ke),
                new ClientHelloPreSharedKeyExtension(new NewSessionTicket(new byte[32], ticketMessage, CipherSuite.TLS_AES_128_GCM_SHA256)),
                new EarlyDataExtension(),
                new ApplicationLayerProtocolNegotiationExtension("h3")
        ), tlsState);
        engine.received(clientHello, ProtectionKeysType.None);

        // Then
        verify(tlsStatusHandler).isEarlyDataAccepted();
    }

    @Test
    void whenSelectedALPNnotSetEarlyDataShouldBeEnabled() throws Exception {
        // Given
        TlsState tlsState = mock(TlsState.class);
        when(tlsState.computePskBinder(any())).thenReturn(new byte[32]);
        NewSessionTicketMessage ticketMessage = tlsSessionRegistry.createNewSessionTicketMessage((byte) 0, TLS_AES_128_GCM_SHA256, tlsState, "h3");
        // And given a server that implements application protocol layer negotiation and sets the selected protocol....
        simulateAlpnNegotation();

        // When
        ClientHello clientHello = createDefaultClientHello(List.of(
                new PskKeyExchangeModesExtension(PskKeyExchangeMode.psk_dhe_ke),
                new ClientHelloPreSharedKeyExtension(new NewSessionTicket(new byte[32], ticketMessage, CipherSuite.TLS_AES_128_GCM_SHA256)),
                new EarlyDataExtension()
        ), tlsState);
        engine.received(clientHello, ProtectionKeysType.None);

        // Then
        verify(tlsStatusHandler, never()).isEarlyDataAccepted();
    }

    @Test
    void whenALPNdontMatchEarlyDataShouldNotBeEnabled() throws Exception {
        // Given
        TlsState tlsState = mock(TlsState.class);
        when(tlsState.computePskBinder(any())).thenReturn(new byte[32]);
        NewSessionTicketMessage ticketMessage = tlsSessionRegistry.createNewSessionTicketMessage((byte) 0, TLS_AES_128_GCM_SHA256, tlsState, "h3");
        // And given a server that implements application protocol layer negotiation and sets the selected protocol....
        simulateAlpnNegotation();

        // When
        ClientHello clientHello = createDefaultClientHello(List.of(
                new PskKeyExchangeModesExtension(PskKeyExchangeMode.psk_dhe_ke),
                new ClientHelloPreSharedKeyExtension(new NewSessionTicket(new byte[32], ticketMessage, CipherSuite.TLS_AES_128_GCM_SHA256)),
                new EarlyDataExtension(),
                new ApplicationLayerProtocolNegotiationExtension("http/1.1")
        ), tlsState);
        engine.received(clientHello, ProtectionKeysType.None);

        // Then
        verify(tlsStatusHandler, never()).isEarlyDataAccepted();
    }


    @Test
    void serverPreferredSignatureAlgorithmShouldBeSelectedIfClientSupportsIt1() throws Exception {
        // Given
        List<SignatureScheme> clientAlgorithms = List.of(rsa_pss_rsae_sha256, rsa_pss_rsae_sha384, rsa_pss_rsae_sha512);
        List<SignatureScheme> serverPreferredAlgorithms = List.of(rsa_pss_rsae_sha384, rsa_pss_rsae_sha256);

        // When
        SignatureScheme selected = TlsServerEngineImpl.determineSignatureAlgorithm(clientAlgorithms, serverPreferredAlgorithms);

        // Then
        assertThat(selected).isEqualTo(rsa_pss_rsae_sha384);
    }

    @Test
    void serverPreferredSignatureAlgorithmShouldBeSelectedIfClientSupportsIt2() throws Exception {
        // Given
        List<SignatureScheme> clientAlgorithms = List.of(rsa_pss_rsae_sha256, rsa_pss_rsae_sha384, rsa_pss_rsae_sha512, ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, ecdsa_secp521r1_sha512);
        List<SignatureScheme> serverPreferredAlgorithms = List.of(ecdsa_secp384r1_sha384);

        // When
        SignatureScheme selected = TlsServerEngineImpl.determineSignatureAlgorithm(clientAlgorithms, serverPreferredAlgorithms);

        // Then
        assertThat(selected).isEqualTo(ecdsa_secp384r1_sha384);
    }

    @Test
    void serverPreferredSignatureAlgorithmShouldNotBeSelectedIfClientDoesNotSupportsIt() throws Exception {
        // Given
        List<SignatureScheme> clientAlgorithms = List.of(rsa_pss_rsae_sha256, rsa_pss_rsae_sha384, rsa_pss_rsae_sha512);
        List<SignatureScheme> serverPreferredAlgorithms = List.of(ecdsa_secp384r1_sha384, rsa_pss_rsae_sha256);

        // When
        SignatureScheme selected = TlsServerEngineImpl.determineSignatureAlgorithm(clientAlgorithms, serverPreferredAlgorithms);

        // Then
        assertThat(selected).isEqualTo(rsa_pss_rsae_sha256);
    }

    @Test
    void whenNoSignatureAlgorithmCanBeNegotiatedHandshakeFailureIsThrown() throws Exception {
        // Given
        List<SignatureScheme> clientAlgorithms = List.of(rsa_pss_rsae_sha256, rsa_pss_rsae_sha384, rsa_pss_rsae_sha512);
        List<SignatureScheme> serverPreferredAlgorithms = List.of(ecdsa_secp384r1_sha384, ecdsa_secp256r1_sha256);

        assertThatThrownBy(() ->
                // When
                TlsServerEngineImpl.determineSignatureAlgorithm(clientAlgorithms, serverPreferredAlgorithms)
                // Then
        ).isInstanceOf(HandshakeFailureAlert.class);
    }

    @Test
    void clientHelloWithDuplicateExtensionShouldBeRejected() {
        // Given: a ClientHello with a duplicate SupportedGroupsExtension
        ClientHello clientHello = createDefaultClientHello();
        clientHello.getExtensions().add(new SupportedGroupsExtension(NamedGroup.secp384r1));

        assertThatThrownBy(() ->
                // When
                engine.received(clientHello, ProtectionKeysType.None))
                // Then
                .isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void clientHelloWithOnlyTls12ShouldBeRejected() throws Exception {
        // Given
        ClientHello clientHello = createDefaultClientHello();
        // Replace the SupportedVersionsExtension with one that only offers TLS 1.2
        clientHello.getExtensions().removeIf(ext -> ext instanceof SupportedVersionsExtension);
        // Build a SupportedVersionsExtension from raw bytes containing only TLS 1.2 (0x0303)
        // Extension type 0x002b, data length 0x0003, versions length 0x02, version 0x0303
        ByteBuffer versionExtBuffer = ByteBuffer.wrap(new byte[] {
                0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x03
        });
        clientHello.getExtensions().add(new SupportedVersionsExtension(versionExtBuffer, HandshakeType.client_hello));

        assertThatThrownBy(() ->
                // When
                engine.received(clientHello, ProtectionKeysType.None))
                // Then
                .isInstanceOf(ProtocolVersionAlert.class);
    }

    @Test
    void firstKeyShareGroupSupportedByServerIsSelected() throws Exception {
        // Given: a server that (only) supports x25519
        KeyExchangeFactory keyExchangeFactory = keyExchangeFactorySupporting(NamedGroup.x25519);
        TlsServerEngineImpl engine = createEngine(keyExchangeFactory);
        // and a client that offers x448 (which the server does not support) and x25519
        ClientHello clientHello = createClientHelloWithKeyShares(NamedGroup.x448, NamedGroup.x25519);

        // When
        engine.received(clientHello, ProtectionKeysType.None);

        // Then
        assertThat(selectedGroup()).isEqualTo(NamedGroup.x25519);
    }

    @Test
    void whenServerSupportsMultipleKeyShareGroupsClientPreferenceDetermines() throws Exception {
        // Given: a server that supports both X25519MLKEM768 and x25519
        KeyExchangeFactory keyExchangeFactory = keyExchangeFactorySupporting(NamedGroup.x448, NamedGroup.x25519, NamedGroup.X25519MLKEM768, NamedGroup.secp384r1);
        TlsServerEngineImpl engine = createEngine(keyExchangeFactory);
        // and a client that prefers X25519MLKEM768 (key shares are in client's order of preference)
        ClientHello clientHello = createClientHelloWithKeyShares(NamedGroup.X25519MLKEM768, NamedGroup.x25519);

        // When
        engine.received(clientHello, ProtectionKeysType.None);

        // Then
        assertThat(selectedGroup()).isEqualTo(NamedGroup.X25519MLKEM768);
    }

    @Test
    void whenServerSupportsNoneOfTheClientsGroupsHandshakeFailureIsThrown() throws Exception {
        // Given: a server that (only) supports x25519
        TlsServerEngineImpl engine = createEngine(keyExchangeFactorySupporting(NamedGroup.x25519));
        // and a client that only offers x448
        ClientHello clientHello = createClientHelloWithKeyShares(NamedGroup.x448);

        assertThatThrownBy(() ->
                // When
                engine.received(clientHello, ProtectionKeysType.None))
                // Then
                .isInstanceOf(HandshakeFailureAlert.class);
    }

    /**
     * Returns the named group of the key share in the ServerHello that the engine has sent.
     */
    private NamedGroup selectedGroup() throws Exception {
        ArgumentCaptor<ServerHello> captor = ArgumentCaptor.forClass(ServerHello.class);
        verify(messageSender).send(captor.capture());
        return captor.getValue().getExtensions().stream()
                .filter(ext -> ext instanceof KeyShareExtension)
                .map(ext -> (KeyShareExtension) ext)
                .flatMap(ext -> ext.getKeyShareEntries().stream())
                .map(KeyShareExtension.KeyShareEntry::getNamedGroup)
                .findFirst()
                .orElseThrow();
    }

    private TlsServerEngineImpl createEngine(KeyExchangeFactory keyExchangeFactory) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(encodedKwikDotTechRsaCertificatePrivateKey));
        PrivateKey privateKey = keyFactory.generatePrivate(keySpecPKCS8);

        TlsServerEngineImpl engine = new TlsServerEngineImpl(List.of(serverCertificate), privateKey, List.of(rsa_pss_rsae_sha256),
                messageSender, tlsStatusHandler, tlsSessionRegistry, keyExchangeFactory);
        engine.addSupportedCiphers(List.of(TLS_AES_128_GCM_SHA256));
        return engine;
    }

    /**
     * Creates a key exchange factory that supports exactly the given groups: for any other group it returns null.
     */
    private KeyExchangeFactory keyExchangeFactorySupporting(NamedGroup... supportedGroups) throws Exception {
        KeyExchange keyExchange = mock(KeyExchange.class);
        when(keyExchange.serverProcessClientKeyShare(any())).thenReturn(new byte[32]);
        when(keyExchange.getServerKeyShare()).thenReturn(new byte[32]);

        KeyExchangeFactory keyExchangeFactory = mock(KeyExchangeFactory.class);   // Returns null for all groups by default
        for (NamedGroup group: supportedGroups) {
            when(keyExchangeFactory.forGroup(group)).thenReturn(keyExchange);
        }
        return keyExchangeFactory;
    }

    /**
     * Creates a ClientHello that offers the given groups (both as supported groups and as key shares), in the given order.
     */
    private ClientHello createClientHelloWithKeyShares(NamedGroup... groups) throws Exception {
        ClientHello clientHello = createDefaultClientHello();
        clientHello.getExtensions().removeIf(ext -> ext instanceof SupportedGroupsExtension || ext instanceof KeyShareExtension);
        clientHello.getExtensions().add(createSupportedGroupsExtension(groups));
        clientHello.getExtensions().add(createKeyShareExtension(groups));
        return clientHello;
    }

    private SupportedGroupsExtension createSupportedGroupsExtension(NamedGroup... groups) throws Exception {
        ByteBuffer buffer = ByteBuffer.allocate(6 + 2 * groups.length);
        buffer.putShort(ExtensionType.supported_groups.value);
        buffer.putShort((short) (2 + 2 * groups.length));    // Extension data length
        buffer.putShort((short) (2 * groups.length));        // Named groups length
        for (NamedGroup group: groups) {
            buffer.putShort(group.value);
        }
        buffer.flip();
        return new SupportedGroupsExtension(buffer);
    }

    private KeyShareExtension createKeyShareExtension(NamedGroup... groups) throws Exception {
        int entriesLength = groups.length * (4 + KEY_EXCHANGE_DATA.length);
        ByteBuffer buffer = ByteBuffer.allocate(6 + entriesLength);
        buffer.putShort(ExtensionType.key_share.value);
        buffer.putShort((short) (2 + entriesLength));   // Extension data length
        buffer.putShort((short) entriesLength);         // Key share entries length
        for (NamedGroup group: groups) {
            buffer.putShort(group.value);
            buffer.putShort((short) KEY_EXCHANGE_DATA.length);
            buffer.put(KEY_EXCHANGE_DATA);
        }
        buffer.flip();
        return new KeyShareExtension(buffer, HandshakeType.client_hello);
    }

    private ClientHello createDefaultClientHello() {
        return createDefaultClientHello(Collections.emptyList(), null);
    }

    private ClientHello createDefaultClientHello(List<Extension> extensions, TlsState state) {
        return new ClientHello("localhost", KEY_EXCHANGE_DATA, false,
                List.of(TLS_AES_128_GCM_SHA256),
                List.of(rsa_pss_rsae_sha256),
                NamedGroup.secp256r1, extensions, state, ClientHello.PskKeyEstablishmentMode.none);
    }

    private void simulateAlpnNegotation() throws Exception {
        // A server is supposed to select an application layer protocol while processing client extensions...
        doAnswer(new Answer<Void>() {
            public Void answer(InvocationOnMock invocation) {
                ((List) invocation.getArgument(0)).stream()
                        // Find the ApplicationLayerProtocolNegotiationExtension, extra the first protocol and use that as selected
                        .filter(ext -> ext instanceof ApplicationLayerProtocolNegotiationExtension)
                        .map(ext -> ((ApplicationLayerProtocolNegotiationExtension) ext).getProtocols().get(0))
                        .forEach(protocol -> engine.setSelectedApplicationLayerProtocol((String) protocol));
                return null;
            }
        }
        // ... in the extensionsReceived method
        ).when(tlsStatusHandler).extensionsReceived(anyList());
    }
}
