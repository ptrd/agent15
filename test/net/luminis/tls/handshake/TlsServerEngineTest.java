/*
 * Copyright © 2019, 2020, 2021, 2022, 2023 Peter Doornbosch
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
package net.luminis.tls.handshake;

import net.luminis.tls.*;
import net.luminis.tls.alert.DecryptErrorAlert;
import net.luminis.tls.alert.HandshakeFailureAlert;
import net.luminis.tls.alert.MissingExtensionAlert;
import net.luminis.tls.extension.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.internal.util.reflection.FieldSetter;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import static net.luminis.tls.TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256;
import static net.luminis.tls.TlsConstants.CipherSuite.TLS_CHACHA20_POLY1305_SHA256;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

public class TlsServerEngineTest extends EngineTest {

    private TlsServerEngine engine;
    private ECPublicKey publicKey;
    private ServerMessageSender messageSender;
    private X509Certificate serverCertificate;
    private TlsStatusEventHandler tlsStatusHandler;
    private TlsSessionRegistryImpl tlsSessionRegistry;

    @BeforeEach
    private void initObjectUnderTest() throws Exception {
        messageSender = mock(ServerMessageSender.class);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(encodedPrivateKey));
        PrivateKey privateKey = keyFactory.generatePrivate(keySpecPKCS8);

        serverCertificate = CertificateUtils.inflateCertificate(encodedCertificate);
        tlsStatusHandler = mock(TlsStatusEventHandler.class);
        tlsSessionRegistry = new TlsSessionRegistryImpl();
        engine = new TlsServerEngine(serverCertificate, privateKey, messageSender, tlsStatusHandler, tlsSessionRegistry) {
            protected boolean validateBinder(ClientHelloPreSharedKeyExtension.PskBinderEntry pskBinderEntry, int binderPosition, ClientHello clientHello) {
                return true;
            }
        };
        engine.addSupportedCiphers(List.of(TLS_AES_128_GCM_SHA256));

        publicKey = KeyUtils.generatePublicKey();
    }

    @Test
    void failingCipherNegotiationLeadsToHandshakeException() throws Exception {
        // Given
        ClientHello clientHello = new ClientHello("localhost", publicKey, false,
                List.of(TLS_CHACHA20_POLY1305_SHA256),
                List.of(TlsConstants.SignatureScheme.rsa_pss_rsae_sha256),
                TlsConstants.NamedGroup.secp256r1, Collections.emptyList(), null, ClientHello.PskKeyEstablishmentMode.both);

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
        ClientHello clientHello = new ClientHello("localhost", publicKey, false,
                List.of(TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256),
                List.of(TlsConstants.SignatureScheme.rsa_pss_rsae_sha256),
                TlsConstants.NamedGroup.secp256r1, Collections.emptyList(), null, ClientHello.PskKeyEstablishmentMode.both);

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
        NewSessionTicket ticket = new NewSessionTicket(tlsState,
                new NewSessionTicketMessage(3600, 0xffffffff, new byte[]{ 0x00 }, new byte[]{ 0x00, 0x01, 0x02, 0x03 }));
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
                new PskKeyExchangeModesExtension(TlsConstants.PskKeyExchangeMode.psk_dhe_ke),
                new ClientHelloPreSharedKeyExtension(new NewSessionTicket(tlsState, ticketMessage)),
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
                new PskKeyExchangeModesExtension(TlsConstants.PskKeyExchangeMode.psk_dhe_ke),
                new ClientHelloPreSharedKeyExtension(new NewSessionTicket(tlsState, ticketMessage)),
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
                new PskKeyExchangeModesExtension(TlsConstants.PskKeyExchangeMode.psk_dhe_ke),
                new ClientHelloPreSharedKeyExtension(new NewSessionTicket(tlsState, ticketMessage)),
                new EarlyDataExtension(),
                new ApplicationLayerProtocolNegotiationExtension("http/1.1")
        ), tlsState);
        engine.received(clientHello, ProtectionKeysType.None);

        // Then
        verify(tlsStatusHandler, never()).isEarlyDataAccepted();
    }

    private ClientHello createDefaultClientHello() {
        return createDefaultClientHello(Collections.emptyList(), null);
    }

    private ClientHello createDefaultClientHello(List<Extension> extensions, TlsState state) {
        return new ClientHello("localhost", publicKey, false,
                List.of(TLS_AES_128_GCM_SHA256),
                List.of(TlsConstants.SignatureScheme.rsa_pss_rsae_sha256),
                TlsConstants.NamedGroup.secp256r1, extensions, state, ClientHello.PskKeyEstablishmentMode.none);
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
