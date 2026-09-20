/*
 * Copyright © 2026 Peter Doornbosch
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
import tech.kwik.agent15.NewSessionTicket;
import tech.kwik.agent15.ProtectionKeysType;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.engine.ClientMessageSender;
import tech.kwik.agent15.engine.HostnameVerifier;
import tech.kwik.agent15.engine.ServerMessageSender;
import tech.kwik.agent15.engine.TlsSessionRegistry;
import tech.kwik.agent15.engine.TlsStatusEventHandler;
import tech.kwik.agent15.handshake.CertificateMessage;
import tech.kwik.agent15.handshake.CertificateVerifyMessage;
import tech.kwik.agent15.handshake.ClientHello;
import tech.kwik.agent15.handshake.EncryptedExtensions;
import tech.kwik.agent15.handshake.FinishedMessage;
import tech.kwik.agent15.handshake.HelloRetryRequest;
import tech.kwik.agent15.handshake.NewSessionTicketMessage;
import tech.kwik.agent15.handshake.ServerHello;
import tech.kwik.agent15.util.CertificateUtils;

import javax.net.ssl.X509TrustManager;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.Deque;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static tech.kwik.agent15.TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256;
import static tech.kwik.agent15.TlsConstants.NamedGroup.secp256r1;
import static tech.kwik.agent15.TlsConstants.NamedGroup.x25519;
import static tech.kwik.agent15.TlsConstants.SignatureScheme.rsa_pss_rsae_sha256;
import static tech.kwik.agent15.util.CertificateUtils.encodedKwikDotTechRsaCertificate;
import static tech.kwik.agent15.util.CertificateUtils.encodedKwikDotTechRsaCertificatePrivateKey;

/**
 * Runs a real client engine against a real server engine. In contrast to the unit tests for either engine, nothing is
 * stubbed here, so the transcript hashes on both sides must match: if they do not, verifying a Finished message fails.
 */
class ClientServerHandshakeTest {

    private static final String SERVER_NAME = "localhost";

    private TlsClientEngineImpl client;
    private TlsServerEngineImpl server;
    private TlsStatusEventHandler clientStatusHandler;
    private TlsStatusEventHandler serverStatusHandler;
    private TlsSessionRegistry sessionRegistry;
    private X509Certificate serverCertificate;
    private PrivateKey serverPrivateKey;

    /** Messages that have been sent but not yet delivered, in the order they were sent. */
    private final Deque<Delivery> messagesInFlight = new ArrayDeque<>();
    private int helloRetryRequestCount;

    @FunctionalInterface
    private interface Delivery {
        void deliver() throws Exception;
    }

    @BeforeEach
    void createEngines() throws Exception {
        serverCertificate = CertificateUtils.inflateCertificate(encodedKwikDotTechRsaCertificate);
        serverPrivateKey = KeyFactory.getInstance("RSA").generatePrivate(
                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(encodedKwikDotTechRsaCertificatePrivateKey)));
        sessionRegistry = new TlsSessionRegistryImpl();

        clientStatusHandler = mock(TlsStatusEventHandler.class);
        serverStatusHandler = mock(TlsStatusEventHandler.class);
        client = createClient(clientStatusHandler);
        server = createServer(serverStatusHandler);
    }

    @Test
    void handshakeWithoutHelloRetryRequestShouldSucceed() throws Exception {
        // When
        client.startHandshake(secp256r1, List.of(secp256r1, x25519), List.of(rsa_pss_rsae_sha256));
        deliverAll();

        // Then
        assertThat(helloRetryRequestCount).isZero();
        assertThat(client.handshakeFinished()).isTrue();
        verify(serverStatusHandler).handshakeFinished();
    }

    @Test
    void handshakeWithHelloRetryRequestShouldSucceed() throws Exception {
        // Given: a server that only offers x25519
        server.addSupportedGroups(List.of(x25519));

        // When: a client that sends a key share for secp256r1, but does offer x25519
        client.startHandshake(secp256r1, List.of(secp256r1, x25519), List.of(rsa_pss_rsae_sha256));
        deliverAll();

        // Then: exactly one hello retry request was needed, and the handshake completed on both sides. Note that this
        // only works when both sides compute the same transcript hash, which includes the synthetic message that
        // replaces the first client hello and the hello retry request itself; otherwise verifying the finished
        // messages fails.
        assertThat(helloRetryRequestCount).isEqualTo(1);
        assertThat(client.handshakeFinished()).isTrue();
        assertThat(client.getSelectedCipher()).isEqualTo(TLS_AES_128_GCM_SHA256);
        verify(serverStatusHandler).handshakeFinished();
    }

    @Test
    void sessionResumptionWithHelloRetryRequestShouldSucceed() throws Exception {
        // Given: a completed handshake that provided a session ticket
        client.startHandshake(secp256r1, List.of(secp256r1, x25519), List.of(rsa_pss_rsae_sha256));
        deliverAll();
        NewSessionTicket ticket = obtainedSessionTicket();

        // and a new connection (with the same session registry on the server) that needs a hello retry request
        clientStatusHandler = mock(TlsStatusEventHandler.class);
        serverStatusHandler = mock(TlsStatusEventHandler.class);
        client = createClient(clientStatusHandler);
        server = createServer(serverStatusHandler);
        server.addSupportedGroups(List.of(x25519));
        helloRetryRequestCount = 0;
        // The message sender is shared by both handshakes, so forget what the first one sent.
        clearInvocations(serverMessageSender);

        // When: the client resumes the session
        client.setNewSessionTicket(ticket);
        client.startHandshake(secp256r1, List.of(secp256r1, x25519), List.of(rsa_pss_rsae_sha256));
        deliverAll();

        // Then: the binder was accepted (it is computed over the transcript that includes the hello retry request) and
        // the session was resumed, so the server did not send a certificate.
        assertThat(helloRetryRequestCount).isEqualTo(1);
        assertThat(client.handshakeFinished()).isTrue();
        verify(serverStatusHandler).handshakeFinished();
        verify(serverMessageSender(), never()).send(any(CertificateMessage.class));
    }

    private NewSessionTicket obtainedSessionTicket() {
        ArgumentCaptor<NewSessionTicket> captor = ArgumentCaptor.forClass(NewSessionTicket.class);
        verify(clientStatusHandler).newSessionTicketReceived(captor.capture());
        return captor.getValue();
    }

    /**
     * Delivers messages until there are none left. Messages are queued rather than delivered directly, because an
     * engine sends its messages while it is processing a received message: delivering directly would re-enter the
     * peer engine while it has not finished with the previous message.
     */
    private void deliverAll() throws Exception {
        while (!messagesInFlight.isEmpty()) {
            messagesInFlight.removeFirst().deliver();
        }
    }

    private TlsClientEngineImpl createClient(TlsStatusEventHandler statusHandler) {
        TlsClientEngineImpl client = new TlsClientEngineImpl(clientMessageSender(), statusHandler, new KeyExchangeFactoryImpl());
        client.setServerName(SERVER_NAME);
        client.addSupportedCiphers(List.of(TLS_AES_128_GCM_SHA256));
        client.setTrustManager(acceptAllTrustManager());
        client.setHostnameVerifier(acceptAllHostnameVerifier());
        return client;
    }

    private TlsServerEngineImpl createServer(TlsStatusEventHandler statusHandler) {
        TlsServerEngineImpl server = new TlsServerEngineImpl(List.of(serverCertificate), serverPrivateKey,
                List.of(rsa_pss_rsae_sha256), serverMessageSender, statusHandler, sessionRegistry, new KeyExchangeFactoryImpl());
        server.addSupportedCiphers(List.of(TLS_AES_128_GCM_SHA256));
        return server;
    }

    private ClientMessageSender clientMessageSender() {
        return new ClientMessageSender() {
            @Override
            public void send(ClientHello clientHello) {
                messagesInFlight.addLast(() -> server.received(clientHello, ProtectionKeysType.None));
            }

            @Override
            public void send(FinishedMessage finishedMessage) {
                messagesInFlight.addLast(() -> server.received(finishedMessage, ProtectionKeysType.Handshake));
            }

            @Override
            public void send(CertificateMessage certificateMessage) {
                messagesInFlight.addLast(() -> server.received(certificateMessage, ProtectionKeysType.Handshake));
            }

            @Override
            public void send(CertificateVerifyMessage certificateVerifyMessage) {
                messagesInFlight.addLast(() -> server.received(certificateVerifyMessage, ProtectionKeysType.Handshake));
            }
        };
    }

    /** The server message sender is a single instance, so tests can verify what the server sent. */
    private final ServerMessageSender serverMessageSender = mock(ServerMessageSender.class,
            invocation -> {
                Object message = invocation.getArguments()[0];
                if (message instanceof ServerHello) {
                    messagesInFlight.addLast(() -> client.received((ServerHello) message, ProtectionKeysType.None));
                }
                else if (message instanceof HelloRetryRequest) {
                    helloRetryRequestCount++;
                    messagesInFlight.addLast(() -> client.received((HelloRetryRequest) message, ProtectionKeysType.None));
                }
                else if (message instanceof EncryptedExtensions) {
                    messagesInFlight.addLast(() -> client.received((EncryptedExtensions) message, ProtectionKeysType.Handshake));
                }
                else if (message instanceof CertificateMessage) {
                    messagesInFlight.addLast(() -> client.received((CertificateMessage) message, ProtectionKeysType.Handshake));
                }
                else if (message instanceof CertificateVerifyMessage) {
                    messagesInFlight.addLast(() -> client.received((CertificateVerifyMessage) message, ProtectionKeysType.Handshake));
                }
                else if (message instanceof FinishedMessage) {
                    messagesInFlight.addLast(() -> client.received((FinishedMessage) message, ProtectionKeysType.Handshake));
                }
                else if (message instanceof NewSessionTicketMessage) {
                    messagesInFlight.addLast(() -> client.received((NewSessionTicketMessage) message, ProtectionKeysType.Application));
                }
                return null;
            });

    private ServerMessageSender serverMessageSender() {
        return serverMessageSender;
    }

    private HostnameVerifier acceptAllHostnameVerifier() {
        return (hostname, serverCertificate) -> true;
    }

    private X509TrustManager acceptAllTrustManager() {
        return new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }

            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }

            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }
        };
    }
}
