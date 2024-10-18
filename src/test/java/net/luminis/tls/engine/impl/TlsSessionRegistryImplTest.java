/*
 * Copyright © 2021, 2022, 2023, 2024 Peter Doornbosch
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
package net.luminis.tls.engine.impl;

import net.luminis.tls.TlsConstants;
import net.luminis.tls.extension.ClientHelloPreSharedKeyExtension;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


class TlsSessionRegistryImplTest {

    @Test
    void sessionSelectionShouldCheckForSameCipher() throws Exception {
        // Given
        var registry = new TlsSessionRegistryImpl();
        TlsState tlsState = mock(TlsState.class);
        when(tlsState.computePSK(any())).thenReturn(new byte[16]);
        var ticketMessage1 = registry.createNewSessionTicketMessage((byte) 0, TlsConstants.CipherSuite.TLS_AES_256_GCM_SHA384, tlsState, "");
        var ticketMessage2 = registry.createNewSessionTicketMessage((byte) 1, TlsConstants.CipherSuite.TLS_CHACHA20_POLY1305_SHA256, tlsState, "");
        var ticketMessage3 = registry.createNewSessionTicketMessage((byte) 2, TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256, tlsState, "");

        // When
        Integer selectedIdentity = registry.selectIdentity(List.of(
                new ClientHelloPreSharedKeyExtension.PskIdentity(ticketMessage1.getTicket(), 0xff),
                new ClientHelloPreSharedKeyExtension.PskIdentity(ticketMessage2.getTicket(), 0xff),
                new ClientHelloPreSharedKeyExtension.PskIdentity(ticketMessage3.getTicket(), 0xff)
        ), TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256);

        // Then
        assertThat(selectedIdentity).isEqualTo(2);
    }

    @Test
    void expiredSessionsShouldBeRemoved() throws Exception {
        // Given
        var registry = new TlsSessionRegistryImpl(1);
        TlsState tlsState = mock(TlsState.class);
        when(tlsState.computePSK(any())).thenReturn(new byte[16]);
        var ticketMessage1 = registry.createNewSessionTicketMessage((byte) 0, TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256, tlsState, "");
        Thread.sleep(500);
        var ticketMessage2 = registry.createNewSessionTicketMessage((byte) 2, TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256, tlsState, "");

        // When
        Thread.sleep(505);
        registry.cleanupExpiredPsks();

        // Then
        assertThat(registry.useSession(new ClientHelloPreSharedKeyExtension.PskIdentity(ticketMessage1.getTicket(), 0))).isNull();
        assertThat(registry.useSession(new ClientHelloPreSharedKeyExtension.PskIdentity(ticketMessage2.getTicket(), 0))).isNotNull();
    }

    @Test
    void expiredSessionShouldNotBeReturn() throws Exception {
        // Given
        var registry = new TlsSessionRegistryImpl(1);
        TlsState tlsState = mock(TlsState.class);
        when(tlsState.computePSK(any())).thenReturn(new byte[16]);
        var ticketMessage1 = registry.createNewSessionTicketMessage((byte) 0, TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256, tlsState, "");

        // When
        Thread.sleep(1005);

        // Then
        Integer selectedIdentity = registry.selectIdentity(List.of(
                new ClientHelloPreSharedKeyExtension.PskIdentity(ticketMessage1.getTicket(), 0xff)
        ), TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256);

        assertThat(selectedIdentity).isNull();
    }

    @Test
    void whenClosedNewSessionShouldNotBeAdded() {
        // Given
        var registry = new TlsSessionRegistryImpl();
        TlsState tlsState = mock(TlsState.class);
        when(tlsState.computePSK(any())).thenReturn(new byte[16]);
        registry.shutdown();

        // When
        var ticketMessage = registry.createNewSessionTicketMessage((byte) 0, TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256, tlsState, "");

        // Then
        assertThat(ticketMessage).isNull();
    }

    @Test
    void whenClosedSessionShouldNotBeReturned() {
        // Given
        var registry = new TlsSessionRegistryImpl();
        TlsState tlsState = mock(TlsState.class);
        when(tlsState.computePSK(any())).thenReturn(new byte[16]);
        var ticketMessage = registry.createNewSessionTicketMessage((byte) 0, TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256, tlsState, "");

        // When
        registry.shutdown();

        // Then
        assertThat(registry.useSession(new ClientHelloPreSharedKeyExtension.PskIdentity(ticketMessage.getTicket(), 0))).isNull();
    }

    @Test
    void whenClosedSessionDataShouldNotBePeeked() {
        // Given
        var registry = new TlsSessionRegistryImpl();
        TlsState tlsState = mock(TlsState.class);
        when(tlsState.computePSK(any())).thenReturn(new byte[16]);
        var ticketMessage = registry.createNewSessionTicketMessage((byte) 0, TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256, tlsState, "");

        // When
        registry.shutdown();

        // Then
        assertThat(registry.useSession(new ClientHelloPreSharedKeyExtension.PskIdentity(ticketMessage.getTicket(), 0))).isNull();
    }
}