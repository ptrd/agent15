/*
 * Copyright © 2023, 2024, 2025, 2026 Peter Doornbosch
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
package tech.kwik.agent15;

import org.junit.jupiter.api.Test;
import tech.kwik.agent15.engine.impl.TlsState;
import tech.kwik.agent15.handshake.NewSessionTicketMessage;
import tech.kwik.agent15.util.ByteUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class NewSessionTicketTest {

    @Test
    void testSerialize() {
        TlsState tlsState = mock(TlsState.class);
        when(tlsState.computePSK(any())).thenReturn(new byte[32]);
        NewSessionTicketMessage ticketMsg = new NewSessionTicketMessage(Integer.MAX_VALUE, 0, new byte[8], new byte[64], 0xffff);
        NewSessionTicket newSessionTicket = new NewSessionTicket(new byte[32], ticketMsg, TlsConstants.CipherSuite.TLS_CHACHA20_POLY1305_SHA256);

        byte[] serializedTicket = newSessionTicket.serialize();

        NewSessionTicket deserializedTicket = NewSessionTicket.deserialize(serializedTicket);
        assertThat(deserializedTicket).isNotNull();
        assertThat(deserializedTicket.getCipher()).isEqualTo(TlsConstants.CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
        assertThat(deserializedTicket.getEarlyDataMaxSize()).isEqualTo(0xffff);
    }

    @Test
    void testDeserialize() {
        //                          creation date    age_add          ticket len ticket            psk len  psk
        byte[] data = ByteUtils.hexToBytes("000001abcdef1234 00000000fab00e11 00000008 0102030405060708 00000004 aabbccdd"
                //  lifetime cipher  early data max size
                + "00093a80 1303    0000000012345678");

        NewSessionTicket ticket = NewSessionTicket.deserialize(data);

        assertThat(ticket.getTicketCreationDate().getTime()).isEqualTo(0x000001abcdef1234L);
        assertThat(ticket.getTicketAgeAdd()).isEqualTo(0xfab00e11L);
        assertThat(ticket.getTicket()).isEqualTo(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
        assertThat(ticket.getPSK()).isEqualTo(new byte[] { (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd });
        assertThat(ticket.getTicketLifeTime()).isEqualTo(604800);
        assertThat(ticket.getCipher()).isEqualTo(TlsConstants.CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
        assertThat(ticket.getEarlyDataMaxSize()).isEqualTo(0x12345678L);
        assertThat(ticket.hasEarlyDataExtension()).isTrue();
    }
}