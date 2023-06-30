/*
 * Copyright © 2023 Peter Doornbosch
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
package net.luminis.tls;

import net.luminis.tls.handshake.NewSessionTicketMessage;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class NewSessionTicketTest {

    @Test
    void testSerialize() {
        TlsState tlsState = mock(TlsState.class);
        when(tlsState.computePSK(any())).thenReturn(new byte[32]);
        NewSessionTicketMessage ticketMsg = new NewSessionTicketMessage(Integer.MAX_VALUE, 0, new byte[8], new byte[64]);
        NewSessionTicket newSessionTicket = new NewSessionTicket(tlsState, ticketMsg, TlsConstants.CipherSuite.TLS_CHACHA20_POLY1305_SHA256);

        byte[] serializedTicket = newSessionTicket.serialize();

        NewSessionTicket deserializedTicket = NewSessionTicket.deserialize(serializedTicket);
        assertThat(deserializedTicket).isNotNull();
        assertThat(deserializedTicket.getCipher()).isEqualTo(TlsConstants.CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
    }
}