/*
 * Copyright © 2021 Peter Doornbosch
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

import net.luminis.tls.TlsState;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;


public class TlsSessionRegistryImpl implements TlsSessionRegistry {

    private static final int DEFAULT_TICKET_LIFETIME = 24 * 3600;
    private static final int DEFAULT_TICKET_LENGTH = 128 / 8;

    private Random randomGenerator = new SecureRandom();
    private Map<BytesKey, Session> sessions = new HashMap<>();


    public NewSessionTicketMessage createNewSessionTicketMessage(byte ticketNonce, TlsState tlsState) {
        byte[] psk = tlsState.computePSK(new byte[] { ticketNonce });
        long ageAdd = randomGenerator.nextLong();
        byte[] ticketId = new byte[DEFAULT_TICKET_LENGTH];
        randomGenerator.nextBytes(ticketId);
        sessions.put(new BytesKey(ticketId), new Session(ticketId, ticketNonce, ageAdd, psk, Instant.now()));
        return new NewSessionTicketMessage(DEFAULT_TICKET_LIFETIME, ageAdd, new byte[] { ticketNonce }, ticketId);
    }

    private class Session {
        final byte[] ticketId;
        final byte ticketNonce;
        final long addAdd;
        final byte[] psk;
        final Instant created;

        public Session(byte[] ticketId, byte ticketNonce, long addAdd, byte[] psk, Instant created) {
            this.ticketId = ticketId;
            this.ticketNonce = ticketNonce;
            this.addAdd = addAdd;
            this.psk = psk;
            this.created = created;
        }
    }

    private class BytesKey {
        private final byte[] data;

        public BytesKey(byte[] data) {
            this.data = data;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            BytesKey other = (BytesKey) o;
            return Arrays.equals(data, other.data);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(data);
        }
    }
}
