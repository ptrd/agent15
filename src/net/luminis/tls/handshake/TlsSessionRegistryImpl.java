/*
 * Copyright © 2021, 2022 Peter Doornbosch
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

import net.luminis.tls.TlsConstants;
import net.luminis.tls.TlsState;
import net.luminis.tls.extension.ClientHelloPreSharedKeyExtension;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;


public class TlsSessionRegistryImpl implements TlsSessionRegistry {

    private static final int DEFAULT_TICKET_LIFETIME_HOURS = 24;
    private static final int DEFAULT_TICKET_LENGTH = 128 / 8;

    private Random randomGenerator = new SecureRandom();
    private Map<BytesKey, Session> sessions = new ConcurrentHashMap<>();
    private int ticketLifeTimeInSeconds;

    public TlsSessionRegistryImpl() {
        ticketLifeTimeInSeconds = (int) TimeUnit.HOURS.toSeconds(DEFAULT_TICKET_LIFETIME_HOURS);
        Executors.newSingleThreadScheduledExecutor().scheduleAtFixedRate(this::cleanupExpiredPsks, 1, 1, TimeUnit.MINUTES);
    }

    public TlsSessionRegistryImpl(int ticketLifeTimeInSeconds) {
        this();
        this.ticketLifeTimeInSeconds = ticketLifeTimeInSeconds;
    }

    @Override
    public NewSessionTicketMessage createNewSessionTicketMessage(byte ticketNonce, TlsConstants.CipherSuite cipher, TlsState tlsState, String applicationProtocol) {
        return createNewSessionTicketMessage(ticketNonce, cipher, tlsState, applicationProtocol, null);
    }

    @Override
    public NewSessionTicketMessage createNewSessionTicketMessage(byte ticketNonce, TlsConstants.CipherSuite cipher, TlsState tlsState, String applicationProtocol, Long maxEarlyDataSize) {
        byte[] psk = tlsState.computePSK(new byte[] { ticketNonce });
        long ageAdd = randomGenerator.nextLong();
        byte[] ticketId = new byte[DEFAULT_TICKET_LENGTH];
        randomGenerator.nextBytes(ticketId);
        Instant expiry = Instant.now().plusMillis(TimeUnit.SECONDS.toMillis(ticketLifeTimeInSeconds));
        sessions.put(new BytesKey(ticketId), new Session(ticketId, ticketNonce, ageAdd, psk, cipher, Instant.now(), expiry, applicationProtocol));
        if (maxEarlyDataSize != null) {
            return new NewSessionTicketMessage(ticketLifeTimeInSeconds, ageAdd, new byte[]{ ticketNonce }, ticketId, maxEarlyDataSize);
        }
        else {
            return new NewSessionTicketMessage(ticketLifeTimeInSeconds, ageAdd, new byte[]{ ticketNonce }, ticketId);
        }
    }

    @Override
    public Integer selectIdentity(List<ClientHelloPreSharedKeyExtension.PskIdentity> identities, TlsConstants.CipherSuite cipher) {
        for (int i = 0; i < identities.size(); i++) {
            BytesKey key = new BytesKey(identities.get(i).getIdentity());
            Session candidateSession = sessions.get(key);
            if (candidateSession != null && candidateSession.expiry.isAfter(Instant.now())) {
                // Note that this condition is (probably) stronger than what the specification mandates:
                // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11
                // "Each PSK is associated with a single Hash algorithm. For PSKs established via the ticket mechanism
                //  (Section 4.6.1), this is the KDF Hash algorithm on the connection where the ticket was established."
                // "The server MUST ensure that it selects a compatible PSK (if any) and cipher suite."
                // "When session resumption is the primary use case of PSKs, the most straightforward way to implement the
                //  PSK/cipher suite matching requirements is to negotiate the cipher suite first and then exclude any incompatible PSKs."
                if (candidateSession.cipher == cipher) {
                    return i;
                }
            }
            // "Any unknown PSKs (e.g., ones not in the PSK database or encrypted with an unknown key) SHOULD simply be ignored."
        }
        return null;
    }

    @Override
    public TlsSession useSession(ClientHelloPreSharedKeyExtension.PskIdentity pskIdentity) {
        // Remove session immediately, to avoid psk being used more than once.
        return sessions.remove(new BytesKey(pskIdentity.getIdentity()));
    }

    void cleanupExpiredPsks() {
        Instant now = Instant.now();
        List<BytesKey> expired = sessions.entrySet().stream()
                .filter(entry -> entry.getValue().expiry.isBefore(now))
                .map(entry -> entry.getKey())
                .collect(Collectors.toList());
        expired.forEach(key -> sessions.remove(key));
    }

    private class Session implements TlsSession {
        final byte[] ticketId;
        final byte ticketNonce;
        final long addAdd;
        final byte[] psk;
        final TlsConstants.CipherSuite cipher;
        final Instant created;
        private final Instant expiry;
        final String applicationProtocol;

        public Session(byte[] ticketId, byte ticketNonce, long addAdd, byte[] psk, TlsConstants.CipherSuite cipher, Instant created, Instant expiry, String applicationProtocol) {
            this.ticketId = ticketId;
            this.ticketNonce = ticketNonce;
            this.addAdd = addAdd;
            this.psk = psk;
            this.cipher = cipher;
            this.created = created;
            this.expiry = expiry;
            this.applicationProtocol = applicationProtocol;
        }

        @Override
        public byte[] getPsk() {
            return psk;
        }

        @Override
        public String getApplicationLayerProtocol() {
            return applicationProtocol;
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
