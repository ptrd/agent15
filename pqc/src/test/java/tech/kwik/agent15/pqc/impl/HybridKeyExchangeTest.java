/*
 * Copyright © 2026 Peter Doornbosch, Chris Burdess
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
package tech.kwik.agent15.pqc.impl;

import org.junit.jupiter.api.Test;
import tech.kwik.agent15.alert.IllegalParameterAlert;
import tech.kwik.agent15.engine.KeyExchange;
import tech.kwik.agent15.pqc.impl.HybridKeyExchange;
import tech.kwik.agent15.pqc.impl.MLKEM768KeyExchange;

import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Exercises HybridKeyExchange's splitting/concatenation/combiner logic
 * using the real MLKEM768KeyExchange as the pqc component and a small
 * fake as the classical component (Agent15's own ECDH/XDH KeyExchange
 * implementations don't exist on this branch yet). The fake stands in
 * structurally for a symmetric DH exchange -- both sides derive the same
 * secret from their own and the peer's share -- which is exactly the
 * property this test needs to catch a splitting or ordering bug.
 *
 * TODO once the real X25519/ECDH KeyExchange implementations land, add
 * an equivalent round-trip test per concrete hybrid group
 * (X25519MLKEM768KeyExchangeTest etc.) using them instead of
 * FakeClassicalKeyExchange -- this class's generic-logic coverage stays
 * useful alongside those, it doesn't get replaced by them.
 */
class HybridKeyExchangeTest {

    private static final int FAKE_CLASSICAL_SHARE_LENGTH = 32;

    /** Test-only stand-in for a symmetric DH exchange (client == server shape). */
    private static class FakeClassicalKeyExchange implements KeyExchange {
        private byte[] ownShare;
        private byte[] peerShare;

        @Override
        public void generateClientKeyPair() {
            ownShare = new byte[FAKE_CLASSICAL_SHARE_LENGTH];
            new SecureRandom().nextBytes(ownShare);
        }

        @Override
        public byte[] getClientKeyShare() {
            return ownShare;
        }

        @Override
        public byte[] clientComputeSharedSecret(byte[] serverKeyShare) throws IllegalParameterAlert {
            if (serverKeyShare.length != FAKE_CLASSICAL_SHARE_LENGTH) {
                throw new IllegalParameterAlert("bad length");
            }
            return xor(ownShare, serverKeyShare);
        }

        @Override
        public byte[] serverProcessClientKeyShare(byte[] clientKeyShare) throws IllegalParameterAlert {
            if (clientKeyShare.length != FAKE_CLASSICAL_SHARE_LENGTH) {
                throw new IllegalParameterAlert("bad length");
            }
            peerShare = clientKeyShare;
            ownShare = new byte[FAKE_CLASSICAL_SHARE_LENGTH];
            new SecureRandom().nextBytes(ownShare);
            return xor(ownShare, peerShare);
        }

        @Override
        public byte[] getServerKeyShare() {
            return ownShare;
        }

        private static byte[] xor(byte[] a, byte[] b) {
            byte[] result = new byte[a.length];
            for (int i = 0; i < a.length; i++) {
                result[i] = (byte) (a[i] ^ b[i]);
            }
            return result;
        }
    }

    private static class PqcFirstHybrid extends HybridKeyExchange {
        PqcFirstHybrid() {
            super("TestHybridPqcFirst", new FakeClassicalKeyExchange(), FAKE_CLASSICAL_SHARE_LENGTH,
                    new MLKEM768KeyExchange(), MLKEM768KeyExchange.ENCAPSULATION_KEY_LENGTH,
                    MLKEM768KeyExchange.CIPHERTEXT_LENGTH, true);
        }
    }

    private static class ClassicalFirstHybrid extends HybridKeyExchange {
        ClassicalFirstHybrid() {
            super("TestHybridClassicalFirst", new FakeClassicalKeyExchange(), FAKE_CLASSICAL_SHARE_LENGTH,
                    new MLKEM768KeyExchange(), MLKEM768KeyExchange.ENCAPSULATION_KEY_LENGTH,
                    MLKEM768KeyExchange.CIPHERTEXT_LENGTH, false);
        }
    }

    @Test
    void clientAndServerDeriveTheSameSharedSecret_pqcFirst() throws Exception {
        assertRoundTrips(new PqcFirstHybrid(), new PqcFirstHybrid());
    }

    @Test
    void clientAndServerDeriveTheSameSharedSecret_classicalFirst() throws Exception {
        assertRoundTrips(new ClassicalFirstHybrid(), new ClassicalFirstHybrid());
    }

    private void assertRoundTrips(HybridKeyExchange client, HybridKeyExchange server) throws Exception {
        int expectedShareLength = FAKE_CLASSICAL_SHARE_LENGTH + MLKEM768KeyExchange.ENCAPSULATION_KEY_LENGTH;
        int expectedServerShareLength = FAKE_CLASSICAL_SHARE_LENGTH + MLKEM768KeyExchange.CIPHERTEXT_LENGTH;
        int expectedSecretLength = FAKE_CLASSICAL_SHARE_LENGTH + MLKEM768KeyExchange.SHARED_SECRET_LENGTH;

        client.generateClientKeyPair();
        byte[] clientKeyShare = client.getClientKeyShare();
        assertThat(clientKeyShare).hasSize(expectedShareLength);

        byte[] serverSecret = server.serverProcessClientKeyShare(clientKeyShare);
        byte[] serverKeyShare = server.getServerKeyShare();
        assertThat(serverKeyShare).hasSize(expectedServerShareLength);
        assertThat(serverSecret).hasSize(expectedSecretLength);

        byte[] clientSecret = client.clientComputeSharedSecret(serverKeyShare);
        assertThat(clientSecret).isEqualTo(serverSecret);
    }

    @Test
    void pqcFirstAndClassicalFirstProduceDifferentlyOrderedSecrets() throws Exception {
        // Same two component exchanges, only the order flag differs -- if the
        // order weren't actually applied, both would be indistinguishable.
        FakeClassicalKeyExchange classicalA = new FakeClassicalKeyExchange();
        MLKEM768KeyExchange pqcA = new MLKEM768KeyExchange();
        HybridKeyExchange pqcFirstClient = new HybridKeyExchange("a", classicalA, FAKE_CLASSICAL_SHARE_LENGTH,
                pqcA, MLKEM768KeyExchange.ENCAPSULATION_KEY_LENGTH, MLKEM768KeyExchange.CIPHERTEXT_LENGTH, true) {};

        FakeClassicalKeyExchange classicalB = new FakeClassicalKeyExchange();
        MLKEM768KeyExchange pqcB = new MLKEM768KeyExchange();
        HybridKeyExchange classicalFirstClient = new HybridKeyExchange("b", classicalB, FAKE_CLASSICAL_SHARE_LENGTH,
                pqcB, MLKEM768KeyExchange.ENCAPSULATION_KEY_LENGTH, MLKEM768KeyExchange.CIPHERTEXT_LENGTH, false) {};

        pqcFirstClient.generateClientKeyPair();
        classicalFirstClient.generateClientKeyPair();

        // Same underlying classical/pqc shares, reordered -- the pqcFirst share
        // is just the classicalFirst share with its two halves swapped.
        byte[] a = pqcFirstClient.getClientKeyShare();
        byte[] b = classicalFirstClient.getClientKeyShare();
        assertThat(a).isNotEqualTo(b);
    }

    @Test
    void rejectsWrongLengthServerKeyShare() {
        HybridKeyExchange client = new PqcFirstHybrid();
        client.generateClientKeyPair();
        assertThatThrownBy(() -> client.clientComputeSharedSecret(new byte[10]))
                .isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void rejectsWrongLengthClientKeyShare() {
        HybridKeyExchange server = new PqcFirstHybrid();
        assertThatThrownBy(() -> server.serverProcessClientKeyShare(new byte[10]))
                .isInstanceOf(IllegalParameterAlert.class);
    }
}
