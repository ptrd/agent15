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
package tech.kwik.agent15.engine.impl;

import org.junit.jupiter.api.Test;
import tech.kwik.agent15.engine.MLKEM768KeyExchange;

import static org.assertj.core.api.Assertions.assertThat;

class X25519MLKEM768KeyExchangeTest {

    @Test
    void clientAndServerDeriveTheSameSharedSecretWithRealComponents() throws Exception {
        X25519MLKEM768KeyExchange client = new X25519MLKEM768KeyExchange();
        client.generateClientKeyPair();
        byte[] clientKeyShare = client.getClientKeyShare();
        assertThat(clientKeyShare).hasSize(X25519MLKEM768KeyExchange.X25519_SHARE_LENGTH + MLKEM768KeyExchange.ENCAPSULATION_KEY_LENGTH);

        X25519MLKEM768KeyExchange server = new X25519MLKEM768KeyExchange();
        byte[] serverSecret = server.serverProcessClientKeyShare(clientKeyShare);
        byte[] serverKeyShare = server.getServerKeyShare();
        assertThat(serverKeyShare).hasSize(X25519MLKEM768KeyExchange.X25519_SHARE_LENGTH + MLKEM768KeyExchange.CIPHERTEXT_LENGTH);

        byte[] clientSecret = client.clientComputeSharedSecret(serverKeyShare);
        assertThat(clientSecret).isEqualTo(serverSecret);
    }
}
