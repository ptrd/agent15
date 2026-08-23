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
import tech.kwik.agent15.engine.MLKEM1024KeyExchange;

import static org.assertj.core.api.Assertions.assertThat;

class SecP384r1MLKEM1024KeyExchangeTest {

    @Test
    void clientAndServerDeriveTheSameSharedSecretWithRealComponents() throws Exception {
        SecP384r1MLKEM1024KeyExchange client = new SecP384r1MLKEM1024KeyExchange();
        client.generateClientKeyPair();
        byte[] clientKeyShare = client.getClientKeyShare();
        assertThat(clientKeyShare).hasSize(SecP384r1MLKEM1024KeyExchange.SECP384R1_SHARE_LENGTH + MLKEM1024KeyExchange.ENCAPSULATION_KEY_LENGTH);

        SecP384r1MLKEM1024KeyExchange server = new SecP384r1MLKEM1024KeyExchange();
        byte[] serverSecret = server.serverProcessClientKeyShare(clientKeyShare);
        byte[] serverKeyShare = server.getServerKeyShare();
        assertThat(serverKeyShare).hasSize(SecP384r1MLKEM1024KeyExchange.SECP384R1_SHARE_LENGTH + MLKEM1024KeyExchange.CIPHERTEXT_LENGTH);

        byte[] clientSecret = client.clientComputeSharedSecret(serverKeyShare);
        assertThat(clientSecret).isEqualTo(serverSecret);
    }
}
