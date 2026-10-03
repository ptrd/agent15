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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MLKEM768KeyExchangeTest {

    @Test
    void clientAndServerDeriveTheSameSharedSecret() throws Exception {
        MLKEM768KeyExchange client = new MLKEM768KeyExchange();
        client.generateClientKeyPair();
        byte[] clientKeyShare = client.getClientKeyShare();
        assertThat(clientKeyShare).hasSize(MLKEM768KeyExchange.ENCAPSULATION_KEY_LENGTH);

        MLKEM768KeyExchange server = new MLKEM768KeyExchange();
        byte[] serverSecret = server.serverProcessClientKeyShare(clientKeyShare);
        byte[] serverKeyShare = server.getServerKeyShare();
        assertThat(serverKeyShare).hasSize(MLKEM768KeyExchange.CIPHERTEXT_LENGTH);
        assertThat(serverSecret).hasSize(MLKEM768KeyExchange.SHARED_SECRET_LENGTH);

        byte[] clientSecret = client.clientComputeSharedSecret(serverKeyShare);
        assertThat(clientSecret).isEqualTo(serverSecret);
    }

    @Test
    void freshKeyPairsProduceDifferentKeyShares() {
        MLKEM768KeyExchange first = new MLKEM768KeyExchange();
        first.generateClientKeyPair();
        MLKEM768KeyExchange second = new MLKEM768KeyExchange();
        second.generateClientKeyPair();

        assertThat(first.getClientKeyShare()).isNotEqualTo(second.getClientKeyShare());
    }

    @Test
    void serverRejectsWrongLengthClientKeyShare() {
        MLKEM768KeyExchange server = new MLKEM768KeyExchange();
        assertThatThrownBy(() -> server.serverProcessClientKeyShare(new byte[100]))
                .isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void clientRejectsWrongLengthServerKeyShare() {
        MLKEM768KeyExchange client = new MLKEM768KeyExchange();
        client.generateClientKeyPair();
        assertThatThrownBy(() -> client.clientComputeSharedSecret(new byte[100]))
                .isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void getServerKeyShareBeforeProcessingThrows() {
        MLKEM768KeyExchange server = new MLKEM768KeyExchange();
        assertThatThrownBy(server::getServerKeyShare)
                .isInstanceOf(IllegalStateException.class);
    }
}
