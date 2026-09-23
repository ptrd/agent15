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

class MLKEM1024KeyExchangeTest {

    @Test
    void clientAndServerDeriveTheSameSharedSecret() throws Exception {
        MLKEM1024KeyExchange client = new MLKEM1024KeyExchange();
        client.generateClientKeyPair();
        byte[] clientKeyShare = client.getClientKeyShare();
        assertThat(clientKeyShare).hasSize(MLKEM1024KeyExchange.ENCAPSULATION_KEY_LENGTH);

        MLKEM1024KeyExchange server = new MLKEM1024KeyExchange();
        byte[] serverSecret = server.serverProcessClientKeyShare(clientKeyShare);
        byte[] serverKeyShare = server.getServerKeyShare();
        assertThat(serverKeyShare).hasSize(MLKEM1024KeyExchange.CIPHERTEXT_LENGTH);
        assertThat(serverSecret).hasSize(MLKEM1024KeyExchange.SHARED_SECRET_LENGTH);

        byte[] clientSecret = client.clientComputeSharedSecret(serverKeyShare);
        assertThat(clientSecret).isEqualTo(serverSecret);
    }

    @Test
    void freshKeyPairsProduceDifferentKeyShares() {
        MLKEM1024KeyExchange first = new MLKEM1024KeyExchange();
        first.generateClientKeyPair();
        MLKEM1024KeyExchange second = new MLKEM1024KeyExchange();
        second.generateClientKeyPair();

        assertThat(first.getClientKeyShare()).isNotEqualTo(second.getClientKeyShare());
    }

    @Test
    void serverRejectsWrongLengthClientKeyShare() {
        MLKEM1024KeyExchange server = new MLKEM1024KeyExchange();
        assertThatThrownBy(() -> server.serverProcessClientKeyShare(new byte[100]))
                .isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void clientRejectsWrongLengthServerKeyShare() {
        MLKEM1024KeyExchange client = new MLKEM1024KeyExchange();
        client.generateClientKeyPair();
        assertThatThrownBy(() -> client.clientComputeSharedSecret(new byte[100]))
                .isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void getServerKeyShareBeforeProcessingThrows() {
        MLKEM1024KeyExchange server = new MLKEM1024KeyExchange();
        assertThatThrownBy(server::getServerKeyShare)
                .isInstanceOf(IllegalStateException.class);
    }
}
