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
import tech.kwik.agent15.engine.KeyExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static tech.kwik.agent15.TlsConstants.NamedGroup.*;

class KeyExchangeFactoryImplTest {

    @Test
    void forGroupReturnsTheHybridImplementationsForTheRfc10024Groups() {
        KeyExchangeFactoryImpl factory = new KeyExchangeFactoryImpl();

        assertThat(factory.forGroup(X25519MLKEM768)).isInstanceOf(X25519MLKEM768KeyExchange.class);
        assertThat(factory.forGroup(SecP256r1MLKEM768)).isInstanceOf(SecP256r1MLKEM768KeyExchange.class);
        assertThat(factory.forGroup(SecP384r1MLKEM1024)).isInstanceOf(SecP384r1MLKEM1024KeyExchange.class);
    }

    @Test
    void forGroupStillReturnsTheClassicalImplementationsForClassicalGroups() {
        KeyExchangeFactoryImpl factory = new KeyExchangeFactoryImpl();

        assertThat(factory.forGroup(x25519)).isInstanceOf(XDHKeyExchange.class);
        assertThat(factory.forGroup(x448)).isInstanceOf(XDHKeyExchange.class);
        assertThat(factory.forGroup(secp256r1)).isInstanceOf(ECKeyExchange.class);
        assertThat(factory.forGroup(secp384r1)).isInstanceOf(ECKeyExchange.class);
        assertThat(factory.forGroup(secp521r1)).isInstanceOf(ECKeyExchange.class);
    }

    @Test
    void initDoesNotThrowAndForGroupStillWorksAfterwards() {
        KeyExchangeFactoryImpl factory = new KeyExchangeFactoryImpl();

        factory.init();

        KeyExchange keyExchange = factory.forGroup(X25519MLKEM768);
        assertThat(keyExchange).isInstanceOf(X25519MLKEM768KeyExchange.class);
        keyExchange.generateClientKeyPair();
        assertThat(keyExchange.getClientKeyShare()).isNotEmpty();
    }
}
