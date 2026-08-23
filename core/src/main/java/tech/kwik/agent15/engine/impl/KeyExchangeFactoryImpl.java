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

import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.engine.KeyExchange;
import tech.kwik.agent15.engine.KeyExchangeFactory;

import java.util.ServiceLoader;

import static tech.kwik.agent15.TlsConstants.NamedGroup.*;

public class KeyExchangeFactoryImpl implements KeyExchangeFactory {

    @Override
    public KeyExchange forGroup(TlsConstants.NamedGroup group) {
        if (group == x25519 || group == x448) {
            return new XDHKeyExchange(group);
        }
        if (group == secp256r1 || group == secp384r1 || group == secp521r1) {
            return new ECKeyExchange(group);
        }
        // Groups that core does not implement itself (the RFC 10024 hybrid groups are provided by the agent15-pqc
        // module, which requires a newer Java version) are delegated to whatever factories are on the class path.
        for (KeyExchangeFactory factory : ServiceLoader.load(KeyExchangeFactory.class)) {
            KeyExchange keyExchange = factory.forGroup(group);
            if (keyExchange != null) {
                return keyExchange;
            }
        }
        return null;
    }

    @Override
    public void init() {
        for (KeyExchangeFactory factory : ServiceLoader.load(KeyExchangeFactory.class)) {
            factory.init();
        }
    }
}
