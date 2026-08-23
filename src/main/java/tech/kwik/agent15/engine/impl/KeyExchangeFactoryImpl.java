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
import tech.kwik.agent15.engine.MLKEM768KeyExchange;
import tech.kwik.agent15.engine.MLKEM1024KeyExchange;

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
        if (group == X25519MLKEM768) {
            return new X25519MLKEM768KeyExchange();
        }
        if (group == SecP256r1MLKEM768) {
            return new SecP256r1MLKEM768KeyExchange();
        }
        if (group == SecP384r1MLKEM1024) {
            return new SecP384r1MLKEM1024KeyExchange();
        }
        return null;
    }

    @Override
    public void init() {
        // MLKEM768KeyExchange/MLKEM1024KeyExchange each derive and cache a
        // DER prefix from a throwaway key pair the first time the class is
        // touched (measured ~260-500us). Touching them here, explicitly,
        // means that cost lands during this warm-up call rather than on
        // whichever handshake happens to be first to need one of the
        // hybrid groups.
        new MLKEM768KeyExchange();
        new MLKEM1024KeyExchange();
    }
}
