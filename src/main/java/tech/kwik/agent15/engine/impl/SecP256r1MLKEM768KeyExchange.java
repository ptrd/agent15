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

import tech.kwik.agent15.engine.HybridKeyExchange;
import tech.kwik.agent15.engine.MLKEM768KeyExchange;

import static tech.kwik.agent15.TlsConstants.NamedGroup.secp256r1;

/**
 * The SecP256r1MLKEM768 hybrid group (RFC 10024): classical (EC) component
 * first in the client/server key shares and the secret combiner.
 */
public class SecP256r1MLKEM768KeyExchange extends HybridKeyExchange {

    // RFC 8446 section 4.2.8.2 -- matches ECKeyExchange's own (private)
    // CURVE_KEY_LENGTHS entry for secp256r1 (uncompressed point: 1 +
    // 2 * 32-byte coordinates).
    public static final int SECP256R1_SHARE_LENGTH = 65;

    public SecP256r1MLKEM768KeyExchange() {
        super("SecP256r1MLKEM768", new ECKeyExchange(secp256r1), SECP256R1_SHARE_LENGTH,
                new MLKEM768KeyExchange(), MLKEM768KeyExchange.ENCAPSULATION_KEY_LENGTH,
                MLKEM768KeyExchange.CIPHERTEXT_LENGTH, false);
    }
}
