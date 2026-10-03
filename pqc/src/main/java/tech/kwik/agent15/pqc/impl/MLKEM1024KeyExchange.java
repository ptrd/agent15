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

/**
 * ML-KEM-1024, the pqc component of the SecP384r1MLKEM1024 hybrid group
 * (RFC 10024). See MLKEMKeyExchange for the implementation.
 */
public class MLKEM1024KeyExchange extends MLKEMKeyExchange {

    public static final String ALGORITHM = "ML-KEM-1024";
    public static final int ENCAPSULATION_KEY_LENGTH = 1568;
    public static final int CIPHERTEXT_LENGTH = 1568;

    // TODO: see MLKEM768KeyExchange's PUBLIC_KEY_DER_PREFIX for why this
    // needs to be touched by KeyExchangeFactory.init() once that has a real
    // implementation.
    private static final byte[] PUBLIC_KEY_DER_PREFIX = computePublicKeyDerPrefix(ALGORITHM, ENCAPSULATION_KEY_LENGTH);

    public MLKEM1024KeyExchange() {
        super(ALGORITHM, ENCAPSULATION_KEY_LENGTH, CIPHERTEXT_LENGTH, PUBLIC_KEY_DER_PREFIX);
    }
}
