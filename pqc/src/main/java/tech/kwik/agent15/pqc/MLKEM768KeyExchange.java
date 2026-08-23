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
package tech.kwik.agent15.pqc;

/**
 * ML-KEM-768, the pqc component of the X25519MLKEM768 and
 * SecP256r1MLKEM768 hybrid groups (RFC 10024). See MLKEMKeyExchange for
 * the implementation.
 */
public class MLKEM768KeyExchange extends MLKEMKeyExchange {

    public static final String ALGORITHM = "ML-KEM-768";
    public static final int ENCAPSULATION_KEY_LENGTH = 1184;
    public static final int CIPHERTEXT_LENGTH = 1088;

    // TODO: this runs an extra throwaway keygen the first time this class is
    // touched (measured ~260us warmed, more like ~400-500us cold), charged to
    // whichever handshake happens to trigger class loading -- and other
    // handshakes on different SelectorLoop threads arriving concurrently
    // block on the same class-init lock, not just that one. Once
    // KeyExchangeFactory.init() has a real implementation, it should
    // reference this class (or MLKEM768KeyExchange/MLKEM1024KeyExchange
    // explicitly) so this runs during the explicit warm-up window instead of
    // on a live handshake.
    private static final byte[] PUBLIC_KEY_DER_PREFIX = computePublicKeyDerPrefix(ALGORITHM, ENCAPSULATION_KEY_LENGTH);

    public MLKEM768KeyExchange() {
        super(ALGORITHM, ENCAPSULATION_KEY_LENGTH, CIPHERTEXT_LENGTH, PUBLIC_KEY_DER_PREFIX);
    }
}
