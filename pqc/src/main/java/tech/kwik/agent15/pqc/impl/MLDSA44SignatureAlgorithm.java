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
 * ML-DSA-44, backing the mldsa44 TLS signature scheme. See MLDSASignatureAlgorithm for the implementation.
 */
public class MLDSA44SignatureAlgorithm extends MLDSASignatureAlgorithm {

    public static final String ALGORITHM = "ML-DSA-44";

    // Runs a throwaway key generation the first time this class is touched, charged to whichever handshake
    // triggers class loading unless SignatureAlgorithmFactory.init() is called during application start-up first
    // (see MLDSASignatureAlgorithmFactory.init()).
    private static final int PUBLIC_KEY_ENCODED_LENGTH = computePublicKeyEncodedLength(ALGORITHM);

    public MLDSA44SignatureAlgorithm() {
        super(PUBLIC_KEY_ENCODED_LENGTH);
    }
}
