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

import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.engine.SignatureAlgorithm;
import tech.kwik.agent15.engine.SignatureAlgorithmFactory;
import tech.kwik.agent15.pqc.impl.MLDSA44SignatureAlgorithm;
import tech.kwik.agent15.pqc.impl.MLDSA65SignatureAlgorithm;
import tech.kwik.agent15.pqc.impl.MLDSA87SignatureAlgorithm;

import java.util.List;

import static tech.kwik.agent15.TlsConstants.SignatureScheme.mldsa44;
import static tech.kwik.agent15.TlsConstants.SignatureScheme.mldsa65;
import static tech.kwik.agent15.TlsConstants.SignatureScheme.mldsa87;

/**
 * Provides the ML-DSA (<a href="https://csrc.nist.gov/pubs/fips/204/final">FIPS 204</a>) post-quantum signature
 * schemes. Registered as a {@link SignatureAlgorithmFactory} service, so core Agent15 picks these schemes up
 * whenever this module is on the class path.
 */
public class MLDSASignatureAlgorithmFactory implements SignatureAlgorithmFactory {

    @Override
    public SignatureAlgorithm forSignatureScheme(TlsConstants.SignatureScheme signatureScheme) {
        if (signatureScheme == mldsa44) {
            return new MLDSA44SignatureAlgorithm();
        }
        if (signatureScheme == mldsa65) {
            return new MLDSA65SignatureAlgorithm();
        }
        if (signatureScheme == mldsa87) {
            return new MLDSA87SignatureAlgorithm();
        }
        return null;
    }

    @Override
    public List<TlsConstants.SignatureScheme> getSupportedSignatureSchemes() {
        return List.of(mldsa44, mldsa65, mldsa87);
    }

    @Override
    public void init() {
        // Each MLDSAxxSignatureAlgorithm class derives and caches its expected public key length from a throwaway
        // key pair the first time it's touched; touching all three here means that cost lands during this
        // warm-up call rather than on whichever handshake happens to need one of them first.
        new MLDSA44SignatureAlgorithm();
        new MLDSA65SignatureAlgorithm();
        new MLDSA87SignatureAlgorithm();
    }
}
