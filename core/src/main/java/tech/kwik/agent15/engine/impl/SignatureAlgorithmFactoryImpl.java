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
import tech.kwik.agent15.engine.SignatureAlgorithm;
import tech.kwik.agent15.engine.SignatureAlgorithmFactory;

import java.util.List;

import static tech.kwik.agent15.TlsConstants.SignatureScheme.*;

public class SignatureAlgorithmFactoryImpl implements SignatureAlgorithmFactory {

    @Override
    public SignatureAlgorithm forSignatureScheme(TlsConstants.SignatureScheme signatureScheme) {
        switch (signatureScheme) {
            case rsa_pss_rsae_sha256:
                return new RsaPssRsaeSha256();
            case rsa_pss_rsae_sha384:
                return new RsaPssRsaeSha384();
            case rsa_pss_rsae_sha512:
                return new RsaPssRsaeSha512();
            case ecdsa_secp256r1_sha256:
                return new EcdsaSecp256r1Sha256();
            case ecdsa_secp384r1_sha384:
                return new EcdsaSecp384r1Sha384();
            case ecdsa_secp521r1_sha512:
                return new EcdsaSecp521r1Sha512();
            default:
                return null;
        }
    }

    @Override
    public List<TlsConstants.SignatureScheme> getSupportedSignatureSchemes() {
        return List.of(rsa_pss_rsae_sha256, rsa_pss_rsae_sha384, rsa_pss_rsae_sha512,
                ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, ecdsa_secp521r1_sha512);
    }

    @Override
    public void init() {
        // Nothing to warm up: these signature algorithms hold no lazily derived state.
    }
}
