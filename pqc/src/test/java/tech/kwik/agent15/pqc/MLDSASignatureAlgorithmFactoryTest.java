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

import org.junit.jupiter.api.Test;
import tech.kwik.agent15.engine.SignatureAlgorithm;
import tech.kwik.agent15.engine.SignatureAlgorithmFactory;
import tech.kwik.agent15.engine.impl.SignatureAlgorithmFactoryScanner;
import tech.kwik.agent15.pqc.impl.MLDSA44SignatureAlgorithm;
import tech.kwik.agent15.pqc.impl.MLDSA65SignatureAlgorithm;
import tech.kwik.agent15.pqc.impl.MLDSA87SignatureAlgorithm;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.assertj.core.api.Assertions.assertThat;
import static tech.kwik.agent15.TlsConstants.SignatureScheme.*;

class MLDSASignatureAlgorithmFactoryTest {

    @Test
    void forSignatureSchemeReturnsTheMlDsaImplementations() {
        SignatureAlgorithmFactory factory = new MLDSASignatureAlgorithmFactory();

        assertThat(factory.forSignatureScheme(mldsa44)).isInstanceOf(MLDSA44SignatureAlgorithm.class);
        assertThat(factory.forSignatureScheme(mldsa65)).isInstanceOf(MLDSA65SignatureAlgorithm.class);
        assertThat(factory.forSignatureScheme(mldsa87)).isInstanceOf(MLDSA87SignatureAlgorithm.class);
    }

    @Test
    void forSignatureSchemeReturnsNullForUnsupportedScheme() {
        assertThat(new MLDSASignatureAlgorithmFactory().forSignatureScheme(ecdsa_secp256r1_sha256)).isNull();
    }

    @Test
    void getSupportedSignatureSchemesReturnsExactlyTheThreeMlDsaSchemes() {
        assertThat(new MLDSASignatureAlgorithmFactory().getSupportedSignatureSchemes())
                .containsExactlyInAnyOrder(mldsa44, mldsa65, mldsa87);
    }

    @Test
    void initDoesNotThrowAndForSignatureSchemeStillWorksAfterwards() throws Exception {
        SignatureAlgorithmFactory factory = new MLDSASignatureAlgorithmFactory();

        factory.init();

        SignatureAlgorithm algorithm = factory.forSignatureScheme(mldsa65);
        KeyPair keyPair = KeyPairGenerator.getInstance(MLDSA65SignatureAlgorithm.ALGORITHM).generateKeyPair();
        byte[] content = "test".getBytes(StandardCharsets.US_ASCII);
        byte[] signature = algorithm.sign(content, keyPair.getPrivate());
        assertThat(algorithm.verify(content, signature, keyPair.getPublic())).isTrue();
    }

    @Test
    void scannerShouldFindTheMlDsaSchemesProvidedByThisModule() {
        // The engines use the scanner by default, so these schemes must be registered as a service; when they are
        // not, the scanner finds nothing and ML-DSA is never offered or accepted, even with this module present.
        SignatureAlgorithmFactory scanner = new SignatureAlgorithmFactoryScanner();

        assertThat(scanner.getSupportedSignatureSchemes()).contains(mldsa44, mldsa65, mldsa87);
        assertThat(scanner.forSignatureScheme(mldsa44)).isInstanceOf(MLDSA44SignatureAlgorithm.class);
        assertThat(scanner.forSignatureScheme(mldsa65)).isInstanceOf(MLDSA65SignatureAlgorithm.class);
        assertThat(scanner.forSignatureScheme(mldsa87)).isInstanceOf(MLDSA87SignatureAlgorithm.class);
    }
}
