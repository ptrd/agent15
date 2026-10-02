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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import tech.kwik.agent15.engine.SignatureAlgorithm;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Cross-checks the MLDSAxxSignatureAlgorithm classes against Bouncy Castle's independent ML-DSA implementation, in
 * both directions. The round-trip tests elsewhere only prove this code agrees with itself; this proves the
 * signatures it produces and the public keys it accepts are the standards-conformant FIPS 204 encoding an
 * unrelated implementation also produces and accepts -- not just something that happens to work against a second
 * copy of the same code.
 */
class MLDSAInteropTest {

    private static final byte[] CONTENT = "the content to be signed".getBytes(StandardCharsets.US_ASCII);

    @BeforeAll
    static void addBouncyCastleProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @AfterAll
    static void removeBouncyCastleProvider() {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

    enum ParameterSet {
        ML_DSA_44(MLDSA44SignatureAlgorithm.ALGORITHM, MLDSA44SignatureAlgorithm::new),
        ML_DSA_65(MLDSA65SignatureAlgorithm.ALGORITHM, MLDSA65SignatureAlgorithm::new),
        ML_DSA_87(MLDSA87SignatureAlgorithm.ALGORITHM, MLDSA87SignatureAlgorithm::new);

        final String jcaAlgorithm;
        final Supplier<SignatureAlgorithm> algorithmSupplier;

        ParameterSet(String jcaAlgorithm, Supplier<SignatureAlgorithm> algorithmSupplier) {
            this.jcaAlgorithm = jcaAlgorithm;
            this.algorithmSupplier = algorithmSupplier;
        }
    }

    @ParameterizedTest
    @EnumSource(ParameterSet.class)
    void bouncyCastleCanVerifyOurSignature(ParameterSet parameterSet) throws Exception {
        SignatureAlgorithm algorithm = parameterSet.algorithmSupplier.get();
        KeyPair keyPair = KeyPairGenerator.getInstance(parameterSet.jcaAlgorithm).generateKeyPair();

        byte[] signature = algorithm.sign(CONTENT, keyPair.getPrivate());

        // Bouncy Castle parses our X.509-encoded public key independently, rather than reusing the JDK's own
        // in-memory key object
        KeyFactory bcKeyFactory = KeyFactory.getInstance(parameterSet.jcaAlgorithm, "BC");
        PublicKey bcPublicKey = bcKeyFactory.generatePublic(new X509EncodedKeySpec(keyPair.getPublic().getEncoded()));

        Signature bcVerifier = Signature.getInstance("ML-DSA", "BC");
        bcVerifier.initVerify(bcPublicKey);
        bcVerifier.update(CONTENT);
        assertThat(bcVerifier.verify(signature)).isTrue();
    }

    @ParameterizedTest
    @EnumSource(ParameterSet.class)
    void weCanVerifyBouncyCastlesSignature(ParameterSet parameterSet) throws Exception {
        KeyPairGenerator bcKeyPairGenerator = KeyPairGenerator.getInstance(parameterSet.jcaAlgorithm, "BC");
        KeyPair bcKeyPair = bcKeyPairGenerator.generateKeyPair();

        Signature bcSigner = Signature.getInstance("ML-DSA", "BC");
        bcSigner.initSign(bcKeyPair.getPrivate());
        bcSigner.update(CONTENT);
        byte[] signature = bcSigner.sign();

        // Our code parses Bouncy Castle's X.509-encoded public key independently, via the JDK's own KeyFactory
        KeyFactory jdkKeyFactory = KeyFactory.getInstance("ML-DSA");
        PublicKey jdkPublicKey = jdkKeyFactory.generatePublic(new X509EncodedKeySpec(bcKeyPair.getPublic().getEncoded()));

        SignatureAlgorithm algorithm = parameterSet.algorithmSupplier.get();
        assertThat(algorithm.verify(CONTENT, signature, jdkPublicKey)).isTrue();
        assertThat(algorithm.keyMatchesScheme(jdkPublicKey)).isTrue();
    }
}
