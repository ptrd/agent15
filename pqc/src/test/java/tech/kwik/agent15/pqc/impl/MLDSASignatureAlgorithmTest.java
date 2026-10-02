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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import tech.kwik.agent15.alert.InternalErrorAlert;
import tech.kwik.agent15.engine.SignatureAlgorithm;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MLDSASignatureAlgorithmTest {

    private static final byte[] CONTENT = "the content to be signed".getBytes(StandardCharsets.US_ASCII);

    enum ParameterSet {
        ML_DSA_44(MLDSA44SignatureAlgorithm.ALGORITHM, MLDSA44SignatureAlgorithm::new),
        ML_DSA_65(MLDSA65SignatureAlgorithm.ALGORITHM, MLDSA65SignatureAlgorithm::new),
        ML_DSA_87(MLDSA87SignatureAlgorithm.ALGORITHM, MLDSA87SignatureAlgorithm::new);

        final String jcaAlgorithm;
        final java.util.function.Supplier<SignatureAlgorithm> algorithmSupplier;

        ParameterSet(String jcaAlgorithm, java.util.function.Supplier<SignatureAlgorithm> algorithmSupplier) {
            this.jcaAlgorithm = jcaAlgorithm;
            this.algorithmSupplier = algorithmSupplier;
        }

        KeyPair generateKeyPair() throws Exception {
            return KeyPairGenerator.getInstance(jcaAlgorithm).generateKeyPair();
        }
    }

    @ParameterizedTest
    @EnumSource(ParameterSet.class)
    void signatureCreatedWithParameterSetShouldVerifyWithSameParameterSet(ParameterSet parameterSet) throws Exception {
        SignatureAlgorithm algorithm = parameterSet.algorithmSupplier.get();
        KeyPair keyPair = parameterSet.generateKeyPair();

        byte[] signature = algorithm.sign(CONTENT, keyPair.getPrivate());

        assertThat(algorithm.verify(CONTENT, signature, keyPair.getPublic())).isTrue();
    }

    @ParameterizedTest
    @EnumSource(ParameterSet.class)
    void verifyShouldReturnFalseWhenContentDoesNotMatchSignature(ParameterSet parameterSet) throws Exception {
        SignatureAlgorithm algorithm = parameterSet.algorithmSupplier.get();
        KeyPair keyPair = parameterSet.generateKeyPair();
        byte[] signature = algorithm.sign(CONTENT, keyPair.getPrivate());

        byte[] otherContent = "something else entirely".getBytes(StandardCharsets.US_ASCII);
        assertThat(algorithm.verify(otherContent, signature, keyPair.getPublic())).isFalse();
    }

    @ParameterizedTest
    @EnumSource(ParameterSet.class)
    void verifyShouldReturnFalseWhenSignatureIsCorrupt(ParameterSet parameterSet) throws Exception {
        SignatureAlgorithm algorithm = parameterSet.algorithmSupplier.get();
        KeyPair keyPair = parameterSet.generateKeyPair();
        byte[] signature = algorithm.sign(CONTENT, keyPair.getPrivate());

        signature[signature.length - 1] ^= 0x01;

        assertThat(algorithm.verify(CONTENT, signature, keyPair.getPublic())).isFalse();
    }

    @ParameterizedTest
    @EnumSource(ParameterSet.class)
    void keyMatchesSchemeShouldAcceptKeyOfRightParameterSet(ParameterSet parameterSet) throws Exception {
        SignatureAlgorithm algorithm = parameterSet.algorithmSupplier.get();

        assertThat(algorithm.keyMatchesScheme(parameterSet.generateKeyPair().getPublic())).isTrue();
    }

    @Test
    void keyMatchesSchemeShouldNotMatchKeyOfOtherParameterSet() throws Exception {
        // Given: a ML-DSA-65 key
        PublicKey key = ParameterSet.ML_DSA_65.generateKeyPair().getPublic();

        // When/Then: getAlgorithm() reports "ML-DSA" for every parameter set, so only the encoded length
        // distinguishes them; only the scheme for that very parameter set may match
        assertThat(new MLDSA65SignatureAlgorithm().keyMatchesScheme(key)).isTrue();
        assertThat(new MLDSA44SignatureAlgorithm().keyMatchesScheme(key)).isFalse();
        assertThat(new MLDSA87SignatureAlgorithm().keyMatchesScheme(key)).isFalse();
    }

    @Test
    void keyMatchesSchemeShouldReturnFalseWhenEncodedKeyMaterialIsMissing() {
        PublicKey keyWithoutEncoding = new PublicKey() {
            @Override
            public String getAlgorithm() {
                return "ML-DSA";
            }

            @Override
            public String getFormat() {
                return "X.509";
            }

            @Override
            public byte[] getEncoded() {
                return null;
            }
        };

        assertThat(new MLDSA65SignatureAlgorithm().keyMatchesScheme(keyWithoutEncoding)).isFalse();
    }

    @Test
    void keyMatchesSchemeShouldNotMatchEcKey() throws Exception {
        // Given: an EC public key, as a server using an ECDSA certificate would present
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        PublicKey ecKey = generator.generateKeyPair().getPublic();

        // When/Then: the ML-DSA schemes must reject it rather than fail on the key's type
        assertThat(new MLDSA44SignatureAlgorithm().keyMatchesScheme(ecKey)).isFalse();
        assertThat(new MLDSA65SignatureAlgorithm().keyMatchesScheme(ecKey)).isFalse();
        assertThat(new MLDSA87SignatureAlgorithm().keyMatchesScheme(ecKey)).isFalse();
    }

    @Test
    void signingWithKeyOfWrongTypeShouldThrowInternalErrorAlert() throws Exception {
        // Given: an EC private key, which cannot be used with ML-DSA
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair ecKeyPair = generator.generateKeyPair();

        // When/Then: a private key that cannot be used with the scheme is a configuration error on our own side
        assertThatThrownBy(() -> new MLDSA65SignatureAlgorithm().sign(CONTENT, ecKeyPair.getPrivate()))
                .isInstanceOf(InternalErrorAlert.class);
    }
}
