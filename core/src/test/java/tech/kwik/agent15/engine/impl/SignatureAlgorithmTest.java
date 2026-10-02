/*
 * Copyright © 2026 Peter Doornbosch
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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import tech.kwik.agent15.TlsConstants.SignatureScheme;
import tech.kwik.agent15.alert.InternalErrorAlert;
import tech.kwik.agent15.engine.SignatureAlgorithm;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static tech.kwik.agent15.TlsConstants.SignatureScheme.ecdsa_secp256r1_sha256;
import static tech.kwik.agent15.TlsConstants.SignatureScheme.ecdsa_secp384r1_sha384;
import static tech.kwik.agent15.TlsConstants.SignatureScheme.ecdsa_secp521r1_sha512;
import static tech.kwik.agent15.TlsConstants.SignatureScheme.rsa_pss_rsae_sha256;
import static tech.kwik.agent15.TlsConstants.SignatureScheme.rsa_pss_rsae_sha384;
import static tech.kwik.agent15.TlsConstants.SignatureScheme.rsa_pss_rsae_sha512;

class SignatureAlgorithmTest {

    private static final byte[] CONTENT = "the content to be signed".getBytes(StandardCharsets.US_ASCII);

    private final SignatureAlgorithmFactoryImpl factory = new SignatureAlgorithmFactoryImpl();

    /**
     * The signature schemes this test knows how to create a key pair for; these are exactly the schemes the factory
     * claims to support.
     */
    enum SupportedScheme {
        RSA_PSS_RSAE_SHA256(rsa_pss_rsae_sha256, "RSA", null),
        RSA_PSS_RSAE_SHA384(rsa_pss_rsae_sha384, "RSA", null),
        RSA_PSS_RSAE_SHA512(rsa_pss_rsae_sha512, "RSA", null),
        ECDSA_SECP256R1_SHA256(ecdsa_secp256r1_sha256, "EC", "secp256r1"),
        ECDSA_SECP384R1_SHA384(ecdsa_secp384r1_sha384, "EC", "secp384r1"),
        ECDSA_SECP521R1_SHA512(ecdsa_secp521r1_sha512, "EC", "secp521r1");

        final SignatureScheme scheme;
        final String keyAlgorithm;
        final String curveName;

        SupportedScheme(SignatureScheme scheme, String keyAlgorithm, String curveName) {
            this.scheme = scheme;
            this.keyAlgorithm = keyAlgorithm;
            this.curveName = curveName;
        }

        KeyPair generateKeyPair() throws Exception {
            return SignatureAlgorithmTest.generateKeyPair(keyAlgorithm, curveName);
        }
    }

    @ParameterizedTest
    @EnumSource(SupportedScheme.class)
    void signatureCreatedWithSchemeShouldVerifyWithSameScheme(SupportedScheme supported) throws Exception {
        // Given
        SignatureAlgorithm algorithm = factory.forSignatureScheme(supported.scheme);
        KeyPair keyPair = supported.generateKeyPair();

        // When
        byte[] signature = algorithm.sign(CONTENT, keyPair.getPrivate());

        // Then
        assertThat(algorithm.verify(CONTENT, signature, keyPair.getPublic())).isTrue();
    }

    @ParameterizedTest
    @EnumSource(SupportedScheme.class)
    void verifyShouldReturnFalseWhenContentDoesNotMatchSignature(SupportedScheme supported) throws Exception {
        // Given
        SignatureAlgorithm algorithm = factory.forSignatureScheme(supported.scheme);
        KeyPair keyPair = supported.generateKeyPair();
        byte[] signature = algorithm.sign(CONTENT, keyPair.getPrivate());

        // When/Then: the signature does not cover this content, but that must not throw
        byte[] otherContent = "something else entirely".getBytes(StandardCharsets.US_ASCII);
        assertThat(algorithm.verify(otherContent, signature, keyPair.getPublic())).isFalse();
    }

    @ParameterizedTest
    @EnumSource(SupportedScheme.class)
    void verifyShouldReturnFalseWhenSignatureIsCorrupt(SupportedScheme supported) throws Exception {
        // Given
        SignatureAlgorithm algorithm = factory.forSignatureScheme(supported.scheme);
        KeyPair keyPair = supported.generateKeyPair();
        byte[] signature = algorithm.sign(CONTENT, keyPair.getPrivate());

        // When
        signature[signature.length - 1] ^= 0x01;

        // Then
        assertThat(algorithm.verify(CONTENT, signature, keyPair.getPublic())).isFalse();
    }

    @ParameterizedTest
    @EnumSource(SupportedScheme.class)
    void keyMatchesSchemeShouldAcceptKeyOfRightTypeAndCurve(SupportedScheme supported) throws Exception {
        // Given
        SignatureAlgorithm algorithm = factory.forSignatureScheme(supported.scheme);

        // When/Then
        assertThat(algorithm.keyMatchesScheme(supported.generateKeyPair().getPublic())).isTrue();
    }

    @Test
    void ecdsaSchemeShouldNotMatchRsaKey() throws Exception {
        // Given: an RSA public key, as a server using an RSA certificate would present
        PublicKey rsaKey = generateKeyPair("RSA", null).getPublic();

        // When/Then: the ecdsa schemes must reject it rather than fail on the key's type
        assertThat(new EcdsaSecp256r1Sha256().keyMatchesScheme(rsaKey)).isFalse();
        assertThat(new EcdsaSecp384r1Sha384().keyMatchesScheme(rsaKey)).isFalse();
        assertThat(new EcdsaSecp521r1Sha512().keyMatchesScheme(rsaKey)).isFalse();
    }

    @Test
    void rsaPssSchemeShouldNotMatchEcKey() throws Exception {
        // Given
        PublicKey ecKey = generateKeyPair("EC", "secp256r1").getPublic();

        // When/Then
        assertThat(new RsaPssRsaeSha256().keyMatchesScheme(ecKey)).isFalse();
        assertThat(new RsaPssRsaeSha384().keyMatchesScheme(ecKey)).isFalse();
        assertThat(new RsaPssRsaeSha512().keyMatchesScheme(ecKey)).isFalse();
    }

    @Test
    void ecdsaSchemeShouldNotMatchKeyOnOtherCurve() throws Exception {
        // Given: a key on secp384r1
        PublicKey key = generateKeyPair("EC", "secp384r1").getPublic();

        // When/Then: only the scheme for that very curve matches
        assertThat(new EcdsaSecp384r1Sha384().keyMatchesScheme(key)).isTrue();
        assertThat(new EcdsaSecp256r1Sha256().keyMatchesScheme(key)).isFalse();
        assertThat(new EcdsaSecp521r1Sha512().keyMatchesScheme(key)).isFalse();
    }

    @Test
    void signingWithKeyOfWrongTypeShouldThrowInternalErrorAlert() throws Exception {
        // Given
        KeyPair rsaKeyPair = generateKeyPair("RSA", null);
        KeyPair ecKeyPair = generateKeyPair("EC", "secp256r1");

        // When/Then: a private key that cannot be used with the scheme is a configuration error on our own side
        assertThatThrownBy(() -> new EcdsaSecp256r1Sha256().sign(CONTENT, rsaKeyPair.getPrivate()))
                .isInstanceOf(InternalErrorAlert.class);
        assertThatThrownBy(() -> new RsaPssRsaeSha256().sign(CONTENT, ecKeyPair.getPrivate()))
                .isInstanceOf(InternalErrorAlert.class);
    }

    private static KeyPair generateKeyPair(String keyAlgorithm, String curveName) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(keyAlgorithm);
        if (curveName != null) {
            generator.initialize(new ECGenParameterSpec(curveName));
        }
        else {
            generator.initialize(2048);
        }
        return generator.generateKeyPair();
    }
}
