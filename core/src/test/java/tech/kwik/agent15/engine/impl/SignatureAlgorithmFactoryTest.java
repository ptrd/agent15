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
import tech.kwik.agent15.TlsConstants.SignatureScheme;
import tech.kwik.agent15.engine.SignatureAlgorithmFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static tech.kwik.agent15.TlsConstants.SignatureScheme.ecdsa_secp256r1_sha256;
import static tech.kwik.agent15.TlsConstants.SignatureScheme.ecdsa_secp384r1_sha384;
import static tech.kwik.agent15.TlsConstants.SignatureScheme.ecdsa_secp521r1_sha512;
import static tech.kwik.agent15.TlsConstants.SignatureScheme.rsa_pkcs1_sha1;
import static tech.kwik.agent15.TlsConstants.SignatureScheme.rsa_pss_rsae_sha256;
import static tech.kwik.agent15.TlsConstants.SignatureScheme.rsa_pss_rsae_sha384;
import static tech.kwik.agent15.TlsConstants.SignatureScheme.rsa_pss_rsae_sha512;

class SignatureAlgorithmFactoryTest {

    @Test
    void factoryShouldSupportTheSignatureSchemesCoreImplements() {
        assertThat(new SignatureAlgorithmFactoryImpl().getSupportedSignatureSchemes())
                .containsExactlyInAnyOrder(rsa_pss_rsae_sha256, rsa_pss_rsae_sha384, rsa_pss_rsae_sha512,
                        ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, ecdsa_secp521r1_sha512);
    }

    @Test
    void everySupportedSchemeShouldYieldAnAlgorithm() {
        SignatureAlgorithmFactory factory = new SignatureAlgorithmFactoryImpl();

        for (SignatureScheme scheme : factory.getSupportedSignatureSchemes()) {
            assertThat(factory.forSignatureScheme(scheme)).as("algorithm for " + scheme).isNotNull();
        }
    }

    @Test
    void factoryShouldReturnNullForUnsupportedScheme() {
        assertThat(new SignatureAlgorithmFactoryImpl().forSignatureScheme(rsa_pkcs1_sha1)).isNull();
    }

    @Test
    void factoryShouldCreateTheAlgorithmThatBelongsToTheScheme() {
        SignatureAlgorithmFactory factory = new SignatureAlgorithmFactoryImpl();

        assertThat(factory.forSignatureScheme(rsa_pss_rsae_sha256)).isInstanceOf(RsaPssRsaeSha256.class);
        assertThat(factory.forSignatureScheme(rsa_pss_rsae_sha384)).isInstanceOf(RsaPssRsaeSha384.class);
        assertThat(factory.forSignatureScheme(rsa_pss_rsae_sha512)).isInstanceOf(RsaPssRsaeSha512.class);
        assertThat(factory.forSignatureScheme(ecdsa_secp256r1_sha256)).isInstanceOf(EcdsaSecp256r1Sha256.class);
        assertThat(factory.forSignatureScheme(ecdsa_secp384r1_sha384)).isInstanceOf(EcdsaSecp384r1Sha384.class);
        assertThat(factory.forSignatureScheme(ecdsa_secp521r1_sha512)).isInstanceOf(EcdsaSecp521r1Sha512.class);
    }

    @Test
    void scannerShouldFindTheSignatureAlgorithmsProvidedByCore() {
        // The engines use the scanner by default, so the algorithms core implements must be registered as a service;
        // when they are not, the scanner finds nothing and every handshake fails on the certificate verify message.
        SignatureAlgorithmFactory scanner = new SignatureAlgorithmFactoryScanner();

        assertThat(scanner.getSupportedSignatureSchemes())
                .containsExactlyInAnyOrderElementsOf(new SignatureAlgorithmFactoryImpl().getSupportedSignatureSchemes());
    }

    @Test
    void scannerShouldCreateAnAlgorithmForEverySchemeItSupports() {
        SignatureAlgorithmFactory scanner = new SignatureAlgorithmFactoryScanner();

        for (SignatureScheme scheme : scanner.getSupportedSignatureSchemes()) {
            assertThat(scanner.forSignatureScheme(scheme)).as("algorithm for " + scheme).isNotNull();
        }
    }

    @Test
    void scannerShouldReturnNullForUnsupportedScheme() {
        assertThat(new SignatureAlgorithmFactoryScanner().forSignatureScheme(rsa_pkcs1_sha1)).isNull();
    }
}
