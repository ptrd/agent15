/*
 * Copyright © 2024, 2025 Peter Doornbosch
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
package net.luminis.tls.engine;

import net.luminis.tls.CertificateUtils;
import net.luminis.tls.TlsConstants;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import static net.luminis.tls.TlsConstants.SignatureScheme;
import static net.luminis.tls.TlsConstants.SignatureScheme.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TlsServerEngineFactoryTest {

    @Test
    void selectedSignatureAlgorithForRsaWith2048BitsKey() throws Exception {
        // Given
        X509Certificate certificate = CertificateUtils.inflateCertificate(CertificateUtils.encodedKwikDotTechRsaCertificate);

        // When
        List<TlsConstants.SignatureScheme> signatureScheme = TlsServerEngineFactory.preferredSignatureSchemes(certificate, null);

        // Then
        assertThat(signatureScheme).containsExactly(rsa_pss_rsae_sha256, rsa_pss_rsae_sha384, rsa_pss_rsae_sha512);
    }

    @Test
    void whenCertificateCannotBeFoundInKeystoreProperExceptionShouldBeThrown() throws Exception {
        // Given
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(getClass().getResourceAsStream("ec-rsa-signed.p12"), "secret".toCharArray());

        String alias = "wrong";
        String keyPassword = "dontcare";

        // When
        assertThatThrownBy(() -> new TlsServerEngineFactory(keyStore, alias, keyPassword.toCharArray()))
                // Then
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("No certificate found for alias");
    }

    @Test
    void whenCertificateCannotBeLoadedFromKeystoreProperExceptionShouldBeThrown() throws Exception {
        // Given
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(getClass().getResourceAsStream("ec-rsa-signed.p12"), "secret".toCharArray());

        String alias = "example";
        String keyPassword = "wrong";

        // When
        assertThatThrownBy(() -> new TlsServerEngineFactory(keyStore, alias, keyPassword.toCharArray()))
                // Then
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("bad key");
    }

    @Test
    void selectedSignatureAlgorithForRsaWith1024BitsKeyWithBouncyCastle() throws Exception {
        try {
            // Given
            // Certificate:
            //    Data:
            //        Version: 3 (0x2)
            //        Serial Number:
            //            45:96:c5:8e:ae:15:ee:63:82:1a:3d:bc:fa:7c:e2:8f:fd:13:5b:3a
            //        Signature Algorithm: sha256WithRSAEncryption
            //        Issuer: CN=example
            //        Validity
            //            Not Before: Jun 22 16:25:57 2024 GMT
            //            Not After : Jun 20 16:25:57 2034 GMT
            //        Subject: CN=example
            //        Subject Public Key Info:
            //            Public Key Algorithm: rsaEncryption
            //                Public-Key: (1024 bit)
            Security.addProvider(new BouncyCastleProvider());
            KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
            keyStore.load(getClass().getResourceAsStream("rsa1048cert.p12"), "secret".toCharArray());
            X509Certificate certificate = (X509Certificate) keyStore.getCertificate("example");

            // When
            List<TlsConstants.SignatureScheme> signatureScheme = TlsServerEngineFactory.preferredSignatureSchemes(certificate, null);

            // Then
            assertThat(signatureScheme).containsExactly(rsa_pss_rsae_sha256, rsa_pss_rsae_sha384, rsa_pss_rsae_sha512);
        }
        finally {
            Security.removeProvider("BC");
        }
    }

    @Test
    void selectedSignatureAlgorithForRsaWith3072BitsKey() throws Exception {
        // Given
        X509Certificate certificate = CertificateUtils.inflateCertificate(CertificateUtils.encodedSampleRsa3072Certificate);

        // When
        List<SignatureScheme> signatureScheme = TlsServerEngineFactory.preferredSignatureSchemes(certificate, null);

        // Then
        assertThat(signatureScheme).containsExactly(rsa_pss_rsae_sha384, rsa_pss_rsae_sha256, rsa_pss_rsae_sha512);
    }

    @Test
    void selectedSignatureAlgorithForRsaWith4096BitsKey() throws Exception {
        // Given
        X509Certificate certificate = CertificateUtils.inflateCertificate(CertificateUtils.encodedSampleRsa4096Certificate);

        // When
        List<SignatureScheme> signatureScheme = TlsServerEngineFactory.preferredSignatureSchemes(certificate, null);

        // Then
        assertThat(signatureScheme).containsExactly(rsa_pss_rsae_sha512, rsa_pss_rsae_sha256, rsa_pss_rsae_sha384);
    }

    @Test
    void ecdsaSignatureCertificate() throws Exception {
        // Given
        X509Certificate certificate = CertificateUtils.inflateCertificate(CertificateUtils.encodedInteropLeafEcdsaCertificate);

        // When
        List<SignatureScheme> signatureScheme = TlsServerEngineFactory.preferredSignatureSchemes(certificate, null);

        // Then
        assertThat(signatureScheme).containsExactly(ecdsa_secp256r1_sha256);
    }

    @Test
    void ecdsa384SignatureCertificate() throws Exception {
        // Given
        X509Certificate certificate = CertificateUtils.inflateCertificate(CertificateUtils.encodedSampleEcdsa384Certificate);

        // When
        List<SignatureScheme> signatureScheme = TlsServerEngineFactory.preferredSignatureSchemes(certificate, null);

        // Then
        assertThat(signatureScheme).containsExactly(ecdsa_secp384r1_sha384);
    }

    @Test
    void ecdsa512SignatureCertificate() throws Exception {
        // Given
        X509Certificate certificate = CertificateUtils.inflateCertificate(CertificateUtils.encodedSampleEcdsa512Certificate);

        // When
        List<SignatureScheme> signatureScheme = TlsServerEngineFactory.preferredSignatureSchemes(certificate, null);

        // Then
        assertThat(signatureScheme).containsExactly(ecdsa_secp521r1_sha512);
    }

    @Test
    void ecdsa384signedByRsaCaCertificate() throws Exception {
        // Given
        X509Certificate certificate = CertificateUtils.inflateCertificate(CertificateUtils.encodedCA1SignedEcCert);

        // When
        List<SignatureScheme> signatureScheme = TlsServerEngineFactory.preferredSignatureSchemes(certificate, null);

        // Then
        assertThat(signatureScheme).containsExactly(ecdsa_secp384r1_sha384);
    }

    @Test
    void signatureAlgorithmCannotBeDeterminedAutomaticallyWithEcCertificateWithBouncyCastle() throws Exception {
        try {
            // Given
            Security.addProvider(new BouncyCastleProvider());
            KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
            keyStore.load(getClass().getResourceAsStream("ec-rsa-signed.p12"), "secret".toCharArray());
            X509Certificate certificate = (X509Certificate) keyStore.getCertificate("example");

            // When
            assertThatThrownBy(() ->
                    TlsServerEngineFactory.preferredSignatureSchemes(certificate, null)
            ).isInstanceOf(CertificateException.class);

            List<SignatureScheme> signatureScheme = TlsServerEngineFactory.preferredSignatureSchemes(certificate, "secp256r1");

            // Then
            assertThat(signatureScheme).containsExactly(ecdsa_secp256r1_sha256);
        }
        finally {
            Security.removeProvider("BC");
        }
    }
}