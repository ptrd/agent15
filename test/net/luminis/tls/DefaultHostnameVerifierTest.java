/*
 * Copyright © 2019, 2020, 2021, 2022, 2023 Peter Doornbosch
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
package net.luminis.tls;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;


class DefaultHostnameVerifierTest {

    private DefaultHostnameVerifier verifier;

    @BeforeEach
    void initObjectUnderTest() {
        verifier = new DefaultHostnameVerifier();
    }

    @Test
    void certificateShouldNotVerifyWithArbitraryServerName() throws Exception {
        X509Certificate certificate = CertificateUtils.getTestCertificate();

        boolean result = verifier.verify("server", certificate);

        assertThat(result).isFalse();
    }

    @Test
    void certificateWithServerNameInCommonNameShouldVerify() throws Exception {
        X509Certificate certificate =  CertificateUtils.getTestCertificate();

        boolean result = verifier.verify("example.com", certificate);

        assertThat(result).isTrue();
    }

    @Test
    void singleDnsEntryDoesMatch() {
        List<List<?>> subjectAlternativeNames = List.of(List.of(2, "example.com"));
        boolean result = verifier.verifyHostname("example.com", subjectAlternativeNames);

        assertThat(result).isTrue();
    }

    @Test
    void noDnsEntryDoesNotMatch() {
        List<List<?>> subjectAlternativeNames = List.of(List.of(7, "14.64.231.95"));
        boolean result = verifier.verifyHostname("example.com", subjectAlternativeNames);

        assertThat(result).isFalse();
    }

    @Test
    void multipleDnsEntriesDoesMatch() {
        List<List<?>> subjectAlternativeNames = List.of(List.of(2, "sample.com"), List.of(2, "default.com"), List.of(2, "example.com"));
        boolean result = verifier.verifyHostname("example.com", subjectAlternativeNames);

        assertThat(result).isTrue();
    }

    @Test
    void nonExactMatchDoesNotMatch() {
        List<List<?>> subjectAlternativeNames = List.of(List.of(2, ".example.com"), List.of(2, "example.com.uk"), List.of(2, "sub.example.com"));
        boolean result = verifier.verifyHostname("example.com", subjectAlternativeNames);

        assertThat(result).isFalse();
    }

    @Test
    void wildcardDoesMatchSubDomain() {
        List<List<?>> subjectAlternativeNames = List.of(List.of(2, "*.example.com"));
        boolean result = verifier.verifyHostname("sub.example.com", subjectAlternativeNames);

        assertThat(result).isTrue();
    }

    @Test
    void wildcardDoesMatchDomain() {
        List<List<?>> subjectAlternativeNames = List.of(List.of(2, "*.example.com"));
        boolean result = verifier.verifyHostname("example.com", subjectAlternativeNames);

        assertThat(result).isTrue();
    }

    @Test
    void wildcardDoesNotMatchSubSubDomain() {
        List<List<?>> subjectAlternativeNames = List.of(List.of(2, "*.example.com"));
        boolean result = verifier.verifyHostname("sub.sub.example.com", subjectAlternativeNames);

        assertThat(result).isFalse();
    }

    @Test
    void partialNameMatchDoesNotMatchWildcard() {
        List<List<?>> subjectAlternativeNames = List.of(List.of(2, "*.example.com"));
        boolean result;

        result = verifier.verifyHostname("example", subjectAlternativeNames);
        assertThat(result).isFalse();

        result = verifier.verifyHostname("com", subjectAlternativeNames);
        assertThat(result).isFalse();

        result = verifier.verifyHostname("example.co", subjectAlternativeNames);
        assertThat(result).isFalse();

        result = verifier.verifyHostname("xample.com", subjectAlternativeNames);
        assertThat(result).isFalse();
    }

    @Test
    void wildcardDoesNotMatchOtherDomain() {
        List<List<?>> subjectAlternativeNames = List.of(List.of(2, "*.example.com.uk"));
        boolean result = verifier.verifyHostname("sub.example.com", subjectAlternativeNames);

        assertThat(result).isFalse();
    }

}