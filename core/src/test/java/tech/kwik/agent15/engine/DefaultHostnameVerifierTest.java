/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
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
package tech.kwik.agent15.engine;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.kwik.agent15.util.CertificateUtils;

import javax.security.auth.x500.X500Principal;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


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
    void wildcardShouldNotMatchBaseDomain() {
        // Per RFC 6125 §6.4.3, a wildcard certificate for *.example.com should only match
        // subdomains (e.g. sub.example.com), not the base domain (example.com) itself.
        List<List<?>> subjectAlternativeNames = List.of(List.of(2, "*.example.com"));
        boolean result = verifier.verifyHostname("example.com", subjectAlternativeNames);

        assertThat(result).isFalse();
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
    void dnWithoutCnShouldNotMatch() {
        // A subject DN with no CN attribute should not match any hostname.
        X500Principal dnWithoutCn = new X500Principal("O=SomeOrg, L=SomeCity, C=US");
        boolean result = verifier.verifyHostname("example.com", dnWithoutCn);

        assertThat(result).isFalse();
    }

    @Test
    void cnValueContainingCnEqualsShouldNotMatchManipulatedHostname() {
        Principal dn = () -> "CN=evil.CN=example.com";
        boolean result = verifier.verifyHostname("evil.example.com", dn);

        assertThat(result).isFalse();
    }

    @Test
    void wildcardDoesNotMatchOtherDomain() {
        List<List<?>> subjectAlternativeNames = List.of(List.of(2, "*.example.com.uk"));
        boolean result = verifier.verifyHostname("sub.example.com", subjectAlternativeNames);

        assertThat(result).isFalse();
    }

    @Test
    void sanDnsNameMatchShouldBeCaseInsensitive() {
        List<List<?>> subjectAlternativeNames = List.of(List.of(2, "Example.COM"));
        boolean result = verifier.verifyHostname("example.com", subjectAlternativeNames);

        assertThat(result).isTrue();
    }

    @Test
    void wildcardSanMatchShouldBeCaseInsensitive() {
        List<List<?>> subjectAlternativeNames = List.of(List.of(2, "*.Example.COM"));
        boolean result = verifier.verifyHostname("Sub.example.com", subjectAlternativeNames);

        assertThat(result).isTrue();
    }

    @Test
    void emptySanShouldNotMatch() {
        List<List<?>> subjectAlternativeNames = List.of();
        boolean result = verifier.verifyHostname("example.com", subjectAlternativeNames);

        assertThat(result).isFalse();
    }

    @Test
    void cnMatchShouldBeCaseInsensitive() {
        Principal dn = () -> "CN=Example.COM";
        boolean result = verifier.verifyHostname("example.com", dn);

        assertThat(result).isTrue();
    }

    @Test
    void dnWithAttributeValueLookingLikeCnShouldNotMatch() {
        // A naive comma-split DN parser does not honour RFC 2253 escaping. If an attacker
        // can influence a non-CN attribute (e.g. the Organization), they could embed an
        // escaped comma followed by "CN=victim.com" inside that value. The split-on-comma
        // parser would then see "CN=victim.com" as a separate RDN even though the actual
        // leaf CN is "attacker.com".
        //
        // String literal: O=acme\,CN=victim.com,CN=attacker.com
        Principal dn = () -> "O=acme\\,CN=victim.com,CN=attacker.com";
        boolean result = verifier.verifyHostname("victim.com", dn);

        assertThat(result).isFalse();
    }

    @Test
    void dnWithMultipleCnShouldOnlyMatchLeafCn() {
        // RFC 2253 lists RDNs from leaf (most specific) to root. For certificate identity
        // only the leaf CN should be considered. Here the leaf CN is "attacker.com"; the
        // second "CN=victim.com" is some other CN-typed RDN higher up in the tree. A
        // connection to "victim.com" must not be accepted just because "victim.com" appears
        // anywhere in the DN.
        Principal dn = () -> "CN=attacker.com,CN=victim.com,O=SomeOrg, L=SomeCity, C=US";
        boolean result = verifier.verifyHostname("victim.com", dn);

        assertThat(result).isFalse();
    }

    @Test
    void whenSanIsPresentCnMustNotBeUsedAsFallback() throws Exception {
        // A certificate with a non-matching dNSName SAN entry must not be accepted just because
        // the CN happens to match the requested server name.

        // Given
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getSubjectAlternativeNames()).thenReturn(List.of(List.of(2, "other.example.org")));
        when(certificate.getSubjectDN()).thenReturn((Principal) () -> "CN=legitimate.com");

        // When
        boolean matches = verifier.verify("legitimate.com", certificate);

        // Then
        assertThat(matches).isFalse();
    }
}