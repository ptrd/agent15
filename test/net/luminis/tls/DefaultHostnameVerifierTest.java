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
        X509Certificate certificate = CertificateUtils.inflateCertificate(encodedCertificate);

        boolean result = verifier.verify("server", certificate);

        assertThat(result).isFalse();
    }

    @Test
    void certificateWithServerNameInCommonNameShouldVerify() throws Exception {
        X509Certificate certificate =  CertificateUtils.inflateCertificate(encodedCertificate);

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

    // Subject: C=Netherlands, ST=Noord-Holland, L=Amsterdam, O=Acme, OU=orgUnit, CN=example.com
    String encodedCertificate =
            "MIIDkTCCAnmgAwIBAgIENoUsFTANBgkqhkiG9w0BAQsFADB5MRQwEgYDVQQGEwtO"
            + "ZXRoZXJsYW5kczEWMBQGA1UECBMNTm9vcmQtSG9sbGFuZDESMBAGA1UEBxMJQW1z"
            + "dGVyZGFtMQ0wCwYDVQQKEwRBY21lMRAwDgYDVQQLEwdvcmdVbml0MRQwEgYDVQQD"
            + "EwtleGFtcGxlLmNvbTAeFw0yMDA2MTMxOTMzNDZaFw0yMTA2MTMxOTMzNDZaMHkx"
            + "FDASBgNVBAYTC05ldGhlcmxhbmRzMRYwFAYDVQQIEw1Ob29yZC1Ib2xsYW5kMRIw"
            + "EAYDVQQHEwlBbXN0ZXJkYW0xDTALBgNVBAoTBEFjbWUxEDAOBgNVBAsTB29yZ1Vu"
            + "aXQxFDASBgNVBAMTC2V4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"
            + "MIIBCgKCAQEAtKDu0K5ckEvcaRV3ssntOfjeIXAm1k+P07D5Mt4LOelDa38PFYit"
            + "Se0F59Y+DHarMIt6WlL3VBI5lp+sjdh0s3/DiAQ4mT5FbCd5CGDXUVNTg7a+wFiv"
            + "pKrJc9qEuIP1on7wBLdLcFOOsio4EKKfPX4LE415yY/0ia9+Jqs2CSNZQFVPU4/q"
            + "o6i06FzB5Wo4eheqeygtvifRApOiBkqHQsAevPW7S36DmcHuVflxB66SdBhuG7Ti"
            + "lB9pxsSjouJv9iL6V3Dskyfz+AflEsVamZ6JptgkykKNCWkjwNmW5zRLxInKe9Lr"
            + "DG/QJGd2eLRox2jJgBwohaoos8yn2pbBfwIDAQABoyEwHzAdBgNVHQ4EFgQU7A5p"
            + "4w3cpH2qEgomtT+3ndNMxCkwDQYJKoZIhvcNAQELBQADggEBALEB3tDD8ZE135LD"
            + "oKoDX9Sml6MxAhq7uBJaL9hWkgz+gqkNjIP+jgZGGKjEwWzfrUAP7dxFekTIXFAY"
            + "AO6NuJT9tZTPxLBV37Ns8FulRAbofrY5UkdjDD+vjYY8vmU2xMNd48miHp1WV+Vs"
            + "21tSWUBMoPOcw6uqrnrwJQoyyuIfxLznTOO3OGnvXp/qSrHTaiIpf0yxAOEZ3/Kc"
            + "q8JO/9AmfykOeWsRKio9/V3Ccg6EiE6fdva6hXEB80ZPQZNEv9aqICupNXSMZ6HO"
            + "wwnvBmbndxsN/GBSveOI/mkS8hGSqdcCHD2H7ag0BQxsqnp7NtjgYKtTPNB/nChM"
            + "aB9pFr8=";

}