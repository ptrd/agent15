/*
 * Copyright © 2019, 2020, 2021, 2022 Peter Doornbosch
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

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class CertificateUtils {

    public static X509Certificate inflateCertificate(String encodedCertificate) throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = certificateFactory.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(encodedCertificate.getBytes())));
        return (X509Certificate) certificate;
    }

    public static X509Certificate getTestCertificate() throws Exception {
        return inflateCertificate(encodedCertificate);
    }

    public static PrivateKey getPrivateKey() throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(encodedPrivateKey.getBytes()));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privKey = kf.generatePrivate(keySpec);
        return privKey;
    }

    // Subject: C=Netherlands, ST=Noord-Holland, L=Amsterdam, O=Acme, OU=orgUnit, CN=example.com
    static String encodedCertificate =
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

    static String encodedPrivateKey =
            "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC0oO7QrlyQS9xp" +
                    "FXeyye05+N4hcCbWT4/TsPky3gs56UNrfw8ViK1J7QXn1j4Mdqswi3paUvdUEjmW" +
                    "n6yN2HSzf8OIBDiZPkVsJ3kIYNdRU1ODtr7AWK+kqslz2oS4g/WifvAEt0twU46y" +
                    "KjgQop89fgsTjXnJj/SJr34mqzYJI1lAVU9Tj+qjqLToXMHlajh6F6p7KC2+J9EC" +
                    "k6IGSodCwB689btLfoOZwe5V+XEHrpJ0GG4btOKUH2nGxKOi4m/2IvpXcOyTJ/P4" +
                    "B+USxVqZnomm2CTKQo0JaSPA2ZbnNEvEicp70usMb9AkZ3Z4tGjHaMmAHCiFqiiz" +
                    "zKfalsF/AgMBAAECggEBAKEgUghLEX0SfsoqgT02jWxCSPwxDCPukxE2dAVhN0hw" +
                    "gVi53d3KrzIbwkHdxjnd/bVvJjS+f6w6Ga74PrfFl8yrMuP5R/fDKbBhwcCsikYc" +
                    "e4oqERyJwBy20L+M9QmXhR1v+HFshFnt34Okz6BfQIddEUpe0H3x8SSFLJYX8jrR" +
                    "Ec7HtdgtxN9CAxiS3uxSS+zS3cs5W9upzH448LwfYZDzLpDKrdGeiIISD2r2FRE5" +
                    "NS1+ob2a8g8tbZnsjgNQjwsmPOGVkXjvxQULc4tSePo/pvNUPGRpjwTWOH3S+37s" +
                    "L99FpslR3yeH2dWMv3zm0zmuSjJKpvXAfrua/jmno3kCgYEA56Or48NKxNj1oMph" +
                    "lAj0oVwF0BAj11cnMK51gXSKak4zLQXtDK/iqZlZ0p+he8v3k+6TNrNIWRhticzg" +
                    "DWE6Q3CeNov7jMvm0zZ+ssxoOxlwTk3yRCm5xi+XZ1SVy4u/CLiBlaY+OsMQhWux" +
                    "PVciOaqXKMiZBaRt/OmOSMTLgesCgYEAx5/r//xGcG+XP6IHmaPuFfjJtyY2r87c" +
                    "QzI48KC+W8ZYNuzMTUm1AQCpnIQG3iMbq3ZUm9ALmvERK+FGCGd0L1xEbtfaevcb" +
                    "X1z6qqDBN3WZI7oh772SUjFhZoHJFKGbQCIJ3sG0whyY2QK20qsyZcKXiWRNqu7m" +
                    "XfbJs+qaxb0CgYEAlvqbIs07gqpXDwJaL37W1AWC1GZwtf7cUGKlvEcVoMxvlrzy" +
                    "EP7jIeAOJ7ZcLrB3IjiyQ0j/svK1EsgykQX6T9KrjKoYv2B3httSIYARv9OI28D6" +
                    "U2tO5tpGONds+0qOrUR1UfEVRn+12QCkeXK9oBCMjcyR0JeoCNzCHLQIYRkCgYEA" +
                    "mTXBUJ/ThBnxUHJQOPgbFBv03S9kC3zNinkyQGRulUteixElIDBwzksu4iRmjPkP" +
                    "FILmHwwGzC02y6HDOVIFVxAOqa/bTEL5bDCVZn2oraMBHO2PfEvX0GN76Mu1g7Mg" +
                    "z5EQWDn9PHnsSaoOnROtw3IdEeK8xXNDtVxipEZr8VUCgYAAz9yKIB3HEBNYBT7g" +
                    "pyjkmSJDeftpup13UxDNcDQ47jwWgkQLVr1IBjLVa5NEQ28igQzY4Zugmb3qgf5u" +
                    "T85zQNvlhax7H00x+L8caBimErMrO7j3sKbnC2evp/2tUfS4997/icD1TKs76sJ1" +
                    "3Z9e2GPTQz4pixzAJJQG1sozSw==";
}
