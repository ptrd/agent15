/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.agent15;

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

    /**
     * Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number: 914697237 (0x36852c15)
     *         Signature Algorithm: sha256WithRSAEncryption
     *         Issuer: C=Netherlands, ST=Noord-Holland, L=Amsterdam, O=Acme, OU=orgUnit, CN=example.com
     *         Validity
     *             Not Before: Jun 13 19:33:46 2020 GMT
     *             Not After : Jun 13 19:33:46 2021 GMT
     *         Subject: C=Netherlands, ST=Noord-Holland, L=Amsterdam, O=Acme, OU=orgUnit, CN=example.com
     *         Subject Public Key Info:
     *             Public Key Algorithm: rsaEncryption
     *                 Public-Key: (2048 bit)
     *         X509v3 extensions:
     *             X509v3 Subject Key Identifier:
     *                 EC:0E:69:E3:0D:DC:A4:7D:AA:12:0A:26:B5:3F:B7:9D:D3:4C:C4:29
     *     Signature Algorithm: sha256WithRSAEncryption
     */
    static String encodedCertificate = "" +
            "MIIDkTCCAnmgAwIBAgIENoUsFTANBgkqhkiG9w0BAQsFADB5MRQwEgYDVQQGEwtO" +
            "ZXRoZXJsYW5kczEWMBQGA1UECBMNTm9vcmQtSG9sbGFuZDESMBAGA1UEBxMJQW1z" +
            "dGVyZGFtMQ0wCwYDVQQKEwRBY21lMRAwDgYDVQQLEwdvcmdVbml0MRQwEgYDVQQD" +
            "EwtleGFtcGxlLmNvbTAeFw0yMDA2MTMxOTMzNDZaFw0yMTA2MTMxOTMzNDZaMHkx" +
            "FDASBgNVBAYTC05ldGhlcmxhbmRzMRYwFAYDVQQIEw1Ob29yZC1Ib2xsYW5kMRIw" +
            "EAYDVQQHEwlBbXN0ZXJkYW0xDTALBgNVBAoTBEFjbWUxEDAOBgNVBAsTB29yZ1Vu" +
            "aXQxFDASBgNVBAMTC2V4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A" +
            "MIIBCgKCAQEAtKDu0K5ckEvcaRV3ssntOfjeIXAm1k+P07D5Mt4LOelDa38PFYit" +
            "Se0F59Y+DHarMIt6WlL3VBI5lp+sjdh0s3/DiAQ4mT5FbCd5CGDXUVNTg7a+wFiv" +
            "pKrJc9qEuIP1on7wBLdLcFOOsio4EKKfPX4LE415yY/0ia9+Jqs2CSNZQFVPU4/q" +
            "o6i06FzB5Wo4eheqeygtvifRApOiBkqHQsAevPW7S36DmcHuVflxB66SdBhuG7Ti" +
            "lB9pxsSjouJv9iL6V3Dskyfz+AflEsVamZ6JptgkykKNCWkjwNmW5zRLxInKe9Lr" +
            "DG/QJGd2eLRox2jJgBwohaoos8yn2pbBfwIDAQABoyEwHzAdBgNVHQ4EFgQU7A5p" +
            "4w3cpH2qEgomtT+3ndNMxCkwDQYJKoZIhvcNAQELBQADggEBALEB3tDD8ZE135LD" +
            "oKoDX9Sml6MxAhq7uBJaL9hWkgz+gqkNjIP+jgZGGKjEwWzfrUAP7dxFekTIXFAY" +
            "AO6NuJT9tZTPxLBV37Ns8FulRAbofrY5UkdjDD+vjYY8vmU2xMNd48miHp1WV+Vs" +
            "21tSWUBMoPOcw6uqrnrwJQoyyuIfxLznTOO3OGnvXp/qSrHTaiIpf0yxAOEZ3/Kc" +
            "q8JO/9AmfykOeWsRKio9/V3Ccg6EiE6fdva6hXEB80ZPQZNEv9aqICupNXSMZ6HO" +
            "wwnvBmbndxsN/GBSveOI/mkS8hGSqdcCHD2H7ag0BQxsqnp7NtjgYKtTPNB/nChM" +
            "aB9pFr8=";

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

    /**
     * Self-signed certificate for kwik.tech
     *
     * Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number: 662855123 (0x27825dd3)
     *         Signature Algorithm: sha256WithRSAEncryption
     *         Issuer: CN=kwik.tech
     *         Validity
     *             Not Before: Jun  1 10:24:33 2020 GMT
     *             Not After : Jun  1 10:24:33 2021 GMT
     *         Subject: CN=kwik.tech
     *         Subject Public Key Info:
     *             Public Key Algorithm: rsaEncryption
     *                 Public-Key: (2048 bit)
     *         X509v3 extensions:
     *             X509v3 Subject Key Identifier:
     *                 0A:11:35:6A:5C:D4:44:7B:9D:72:19:7B:2D:67:E4:D0:92:1D:B5:6C
     *     Signature Algorithm: sha256WithRSAEncryption
     */
    public static String encodedKwikDotTechRsaCertificate =
            "MIICxzCCAa+gAwIBAgIEJ4Jd0zANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDEwlr" +
            "d2lrLnRlY2gwHhcNMjAwNjAxMTAyNDMzWhcNMjEwNjAxMTAyNDMzWjAUMRIwEAYD" +
            "VQQDEwlrd2lrLnRlY2gwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCD" +
            "fGLG29p6hjY251wLhSWd1Al9utOd3pkUteFX4pXDi8pgumq3pL6CsEsD9sj1XmCX" +
            "CcWWTVlU0tPHq74daA/gm6KHubtNmyLESS38e5gjC3PCRz5ock4h9IZvsrhoFz9K" +
            "pFs3edTtglaiB0dl2nIm281upk3f2qXN/+JQAK9F5jtimYRaNfUGkPFyHy278tzu" +
            "xEblg+TreCA8L7TJjJz/H/Y+OtYgZFza6K6mGxhm6ykHKbNZOfv76k0KJTC4u/Fz" +
            "V2ReFqfwYip+S4/8M9QHbIx1xQwbFBeDhTQHfM6jak1GrzbIGTs6TWpFFzv7qQip" +
            "DP29HpI5Xgsjy8J5ui9fAgMBAAGjITAfMB0GA1UdDgQWBBQKETVqXNREe51yGXst" +
            "Z+TQkh21bDANBgkqhkiG9w0BAQsFAAOCAQEAWuVsyQLbUdasz1YgbYzdH8SsxtVe" +
            "EwJIhw3YQk9ongDaFxogk+rgqMTBt8CBU0OzYqddKPSCtm1RQGG08qQv00Rzev3c" +
            "VsDHZZM9GiK1TYHnYeYc2hV9UCxxmEcDrs86NHV+eCGjTuw8FJr3owLJs/lnukbw" +
            "SFHMKmPIHbNn1LLMR0oEu7w0h8DEQ6CI/lfpF/F+mcgjrHrDgvC0QP+0ZiUH95YL" +
            "OBaxTtxi3ZDIfGofw3tHJoq55I4SuZcvCKid0FKeCunomfuIHsvCVyVYJcHSaMMa" +
            "vMBM0Kn6CfdkQukplJzwNujbXJtvxx4a7+UPEzfEmBUuuVRZ3rzjq2u46w==";

    public static String encodedKwikDotTechRsaCertificatePrivateKey =
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCDfGLG29p6hjY2" +
            "51wLhSWd1Al9utOd3pkUteFX4pXDi8pgumq3pL6CsEsD9sj1XmCXCcWWTVlU0tPH" +
            "q74daA/gm6KHubtNmyLESS38e5gjC3PCRz5ock4h9IZvsrhoFz9KpFs3edTtglai" +
            "B0dl2nIm281upk3f2qXN/+JQAK9F5jtimYRaNfUGkPFyHy278tzuxEblg+TreCA8" +
            "L7TJjJz/H/Y+OtYgZFza6K6mGxhm6ykHKbNZOfv76k0KJTC4u/FzV2ReFqfwYip+" +
            "S4/8M9QHbIx1xQwbFBeDhTQHfM6jak1GrzbIGTs6TWpFFzv7qQipDP29HpI5Xgsj" +
            "y8J5ui9fAgMBAAECggEAWddn9tDKW+XQrXswXX7A0TLMuWgqqDgtCQWtz8s24cJm" +
            "qek2efzLX6jt2OuLLH0sKoe2xphbbaYQpuImqRktoB830t2JqeFSxCPslBQvQ+LT" +
            "WfAsKFnSIUlfgnrvndAkou/ik+lfIFpqr5OhqWq1jO+rUuu3UjmoCTXKgTe2i19k" +
            "/MeoNP6/OvzuHy8mQLb2Zf2nBx6h+Xn29vvsjvyIhBzSvtZCq9pcPdmRku8CPfql" +
            "cWjGvAGEKxzsSJS5jE4doet+8h+kjgeWUE6jP2Nbkj4yr7pRbKd2PhGlZ0kdfpWz" +
            "1HipRpJ3lilI2ddknU9c6wxl0cKNtM6+/vBT3/V2AQKBgQDM2s5rmqZwmoFIhJ6M" +
            "TFVXGOY5iW/Wj3vhGAQxG4ZPdIOIfH+yvQmSEBjGqkN4BJFlh3EHj8cHFbSggOAf" +
            "0obrMwbXCnzVH4zP0gwyr9xiZlNqA4EmwmvFm22R1X5JjBmq/Nn9HjXLs+/Hy+Uz" +
            "EdoATv44RlclilrOCNCnzF0zHwKBgQCkUD6vfHNvVBhjjCv3q2gQYhzRNtFkOcDV" +
            "scs4+nbEcq8kCMwHUVomvZt5gjr6edSQjNWkpdfYrWai7F8CHv0aSGc7RO2YGw9d" +
            "3/fQpwTC77qYegLyLkd7p1UmVyOm6eHT68bU6hn2QXYhmRgQ+0GzHIOeWTWaPTMC" +
            "fJr/4AG7wQKBgByHcG3t6LYP3mdiCM6TJuNtVUq4CDpCW0c62AKaybaxDExqwkH7" +
            "L6UG1tx8A89oG3OfTC94Z4hmDnS33f6wjBefUJmMHVx0+2BJ6Wb5tOCDTaSa/laO" +
            "hwHLJpRDvkWx3DVC53znwyguU/toOvBE0S5v0dm2ehaBUSoWcjCcNnKTAoGAavYp" +
            "uEbFRkVyEutee71C4tdbdv2+VQYbd4BjkFXLFpqpVEW9u03D59Ap83FJP2ArdWWY" +
            "dbPXzJ8kXw6L0m+lx4Q2XyjBmfCTkkKHqXXv7Y3s4/EZFdn2gpItJeY3uSIq9a9Y" +
            "IaW6/MkkQz7LodJNtHDtZRkhgaQxHn9KzyJdPoECgYEAs75ZaTk4JO9PsEwwokHq" +
            "LX59yk+g0NHf24vdDAQLXiEN1R6GezfFfW5RTZ1Z9EVtPqIlJ7ONLpXg0lEYol3P" +
            "iN/5yyqMuAaKpu6/2ESRPIG1xbn1yttyRusGqkD7G8cTi6FixjGLIeoQ9/0FaOPV" +
            "Jw7iHTfpu+iPQlmvb660GBs=";

    /**
     * Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             2a:89:24:1a:52:e7:ba:b9:19:1f:ce:f6:1b:d1:cd:84:58:12:db:01
     *         Signature Algorithm: ecdsa-with-SHA256
     *         Issuer: O=interop runner Root Certificate Authority
     *         Validity
     *             Not Before: Mar 25 21:09:01 2024 GMT
     *             Not After : Apr  4 21:09:01 2024 GMT
     *         Subject: O=interop runner leaf
     *         Subject Public Key Info:
     *             Public Key Algorithm: id-ecPublicKey
     *                 Public-Key: (256 bit)
     *                 pub:
     *                     04:0b:11:69:0a:bc:a4:17:ba:a2:8d:44:17:07:4b:
     *                     be:e1:68:b2:44:61:e9:2b:56:6d:5e:2e:b8:33:28:
     *                     bb:96:b3:47:95:08:a8:a6:50:ba:6e:bc:88:34:70:
     *                     c1:9e:24:da:7b:1a:87:a4:4e:25:f1:c4:a3:68:ca:
     *                     b9:12:4d:a5:a9
     *                 ASN1 OID: prime256v1
     *                 NIST CURVE: P-256
     *         X509v3 extensions:
     *             X509v3 Subject Alternative Name:
     *                 DNS:server, DNS:server4, DNS:server6, DNS:server46
     *             X509v3 Subject Key Identifier:
     *                 1E:E6:98:9F:4E:8F:F5:8F:64:2C:AB:7E:E7:94:42:62:44:2D:1A:47
     *             X509v3 Authority Key Identifier:
     *                 34:37:3B:B2:C9:89:29:0F:E3:01:47:C8:A6:B2:AA:5C:05:E3:90:4C
     *     Signature Algorithm: ecdsa-with-SHA256
     *     Signature Value:
     *         30:44:02:20:2f:46:f6:d1:49:cc:ed:72:b4:32:ab:95:88:aa:
     *         36:40:ab:b9:fa:32:9f:ec:3f:98:98:e9:a2:4b:96:55:9e:73:
     *         02:20:25:20:9c:c3:c5:da:ab:4f:a4:71:f0:a3:b6:09:b8:5a:
     *         c9:54:4f:9e:30:35:f6:50:4c:1d:3f:ff:c7:88:e6:09
     */
    public static String encodedInteropLeafEcdsaCertificate =
            "MIIBxDCCAWugAwIBAgIUKokkGlLnurkZH872G9HNhFgS2wEwCgYIKoZIzj0EAwIw" +
            "NDEyMDAGA1UECgwpaW50ZXJvcCBydW5uZXIgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRo" +
            "b3JpdHkwHhcNMjQwMzI1MjEwOTAxWhcNMjQwNDA0MjEwOTAxWjAeMRwwGgYDVQQK" +
            "DBNpbnRlcm9wIHJ1bm5lciBsZWFmMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE" +
            "CxFpCrykF7qijUQXB0u+4WiyRGHpK1ZtXi64Myi7lrNHlQioplC6bryINHDBniTa" +
            "exqHpE4l8cSjaMq5Ek2lqaNxMG8wLQYDVR0RBCYwJIIGc2VydmVyggdzZXJ2ZXI0" +
            "ggdzZXJ2ZXI2gghzZXJ2ZXI0NjAdBgNVHQ4EFgQUHuaYn06P9Y9kLKt+55RCYkQt" +
            "GkcwHwYDVR0jBBgwFoAUNDc7ssmJKQ/jAUfIprKqXAXjkEwwCgYIKoZIzj0EAwID" +
            "RwAwRAIgL0b20UnM7XK0MquViKo2QKu5+jKf7D+YmOmiS5ZVnnMCICUgnMPF2qtP" +
            "pHHwo7YJuFrJVE+eMDX2UEwdP//HiOYJ";

    public static String encodedInteropLeafEcdsaCertificatePrivateKey =
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWGL/rBmYfWYUP0PO" +
            "KiwoGV/5qKt7Issz+s9dvlljACKhRANCAAQLEWkKvKQXuqKNRBcHS77haLJEYekr" +
            "Vm1eLrgzKLuWs0eVCKimULpuvIg0cMGeJNp7GoekTiXxxKNoyrkSTaWp";

    /**
     * Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             15:3a:7c:78:fb:ae:0d:2e:7c:a1:31:71:44:e5:65:83:5f:74:24:90
     *         Signature Algorithm: sha256WithRSAEncryption
     *         Issuer: CN=SampleCA1
     *         Validity
     *             Not Before: Aug  6 18:28:10 2024 GMT
     *             Not After : Sep  5 18:28:10 2024 GMT
     *         Subject: CN=sample.com
     *         Subject Public Key Info:
     *             Public Key Algorithm: rsaEncryption
     *                 Public-Key: (3072 bit)
     *         X509v3 extensions:
     *             X509v3 Subject Key Identifier:
     *                 6D:3E:E9:10:E9:F1:1E:FC:3D:47:82:6F:48:5D:85:48:2B:CE:52:42
     *             X509v3 Authority Key Identifier:
     *                 DC:58:35:36:68:E3:64:8B:33:78:C2:6C:52:B0:9E:64:CF:BA:E1:65
     *     Signature Algorithm: sha256WithRSAEncryption
     */
    public static String encodedSampleRsa3072Certificate = 
            "MIIDeTCCAmGgAwIBAgIUFTp8ePuuDS58oTFxROVlg190JJAwDQYJKoZIhvcNAQEL" +
            "BQAwFDESMBAGA1UEAwwJU2FtcGxlQ0ExMB4XDTI0MDgwNjE4MjgxMFoXDTI0MDkw" +
            "NTE4MjgxMFowFTETMBEGA1UEAwwKc2FtcGxlLmNvbTCCAaIwDQYJKoZIhvcNAQEB" +
            "BQADggGPADCCAYoCggGBAJnM7tha9MWJI5MBuquaRaBAlc4NlLJ7ZotqDB2Lntfe" +
            "li85qB0vHBJU3clVWfY/RoPCexN2YM7v6sRC09QPq0138rI43b5h+7qoopeazr0T" +
            "57RvGqXYcxu95/ymkNXAq3CvguRsBNlnN2mOOqjl+uHWDL8jzMdYPmcZWQVWo2BW" +
            "V8O30/CLGpzB7+yHxbn2OQ/m66WI7WzQifB4Ca/dAYHRqwOr54IoPQpb/kWMCawU" +
            "Tr9vZfdKcbSYqsrT36NNO6s6sxdVIO/QbctIbYIyRrYj9ivtGqyJbtuPkAVa1dUi" +
            "ssRV+tLrW04oyU9WfvS1OyyfbjS20phyNpr/v1g6b+gXbN7oMBcAePLmo/jaBIet" +
            "cnRkTERx8IdQskBJ/pf5TIY9C90nJ5IUuqkIp8olUOJfWXRH/NuaA/7IHVpqGRH+" +
            "bq2fLdBXFnqk5YnUgQI3JCPItmv9+K6lwQCU6u0f5NXnZkNW1kK0gXFYJyrfEMVh" +
            "L0FASE/FRIHiF0ixz73r6QIDAQABo0IwQDAdBgNVHQ4EFgQUbT7pEOnxHvw9R4Jv" +
            "SF2FSCvOUkIwHwYDVR0jBBgwFoAU3Fg1NmjjZIszeMJsUrCeZM+64WUwDQYJKoZI" +
            "hvcNAQELBQADggEBADEZQQh6lF9q19XzHRwtsbo7XHbric74bHrHeyQ+Wa6g7pyC" +
            "oA/jpfKvp70RHWk89h4Jy+fdM5vhSH2n+JCnrIbKqcggOQnrBcS2VcJr5fe33d8B" +
            "fodLxbNVSWDJwY5PEIYJYo870ffFjU9k4jW9pqiuXWAUnBGqRoKEOmlZPe++V1ep" +
            "0XTaEWXqjuskOoWhdVGhH+KImDlIHPueWRTbPUkRAGCP5aI7OBMUb/i649EtrRQZ" +
            "zD1okEL+QdJUMMICvuK3NZxTasZ5JJ6+1WqD5rgN2RwU0gmQSxy587R3fCrTy5ZS" +
            "DTwcomtvEEcleR1iL2yjFFHPn06C+4kjSkdpD9Y=";
    
    /**
     * Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             5f:aa:5e:23:77:9e:2d:6e:7c:26:38:13:c7:f8:99:ba:42:d5:4a:95
     *         Signature Algorithm: sha384WithRSAEncryption
     *         Issuer: CN=sample
     *         Validity
     *             Not Before: Mar 29 11:47:34 2024 GMT
     *             Not After : Apr 29 11:47:34 2024 GMT
     *         Subject: CN=sample
     *         Subject Public Key Info:
     *             Public Key Algorithm: rsaEncryption
     *                 Public-Key: (1024 bit)
     *         X509v3 extensions:
     *             X509v3 Subject Key Identifier:
     *                 53:26:A7:F8:5D:FE:C7:3C:25:5A:AC:2D:99:F9:18:06:8C:C1:15:36
     *             X509v3 Authority Key Identifier:
     *                 53:26:A7:F8:5D:FE:C7:3C:25:5A:AC:2D:99:F9:18:06:8C:C1:15:36
     *             X509v3 Basic Constraints: critical
     *                 CA:TRUE
     *     Signature Algorithm: sha384WithRSAEncryption
     */
    public static String encodedSampleRsa384Certificate =
            "MIIB/jCCAWegAwIBAgIUX6peI3eeLW58JjgTx/iZukLVSpUwDQYJKoZIhvcNAQEM" +
            "BQAwETEPMA0GA1UEAwwGc2FtcGxlMB4XDTI0MDMyOTExNDczNFoXDTI0MDQyOTEx" +
            "NDczNFowETEPMA0GA1UEAwwGc2FtcGxlMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB" +
            "iQKBgQC06MN2/mBFgeoj5pl3K6zxy2J/UjtPnJ76eax6V2QTxbdcn5BTbwHntO2g" +
            "VSgmfee9l37by/pWGfJHtaEer4fmvijoglor4L9/9k61nR6yBOA/FcDnX+71csWA" +
            "qX1hb2ewU/HWWfva+ynfPNvy66POm84Fj9tpqckgZ0GK24QNbwIDAQABo1MwUTAd" +
            "BgNVHQ4EFgQUUyan+F3+xzwlWqwtmfkYBozBFTYwHwYDVR0jBBgwFoAUUyan+F3+" +
            "xzwlWqwtmfkYBozBFTYwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQwFAAOB" +
            "gQAQ4Q5CFMN6KTTWG4tJ+j9ZuLgfFwoJQ6uDM7b0ZUbDBoXUac9rt8T6MuqewJAB" +
            "UsU3w2QCSd24pdM1HNlvnd1FJLTRLJV3ptlSL8a1wrKKPRiHLPHmCsjKKhA57bpC" +
            "J3+fplNjwbBB5ZGGHtjPdvbwe14O/CXVgUcb6SGWTdlhSw==";

    /**
     * Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             38:39:ef:8d:dd:7f:5a:4e:4b:2a:da:27:d4:d9:11:6e:dc:22:87:8d
     *         Signature Algorithm: sha256WithRSAEncryption
     *         Issuer: CN=SampleCA1
     *         Validity
     *             Not Before: Aug  6 18:59:45 2024 GMT
     *             Not After : Sep  5 18:59:45 2024 GMT
     *         Subject: CN=sample.com
     *         Subject Public Key Info:
     *             Public Key Algorithm: rsaEncryption
     *                 Public-Key: (4096 bit)
     *         X509v3 extensions:
     *             X509v3 Subject Key Identifier:
     *                 39:88:02:88:14:29:8B:6F:0E:5A:18:7C:76:C6:AC:55:2C:DF:4B:1C
     *             X509v3 Authority Key Identifier:
     *                 DC:58:35:36:68:E3:64:8B:33:78:C2:6C:52:B0:9E:64:CF:BA:E1:65
     *     Signature Algorithm: sha256WithRSAEncryption
     */
    public static String encodedSampleRsa4096Certificate =
            "MIID+TCCAuGgAwIBAgIUODnvjd1/Wk5LKton1NkRbtwih40wDQYJKoZIhvcNAQEL" +
            "BQAwFDESMBAGA1UEAwwJU2FtcGxlQ0ExMB4XDTI0MDgwNjE4NTk0NVoXDTI0MDkw" +
            "NTE4NTk0NVowFTETMBEGA1UEAwwKc2FtcGxlLmNvbTCCAiIwDQYJKoZIhvcNAQEB" +
            "BQADggIPADCCAgoCggIBALGGIlWa+ibpa2DUpFiO6ivCuZaXWTa65bfEf090UdQg" +
            "wE9yf9J3v1U+4IKv5hG6/uB5XU/W6VUjZzrGufV1x6FKN4iJ/iJSEGZ9Y2WuckSk" +
            "p2kkwuIYvBRly/5LJAGuZq4Z/T6BaM19fWNsQgp5WnF1+QxwhKBhZmEYWjQ4Hdpi" +
            "T1LgmqqQVvfBg4GPihzXMvjkZAAKEKfH4Vf4gl5lriFtjSOjil8nSUe/CBk+WipP" +
            "2ywgFH/mqMGB1nN+o3RAYVhujehx7Hjn6q3plx/qczl6wkDZXN1L67wsbXjqZSHx" +
            "NDK1kJENAIQVTU6v1uu1FKEKYBfcj+iQysTnbpZ5cF6Hb1M5lN207iR7nsXnqAh0" +
            "M+3v4KhvLSXj6TIoe4qNn3PAfhJRHwZ72H3HtnZmSy+poWqgvRd9RiwmIWxF89Kb" +
            "UWrzoqi1yj7vj7zrBmk7KcjQH9XSkoZVsJaMU/IL5j6sb1r785wYnnxyrs+n4Jfv" +
            "nA7n5nzrA2NWyq9/Sf8qPZnh2KeTfKFMcz7k9YOmZFhBtb+pg/6nf9q4qPH1Ng8V" +
            "W0Je0+mfrn0FKIXIrG8DtthNIfDuEkD7rrW7jQQBDQIiy9Dxlqi3wHVsLrmeuFHx" +
            "LtBAw4/f/KxvRT++MykEVEHs9sd178XTK/nbVJ06WdE6Ekcqyeb7jWMz5szI5CMp" +
            "AgMBAAGjQjBAMB0GA1UdDgQWBBQ5iAKIFCmLbw5aGHx2xqxVLN9LHDAfBgNVHSME" +
            "GDAWgBTcWDU2aONkizN4wmxSsJ5kz7rhZTANBgkqhkiG9w0BAQsFAAOCAQEAOAY4" +
            "rFjG+sxYlKUx9a+Mzyjlox+mYf9S4NqzvGcvFb2U4ogLHC0Lx0uwdmdgsCZzQ0Jv" +
            "vtrHXm0susJhyRy1VtqxDUzBXZ0D530jOxOgqDs+c6iyk4NC0zXQkb8edW0XzjON" +
            "De5A2k3b9U+nkA0q68gRYeO+xcr/XG+YUTUq1ubd656TZ2JJL1vSRr5A9qUtUeWn" +
            "OcHBm9gEMTWVBC/BiN/xAMBlsSDBkF/SDjrH2glwq78S2tK8zWbVHT1DV8NXA0Pb" +
            "AM14VNux0NuzWix4rGxrJEBq9XmSo8mdWmTLEzUUbb3rSERNhVoL319rvOVJCoOQ" +
            "sOEXoWDw+iZHBn7zOA==";

    /**
     * Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             76:2f:4c:0c:2a:93:c1:46:da:18:39:56:a9:e2:fc:99:66:26:bc:de
     *         Signature Algorithm: sha512WithRSAEncryption
     *         Issuer: CN=sample
     *         Validity
     *             Not Before: Mar 29 11:52:29 2024 GMT
     *             Not After : Apr 29 11:52:29 2024 GMT
     *         Subject: CN=sample
     *         Subject Public Key Info:
     *             Public Key Algorithm: rsaEncryption
     *                 Public-Key: (1024 bit)
     *         X509v3 extensions:
     *             X509v3 Subject Key Identifier:
     *                 70:79:DA:72:CC:4C:AE:DB:9A:40:44:EF:FA:1B:C7:CE:79:F7:93:7E
     *             X509v3 Authority Key Identifier:
     *                 70:79:DA:72:CC:4C:AE:DB:9A:40:44:EF:FA:1B:C7:CE:79:F7:93:7E
     *             X509v3 Basic Constraints: critical
     *                 CA:TRUE
     *     Signature Algorithm: sha512WithRSAEncryption
     */
    public static String encodedSampleRsa512Certificate =
            "MIIB/jCCAWegAwIBAgIUdi9MDCqTwUbaGDlWqeL8mWYmvN4wDQYJKoZIhvcNAQEN" +
            "BQAwETEPMA0GA1UEAwwGc2FtcGxlMB4XDTI0MDMyOTExNTIyOVoXDTI0MDQyOTEx" +
            "NTIyOVowETEPMA0GA1UEAwwGc2FtcGxlMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB" +
            "iQKBgQC89z8okzRhf16jjOPrVDwIDrp0lDX4aTLFSMcbjxQLrExmivwKlWS9qal3" +
            "h7k59GxLfR3++H0bpMAd1gk1LthHTm+pc8fzMNckTb6ctjSAX7fg6DG4TjKc8GbR" +
            "eWKOYMBFCifruSTQGVJwmaRUblevMFshlAt9HeMRkcQa8T2V/wIDAQABo1MwUTAd" +
            "BgNVHQ4EFgQUcHnacsxMrtuaQETv+hvHznn3k34wHwYDVR0jBBgwFoAUcHnacsxM" +
            "rtuaQETv+hvHznn3k34wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOB" +
            "gQACFnoZfPPgKXWSQFRzWvVq3ZSU9pYWzk94SiQsBSx2PFrIcoP+2YYHmykp39Ky" +
            "EyG1Zfex1GL9sMlezZa9mOzSIVzUTThsZ/DZDGy+loe9Eu5Tmc/+chOKqPPLoeJJ" +
            "aQkRfqDYTe2rzcvnXCSfqlq8ME0sdJGjLM7hCn9cee6s8A==";

    /**
     * Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             4e:99:ae:67:9f:46:37:ec:db:20:d2:74:f1:7f:78:4e:95:15:4c:a9
     *         Signature Algorithm: ecdsa-with-SHA384
     *         Issuer: CN=sample
     *         Validity
     *             Not Before: Mar 29 12:19:52 2024 GMT
     *             Not After : Apr 29 12:19:52 2024 GMT
     *         Subject: CN=sample
     *         Subject Public Key Info:
     *             Public Key Algorithm: id-ecPublicKey
     *                 Public-Key: (384 bit)
     *                 pub:
     *                     04:32:30:4c:d3:8c:19:94:4b:10:55:76:9d:f8:9d:
     *                     11:70:a5:12:ac:ce:33:42:cf:ab:fc:58:41:88:fe:
     *                     84:da:e7:35:3d:32:ec:67:49:45:cc:44:c0:60:75:
     *                     ea:08:90:97:d5:6c:da:e6:80:35:ca:d9:d6:2b:ca:
     *                     38:dd:c1:80:03:dc:c0:d5:81:ae:d7:06:8e:69:e9:
     *                     40:31:21:a2:1b:25:31:5c:21:a2:48:66:96:16:53:
     *                     2e:01:1a:ea:7c:f1:ae
     *                 ASN1 OID: secp384r1
     *                 NIST CURVE: P-384
     *         X509v3 extensions:
     *             X509v3 Subject Key Identifier:
     *                 7A:34:BB:BC:70:C6:70:1E:FE:F7:95:1B:A3:69:8F:5C:02:75:DD:C5
     *             X509v3 Authority Key Identifier:
     *                 7A:34:BB:BC:70:C6:70:1E:FE:F7:95:1B:A3:69:8F:5C:02:75:DD:C5
     *             X509v3 Basic Constraints: critical
     *                 CA:TRUE
     *     Signature Algorithm: ecdsa-with-SHA384
     */
    public static String encodedSampleEcdsa384Certificate =
            "MIIBszCCATqgAwIBAgIUTpmuZ59GN+zbINJ08X94TpUVTKkwCgYIKoZIzj0EAwMw" +
            "ETEPMA0GA1UEAwwGc2FtcGxlMB4XDTI0MDMyOTEyMTk1MloXDTI0MDQyOTEyMTk1" +
            "MlowETEPMA0GA1UEAwwGc2FtcGxlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEMjBM" +
            "04wZlEsQVXad+J0RcKUSrM4zQs+r/FhBiP6E2uc1PTLsZ0lFzETAYHXqCJCX1Wza" +
            "5oA1ytnWK8o43cGAA9zA1YGu1waOaelAMSGiGyUxXCGiSGaWFlMuARrqfPGuo1Mw" +
            "UTAdBgNVHQ4EFgQUejS7vHDGcB7+95Ubo2mPXAJ13cUwHwYDVR0jBBgwFoAUejS7" +
            "vHDGcB7+95Ubo2mPXAJ13cUwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNn" +
            "ADBkAjBUSPSWNhpCNtXaV468TginbXN+iTGrBhRqwtKcofgAphDllWA1Mqvhto95" +
            "OhwVQaECMAPRFXsCo6K+kmY1EGRp9z1OehGuIwp/D3U3KOshNuTJeBMLy1smEEaK" +
            "Y13bk20TAA==";

    /**
     * Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             1f:62:43:ab:6c:82:96:4c:c5:2d:e2:e8:51:47:df:e6:ee:e2:65:42
     *         Signature Algorithm: ecdsa-with-SHA512
     *         Issuer: CN=sample
     *         Validity
     *             Not Before: Mar 29 12:31:09 2024 GMT
     *             Not After : Apr 29 12:31:09 2024 GMT
     *         Subject: CN=sample
     *         Subject Public Key Info:
     *             Public Key Algorithm: id-ecPublicKey
     *                 Public-Key: (521 bit)
     *                 pub:
     *                     04:01:56:dd:a5:64:fa:92:4a:1f:9e:c1:84:65:58:
     *                     d2:0b:88:e2:d1:69:ff:7e:07:10:68:18:81:2d:4a:
     *                     c0:81:d5:5c:b9:d2:ac:c2:98:24:3b:38:cd:3b:46:
     *                     44:8f:46:80:dc:a5:ae:f7:de:d0:e3:0e:8e:98:d5:
     *                     d0:2d:de:b1:c0:44:4a:00:3f:bb:28:f2:91:d3:43:
     *                     70:00:13:ce:26:b0:e9:35:8c:94:16:ba:64:6f:96:
     *                     be:b1:1e:b6:c8:8e:76:8a:33:ef:dd:dc:d0:e9:6c:
     *                     4d:0c:66:74:5c:9a:71:7e:5e:c2:ac:8f:a8:00:9d:
     *                     a6:bc:6b:5f:29:34:91:99:3f:4c:72:0a:90
     *                 ASN1 OID: secp521r1
     *                 NIST CURVE: P-521
     *         X509v3 extensions:
     *             X509v3 Subject Key Identifier:
     *                 39:5B:B6:1B:E1:47:9A:5C:AB:34:5E:07:E7:F3:E7:27:08:2E:B5:58
     *             X509v3 Authority Key Identifier:
     *                 39:5B:B6:1B:E1:47:9A:5C:AB:34:5E:07:E7:F3:E7:27:08:2E:B5:58
     *             X509v3 Basic Constraints: critical
     *                 CA:TRUE
     *     Signature Algorithm: ecdsa-with-SHA512
     */
    public static String encodedSampleEcdsa512Certificate =
            "MIIB/jCCAWCgAwIBAgIUH2JDq2yClkzFLeLoUUff5u7iZUIwCgYIKoZIzj0EAwQw" +
            "ETEPMA0GA1UEAwwGc2FtcGxlMB4XDTI0MDMyOTEyMzEwOVoXDTI0MDQyOTEyMzEw" +
            "OVowETEPMA0GA1UEAwwGc2FtcGxlMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB" +
            "Vt2lZPqSSh+ewYRlWNILiOLRaf9+BxBoGIEtSsCB1Vy50qzCmCQ7OM07RkSPRoDc" +
            "pa733tDjDo6Y1dAt3rHAREoAP7so8pHTQ3AAE84msOk1jJQWumRvlr6xHrbIjnaK" +
            "M+/d3NDpbE0MZnRcmnF+XsKsj6gAnaa8a18pNJGZP0xyCpCjUzBRMB0GA1UdDgQW" +
            "BBQ5W7Yb4UeaXKs0Xgfn8+cnCC61WDAfBgNVHSMEGDAWgBQ5W7Yb4UeaXKs0Xgfn" +
            "8+cnCC61WDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMEA4GLADCBhwJBUQ1B" +
            "EbxncyYJ7jkibWqYUiXz6cPlv5jyHCBo/uZr6C+vRlQ11vI5M4r8Td615WTy/VDd" +
            "OPvv7KOmWML2tredmmYCQgDvChUUZZ+45ls3AK9U/3xcRuF81DvGkVsWsl/gaQdd" +
            "a6BeM5nxMW7b9GAo+gYTIM22TGLBxu41SCbvsiGoDnwCmw==";

    /**
     * A sample CA certificate.
     * Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             28:3b:e0:3d:cf:62:59:9a:e0:24:44:38:bc:f0:9e:82:4e:11:10:d8
     *         Signature Algorithm: sha256WithRSAEncryption
     *         Issuer: CN=SampleCA1
     *         Validity
     *             Not Before: May 19 16:02:37 2024 GMT
     *             Not After : May 17 16:02:37 2034 GMT
     *         Subject: CN=SampleCA1
     *         Subject Public Key Info:
     *             Public Key Algorithm: rsaEncryption
     *                 Public-Key: (2048 bit)
     *         X509v3 extensions:
     *             X509v3 Subject Key Identifier:
     *                 DC:58:35:36:68:E3:64:8B:33:78:C2:6C:52:B0:9E:64:CF:BA:E1:65
     *             X509v3 Authority Key Identifier:
     *                 DC:58:35:36:68:E3:64:8B:33:78:C2:6C:52:B0:9E:64:CF:BA:E1:65
     *             X509v3 Basic Constraints: critical
     *                 CA:TRUE
     *
     * generated with: openssl req -x509 -new -nodes -key ca1.key -out ca1-cert.pem -subj='/CN=SampleCA1' -days 3650
     */
    public static String encodedSampleCA1 =
            "MIIDCTCCAfGgAwIBAgIUKDvgPc9iWZrgJEQ4vPCegk4RENgwDQYJKoZIhvcNAQEL" +
            "BQAwFDESMBAGA1UEAwwJU2FtcGxlQ0ExMB4XDTI0MDUxOTE2MDIzN1oXDTM0MDUx" +
            "NzE2MDIzN1owFDESMBAGA1UEAwwJU2FtcGxlQ0ExMIIBIjANBgkqhkiG9w0BAQEF" +
            "AAOCAQ8AMIIBCgKCAQEA2Bv1R0ft2tCB+4gkRg/yfZ43bHC0P8TwyBNakmFVc3Hb" +
            "AyHRWWuLtERXnVI4tZsay61VGjk9pFa+R5wpHb0ZtRgYV/1N7YFdIZzyQN0v3X8O" +
            "y2UTqYfYCAlHTZ8+UEN7MqS0mVwan/GfhKj5m1yx+zxQCLrCvahHoytY9jR3C6gi" +
            "0F/hdN9iICLgc51fOU5WMedyEjAWEh04H5Sg/D7N+w7DBB0okSaP38YoeQaLezmv" +
            "ChtAVo+XMQQPEXaaYgdG+s/yKdT5JWUQgqB+qtc48wnEC2oOUuxu/JZKd+BU3HOG" +
            "xLD7B2Bdm0YGSKt9yCp2L9PVJmlB4PrlAm8GWOgDIwIDAQABo1MwUTAdBgNVHQ4E" +
            "FgQU3Fg1NmjjZIszeMJsUrCeZM+64WUwHwYDVR0jBBgwFoAU3Fg1NmjjZIszeMJs" +
            "UrCeZM+64WUwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAV5wR" +
            "oNb3luMOqWBRSK+NlWG6enDC39hKQJD1NJuq5P7s+k6Ex94rmmpQly6TQA3Zw/wa" +
            "BJ2aHHcyfTyiNE3aKlR+ecFCD6eAQQ6QI1MCQ59DTYfIvcfwSMIs31GPXuGKhp6Z" +
            "rgDyYwAPWs6OhLsV/2dIdAkB11M2mp76klv4MSMEDCofO1WIFfwejz/y2Ya0JGpO" +
            "0fmt4lRZ6GNPrRZ+Pe5OMd0ASwNk8zDFf2ztUkkRxSKLdbgUEqVQrwgVY/oaJMX3" +
            "RqaCUPQLgZW85Z3zii4LFLE0JBlh4vUX5pk4jhz33u/Y1eNr/cHbYItjroqXEZFg" +
            "g9nVG+2RizmTUiuTBQ==";

    /**
     * A sample certificate signed by CA1.
     *
     * Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             16:aa:58:49:ec:ff:cc:2e:df:cd:9c:70:17:e0:33:fd:eb:f3:ee:9e
     *         Signature Algorithm: sha256WithRSAEncryption
     *         Issuer: CN=SampleCA1
     *         Validity
     *             Not Before: Apr  1 10:29:27 2024 GMT
     *             Not After : May  1 10:29:27 2024 GMT
     *         Subject: C=AU, ST=Some-State, O=Internet Widgits Pty Ltd, CN=sample1.com
     *         Subject Public Key Info:
     *             Public Key Algorithm: rsaEncryption
     *                 Public-Key: (2048 bit)
     *
     * generated with:
     * - openssl req -key key1.pem -new -out sample-cert1.csr
     * - openssl x509 -req -in sample-cert1.csr -CAkey ca1.key -CA ca1-cert.pem -out sample-cert1.pem -days 3650
     */
    public static String encodedCA1SignedCert =
            "MIIDPzCCAiegAwIBAgIUa3xhD+Sj0oJk0hUwM0ONl/lmfrgwDQYJKoZIhvcNAQEL" +
            "BQAwFDESMBAGA1UEAwwJU2FtcGxlQ0ExMB4XDTI0MDUxOTE2MTI1OVoXDTM0MDUx" +
            "NzE2MTI1OVowWzELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAf" +
            "BgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEUMBIGA1UEAwwLc2FtcGxl" +
            "MS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDV6+2D/c/fHYr2" +
            "NpngyimPiRQf7epqXmlI8x1Ka5NgYG2/BCgEGoMa/0pZ1LRNjMFbh+IbpshMf2oX" +
            "M0gbyC8kY+wprq9o+rCgA7DEKg/wVHTeut85584lc/Z/nG9rSkNDhnxc6/qTp+UC" +
            "IsqT27t9Qs2YQsgRyC3zdXVzGRAK2CiCVdbT5AJudQtnMOqexDyukfuu4tidjETQ" +
            "1oZ3xFtxDVKKK+zKYj7O69hEAmpN473R0HgKWyNJKr4zneFIWeqeZCyZYZZYfNiF" +
            "Kb445mVCF9D2jBObBqWV1n6FMmFds8E0pAo+SWj2JvHpJx2HG1otPT5lnLkj7XnP" +
            "UQFWsS4fAgMBAAGjQjBAMB0GA1UdDgQWBBTr7NM+Z/AdzOK2r+I5cAOlkCYhADAf" +
            "BgNVHSMEGDAWgBTcWDU2aONkizN4wmxSsJ5kz7rhZTANBgkqhkiG9w0BAQsFAAOC" +
            "AQEAfVEu2Il5KzinGpR68pIrvETLzj2kbbio6awq7nRC6hJq+Zbn/rf7s240SE43" +
            "D9cCk34uABMZgyiXhHfdcrjHgGiD7182dhkQc8VKYghh0jJfNurRZcGrSxKvtZJe" +
            "rNQ6r439qaMUicNPSZHsv8bLSmD6UqNYAJFbxaEJgC5cpspURS4fv5dF7k4xa7UP" +
            "pwAyHzdtzhb7Dg5zcdaaMRo8ZqrfKUpNEFLoHjel+urWkJb3pHagY/3/cmjYLT3f" +
            "Y6s4x//CPFlW7vqOBNi0Pes+Lek++9xuMXOK3wFLK9WI1z9FlEduWRlRC4tWwoF9" +
            "izof7pIaG7MHK4133PCU3a9nww==";

    /**
     * The private key for encodedCA1SignedCert
     */
    public static String encodedCA1SignedCertPrivateKey =
            "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDV6+2D/c/fHYr2" +
            "NpngyimPiRQf7epqXmlI8x1Ka5NgYG2/BCgEGoMa/0pZ1LRNjMFbh+IbpshMf2oX" +
            "M0gbyC8kY+wprq9o+rCgA7DEKg/wVHTeut85584lc/Z/nG9rSkNDhnxc6/qTp+UC" +
            "IsqT27t9Qs2YQsgRyC3zdXVzGRAK2CiCVdbT5AJudQtnMOqexDyukfuu4tidjETQ" +
            "1oZ3xFtxDVKKK+zKYj7O69hEAmpN473R0HgKWyNJKr4zneFIWeqeZCyZYZZYfNiF" +
            "Kb445mVCF9D2jBObBqWV1n6FMmFds8E0pAo+SWj2JvHpJx2HG1otPT5lnLkj7XnP" +
            "UQFWsS4fAgMBAAECggEAGHBGhyC04blfSbd9JtgRnWs8mFU2xYYZoxLbEshtYsJB" +
            "Z2QTKjzZI3lsxgxtuLpO0KUaaKxKD6sytInQQBRDhnW/4hcpxOV2ziD9zbs8bOlJ" +
            "HLTekZ/wxgiUbYmylOA8BPfVN0xiKQIyQGc3G2Mr7Sh3kmB2uMlUro6Jp2eClKpd" +
            "oxAru494oUOC7OZIKdhH+frnCoAX0nGdboJe6unmPqC3icblF9duhMNiNqQw8eY1" +
            "YyM2k00H9NvQ8aC6RZCE4ZgUwLW5+Y2a4SovoJA3KnuGJNsvsCYPNMnNu5wXqsDq" +
            "QNS9VRxvqYOuQ5RGj8wgBLY3/2Ac5K/cFI1E5Ut6qQKBgQDvFcOyTTVFbNfcfTGz" +
            "YRt5E6z75vKz0kq+jd+olVa6DihUnqMlJJpR5y7pFh0euP4i7RuPI8g3HfrknZta" +
            "8Dy5KCDcNTITpRF1YAkeR9K4JcsMn/JU2L/fBNvlh9JoqHQptgofy+SxIrDlHYqj" +
            "PLeRc/dmFcx9qLC8vUllNbwECwKBgQDlDmk4mzmwxkA1BT3JPSpTccPU48QpOHyC" +
            "zcsEaOn7xgUpU+jU0hxeawG7COKtMssHESLzjRr3UbrQv8UvyvCgALXHbEXZXpod" +
            "IF9XUz/LPpsL7LHd1Bl1VHUpB274/J9mMo6gbMszd9jxS62jN3UxxNsjyelSDiva" +
            "+ZHwFiPWvQKBgCuftwNznwK553EtzsHCODcRZgDYlPRGrKi0Tlj+VsLADo/SGkaO" +
            "tTG4kxConkuayZQp21t01fVonPzV3SDssMfAEK7dbfOzrMnT6hYCWOqMys3U6Wyd" +
            "1/SjeFQbQkMiaX+q3ZILrAC+KbTEfSVn0L7TgBK6a4OKIiVuDFRRR6sdAoGAOSMr" +
            "JC+0aGBLy+4Ox5A2arJKQ2S9nfq1NHvZVLRHCcMProt73Pq8kODogZtp0AKHmq+v" +
            "pElinKcKjuAHdDCPbZo/vgtIMTzj/LgCkGn3098+Fe9pPwiVgSscPqvYBswdhwS9" +
            "h08cMS6IM0jJe5lt5ohQkdDgHtPiJLF0sgsTzZECgYAhTTXipAwccofSPBL9ONJh" +
            "ewyraboD1JycDaMgRD3GLgukul8Ts2cAHrqIPnnDX2rAQ2T6zzaaurPkMgywfse6" +
            "56Gu4qNei5fXIgGMtYzzs3C9k4Gs7wmt+WQpb9u3lH4mq7QMIM8iK1PD9PSSTM39" +
            "nIndmfJGIy3q5iBH0ST9sQ==";

    /**
     * A sample CA certificate.
     *
     * Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             2b:62:46:46:f1:8f:94:75:eb:93:34:be:ca:57:67:1b:cb:de:6d:12
     *         Signature Algorithm: sha256WithRSAEncryption
     *         Issuer: CN=SampleCA2
     *         Validity
     *             Not Before: May 19 16:17:43 2024 GMT
     *             Not After : May 17 16:17:43 2034 GMT
     *         Subject: CN=SampleCA2
     *         Subject Public Key Info:
     *             Public Key Algorithm: rsaEncryption
     *                 Public-Key: (2048 bit)
     *         X509v3 extensions:
     *             X509v3 Subject Key Identifier:
     *                 0B:B7:35:CC:7B:F7:09:3A:0C:AF:61:A3:F5:21:07:65:F1:84:77:E5
     *             X509v3 Authority Key Identifier:
     *                 0B:B7:35:CC:7B:F7:09:3A:0C:AF:61:A3:F5:21:07:65:F1:84:77:E5
     *             X509v3 Basic Constraints: critical
     *                 CA:TRUE
     *
     * generated with: openssl req -x509 -new -nodes -key ca2.key -out ca2-cert.pem -subj='/CN=SampleCA2' -days 3650
     */
    public static String encodedSampleCA2 = "" +
            "MIIDCTCCAfGgAwIBAgIUK2JGRvGPlHXrkzS+yldnG8vebRIwDQYJKoZIhvcNAQEL" +
            "BQAwFDESMBAGA1UEAwwJU2FtcGxlQ0EyMB4XDTI0MDUxOTE2MTc0M1oXDTM0MDUx" +
            "NzE2MTc0M1owFDESMBAGA1UEAwwJU2FtcGxlQ0EyMIIBIjANBgkqhkiG9w0BAQEF" +
            "AAOCAQ8AMIIBCgKCAQEAokHS7Aa24KbLn5iYabPaLatvlNrhhJBy51EM6gT3HS+C" +
            "qBmytCtwqBHh4pXlt4iCUyYZJIBRn9m77Rcvc7MyrdQY0U6QM9CWmjQeuc783Weu" +
            "k29Enb4BnNINa3cJxR1cAdJYvkTiSHckA0RBlpD3XQgyehTk3QSFi51pubuWV1GH" +
            "42oJU3kes+LdB81JzDd1EaAblGgiDhAxfWzUxs9mXwr6UyTcEGQP2aGDFOteEm4r" +
            "L9bTivra+rJov1FVZn7wM/aMqmpkWEiH4bgEakrvjjRkM/QNbo9eb8nvugjztvPR" +
            "gvtYTbvMVofjXGnJVGcjU5XY7Ha6EV2ybBTFx165VQIDAQABo1MwUTAdBgNVHQ4E" +
            "FgQUC7c1zHv3CToMr2Gj9SEHZfGEd+UwHwYDVR0jBBgwFoAUC7c1zHv3CToMr2Gj" +
            "9SEHZfGEd+UwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEANLGA" +
            "A6PquB64prHH9JLYChkdlWB+zoiV9FIVd6T5srW9jLlXlSHKiBRNPyOq1PTipal1" +
            "bfDTz2lioMTsatfQSzTGbwMnjO4UDaft7YNX+KhogQkGwWBY7VmtD9Ge45CaDN0X" +
            "g0A2K4cGfOu20OOYGRUCQdZJ7eXdhqZ2Iz/PD76RkSq7kRAUGDqRKZhKb0Rll6oS" +
            "3m7WdJtuHZG3wt1RlbdcHDlW+6eWgZyADcsX6HPgCkglVxYJ918QFsq8Jm1et2tt" +
            "WxZzCSWOISBB5aJhii9HM0RdJ94AhEsvoiQ0isIfJCTSmkaK0TU2mA41CqjZWlCA" +
            "OTFLQ5FXjb/0i0TpVA==";

    /**
     * A sample certificate signed by CA2.
     *
     * Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             6c:fc:fc:16:e6:f6:40:aa:80:8b:8e:f1:35:4d:76:13:db:65:0d:1e
     *         Signature Algorithm: sha256WithRSAEncryption
     *         Issuer: CN=SampleCA2
     *         Validity
     *             Not Before: May 19 16:22:57 2024 GMT
     *             Not After : May 17 16:22:57 2034 GMT
     *         Subject: C=AU, ST=Some-State, O=Internet Widgits Pty Ltd, CN=sample2.com
     *         Subject Public Key Info:
     *             Public Key Algorithm: rsaEncryption
     *                 Public-Key: (2048 bit)
     *         X509v3 extensions:
     *             X509v3 Subject Key Identifier:
     *                 0C:E0:25:56:E3:11:15:F6:CA:F9:89:05:A2:92:C6:53:CC:05:16:EC
     *             X509v3 Authority Key Identifier:
     *                 0B:B7:35:CC:7B:F7:09:3A:0C:AF:61:A3:F5:21:07:65:F1:84:77:E5
     *
     * generated with:
     * - openssl req -key key2.pem -new -out sample-cert2.csr
     * - openssl x509 -req -in sample-cert2.csr -CAkey ca2.key -CA ca2-cert.pem -out sample-cert2.pem -days 3650
     */
    public static String encodedCA2SignedCert = "" +
            "MIIDPzCCAiegAwIBAgIUbPz8Fub2QKqAi47xNU12E9tlDR4wDQYJKoZIhvcNAQEL" +
            "BQAwFDESMBAGA1UEAwwJU2FtcGxlQ0EyMB4XDTI0MDUxOTE2MjI1N1oXDTM0MDUx" +
            "NzE2MjI1N1owWzELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAf" +
            "BgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEUMBIGA1UEAwwLc2FtcGxl" +
            "Mi5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDV2NwXKKPNIZco" +
            "c1LQs1EEJAVu7SJMREwtRKvBzhwibMiMPz1b3+KwGvFKG75nEsEuvOWX8M0poygX" +
            "l0zrsiM7gRPIn0wi2iY+b85W0Cu4SlFGUBedfnFZNBu+pL01McOK3jK2WsAD1Qmc" +
            "JiFT12h7fXXbmNhJ5I0iUXuFunz+pA29KcV4diikJmKj7nkRLWKhVFDAfU2wt1p5" +
            "uCtJs+q4bS77/o9ZmZFtbYrrP3uJ4Btcbo4+/Ei41uzn5wqo5NhjjDKikZg0t7fo" +
            "6hxxchv6cxjXL7Jc1AV4pY46CwDWltOnwS1FYnptXidk2PcUNZsJsF8pWoHkpxYK" +
            "o/C3cXDNAgMBAAGjQjBAMB0GA1UdDgQWBBQM4CVW4xEV9sr5iQWiksZTzAUW7DAf" +
            "BgNVHSMEGDAWgBQLtzXMe/cJOgyvYaP1IQdl8YR35TANBgkqhkiG9w0BAQsFAAOC" +
            "AQEAewq85Ex/0vOrdi9PBT6pQD6X4ULbRuzL0bpScEnn1s4v9Zuab29YFDRaJink" +
            "HR59YdHOv5FDSBDvGu6fVha4u5ojN3TBTxT5bRks/RkXmOnzCm7VEyplHTUALdbW" +
            "xrpN1UhglwEx+JvJviRoLNeWuuUqvmTDgDjzBmigGjoxA8qas2YAECly0kWrs/LQ" +
            "JfAGOVTPkIihLS//BhhL6H5eIf9abx1X4KxOLNJtaii06336iB/5FzzIPW7ucr3Z" +
            "UeLw2i4YaUp2pdVr2Zg0bSdzMRgOoj6bkqwkxGL8OB0VVWOYEsUMx/awflKs7Abn" +
            "YkWuopOVBVPabWKFgACQGu1mTQ==";

    /**
     * The private key for encodedCA2SignedCert
     */
    public static String encodedCA2SignedCertPrivateKey =
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDV2NwXKKPNIZco" +
            "c1LQs1EEJAVu7SJMREwtRKvBzhwibMiMPz1b3+KwGvFKG75nEsEuvOWX8M0poygX" +
            "l0zrsiM7gRPIn0wi2iY+b85W0Cu4SlFGUBedfnFZNBu+pL01McOK3jK2WsAD1Qmc" +
            "JiFT12h7fXXbmNhJ5I0iUXuFunz+pA29KcV4diikJmKj7nkRLWKhVFDAfU2wt1p5" +
            "uCtJs+q4bS77/o9ZmZFtbYrrP3uJ4Btcbo4+/Ei41uzn5wqo5NhjjDKikZg0t7fo" +
            "6hxxchv6cxjXL7Jc1AV4pY46CwDWltOnwS1FYnptXidk2PcUNZsJsF8pWoHkpxYK" +
            "o/C3cXDNAgMBAAECggEABzFo78omaQKO/NA/kh+3TdTErlnsHCrKRtXcks4zFzut" +
            "AD3/+0c72bFs+dGWlTgl3C5Zk64zccnYPKOSdbVzfBon90jXwllaTXcsdoeV3OL6" +
            "ZQt8dof3rz4yi7ZWBe7IqshgEM8FzpXbzE83skQDMpos/MgL8xUCDqGKg9xFaDmT" +
            "2wtlPTikL2xLh28lhUlANuGHoHULl76H01Sq+Uf0N13HNZ7s1m+R4O8KJ88e4bal" +
            "IdBKim0/GrloNu2BKjVItSUlbdZQCTzCnmAvNdxdBMBl+8rSsx8q4JMLEXaampbq" +
            "0WQF3g0Sp8atKLB40I/19h04F5tm/Yw9gF7VLi+T6QKBgQDzZ3Qm0QhQzucIIPjz" +
            "N3/EVusGqBLzSVyFgNMhL7ZBc/9X58GsCUyZszGnCi3+p3jd3Fg3j89iRvoEYbmr" +
            "MwJO5thnX2szXbB1J5unZQCyKAs60P15CkbtPx1nJQluCe2koNBCBmewJW3+n4Sj" +
            "5Tfk931O2nMT6sHrnn4/dAGBNQKBgQDg6dfsNzPsl/FKV8Hq8yCsr2qdRn1VrS7t" +
            "LqT/MPHYYQvTry3TKJ03TvpBoibN/eTh4NBC1uDF5Ja+WWcgm/PeoPE83m/QEiwP" +
            "02W2R5fgUdln6q0mI2htMcoUMNQUyPsf4AHpaIq9LQF16B/S5OMdVNjaz8VTBTNn" +
            "JVYpTS58OQKBgDtdUAbnlI+g5tgkspMfRhos2MWW2IhdrCMjeFrvuBPeprhZ3fKH" +
            "khcqjUGgSfeCAQibZSin+nyNswy+iPooRrfXtZAAxbSRdSgdsOjyyWiqO5LsxeVv" +
            "jDzw18sATXx5D2zHjAOObFuZxWoEneUbUraVZgqFXOvOpd1Bmqj/Mh7BAoGBALVV" +
            "9H//9f5Qdvtwi+mJQpPYDoZledHlAou6as9RP/wsKmPuvmycNz2LkJvwR4cXqD0x" +
            "i9gH9Uu4RI2N+WbCNjoN2tIvqUjCDgJod34idOIoO7fb7uRr8drwJLRoteVYMZh+" +
            "fCwa3Jkvuxi8IURgxHg2m2y3zalk7Q/Be5lrIAqJAoGBAK46wwAQfeQFQLWjc+s1" +
            "NL8bxL+U7474eR4OJNt2FU/XX+IDiEkbx+hql8T71frBRAGYVhoNm0UUw42g/cK2" +
            "yFU3H82qRLxBJ7kNaxXITmeDoNecP8zs6J6sUSakviVQJ8qsb40VlffcOphMBGQv" +
            "QZdM6NwTd1EMUctmNDE4txHW";

    /**
     * EC certificate signed by RSA.
     * generated with:
     * - openssl req -key key-ec-384.pem -new -out ec-384.csr -subj /CN=ec-sample.com
     * - openssl x509 -req -in  ec-384.csr -CAkey ca1.key -CA ca1-cert.pem -out ec-384-rsa-signed-cert.pem -days 3650
     *
     * Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             4c:4f:3d:f9:7e:1b:b5:e7:70:be:69:42:c0:61:99:64:6d:ad:c6:8a
     *         Signature Algorithm: sha256WithRSAEncryption
     *         Issuer: CN=SampleCA1
     *         Validity
     *             Not Before: Aug  3 08:45:46 2024 GMT
     *             Not After : Aug  1 08:45:46 2034 GMT
     *         Subject: CN=ec-sample.com
     *         Subject Public Key Info:
     *             Public Key Algorithm: id-ecPublicKey
     *                 Public-Key: (384 bit)
     *                 pub:
     *                     04:32:30:4c:d3:8c:19:94:4b:10:55:76:9d:f8:9d:
     *                     11:70:a5:12:ac:ce:33:42:cf:ab:fc:58:41:88:fe:
     *                     84:da:e7:35:3d:32:ec:67:49:45:cc:44:c0:60:75:
     *                     ea:08:90:97:d5:6c:da:e6:80:35:ca:d9:d6:2b:ca:
     *                     38:dd:c1:80:03:dc:c0:d5:81:ae:d7:06:8e:69:e9:
     *                     40:31:21:a2:1b:25:31:5c:21:a2:48:66:96:16:53:
     *                     2e:01:1a:ea:7c:f1:ae
     *                 ASN1 OID: secp384r1
     *                 NIST CURVE: P-384
     *         X509v3 extensions:
     *             X509v3 Subject Key Identifier:
     *                 7A:34:BB:BC:70:C6:70:1E:FE:F7:95:1B:A3:69:8F:5C:02:75:DD:C5
     *             X509v3 Authority Key Identifier:
     *                 DC:58:35:36:68:E3:64:8B:33:78:C2:6C:52:B0:9E:64:CF:BA:E1:65
     *     Signature Algorithm: sha256WithRSAEncryption
     */
    public static String encodedCA1SignedEcCert =
            "MIICTjCCATagAwIBAgIUTE89+X4btedwvmlCwGGZZG2txoowDQYJKoZIhvcNAQEL" +
            "BQAwFDESMBAGA1UEAwwJU2FtcGxlQ0ExMB4XDTI0MDgwMzA4NDU0NloXDTM0MDgw" +
            "MTA4NDU0NlowGDEWMBQGA1UEAwwNZWMtc2FtcGxlLmNvbTB2MBAGByqGSM49AgEG" +
            "BSuBBAAiA2IABDIwTNOMGZRLEFV2nfidEXClEqzOM0LPq/xYQYj+hNrnNT0y7GdJ" +
            "RcxEwGB16giQl9Vs2uaANcrZ1ivKON3BgAPcwNWBrtcGjmnpQDEhohslMVwhokhm" +
            "lhZTLgEa6nzxrqNCMEAwHQYDVR0OBBYEFHo0u7xwxnAe/veVG6Npj1wCdd3FMB8G" +
            "A1UdIwQYMBaAFNxYNTZo42SLM3jCbFKwnmTPuuFlMA0GCSqGSIb3DQEBCwUAA4IB" +
            "AQAvfub87xiJudEQQ1IWTZf59Mmz5S4Dgath+/thHc71imF11J2TGcZb17mcpmPk" +
            "QYrGfRTqPwqdcYrTZJqkaRE41q2yf8m60GGk/N+MTPoFaLS4VNTZxl/dsTTOCNwi" +
            "gfjOdcRUxQQ2pTABKu5zbt/wcef2xPM5Of31i4GsSv6hZzRuuON39J5LjpJJB/jI" +
            "G1E16Aic36n4RRcab7cGMAYWCuJdgjYmqcyiCzJcb31yX5fPLkzQPhJzaZzVdnMZ" +
            "sJEeWqeYVnnNBvbDYHzGFpBBAYwi717o/F9SakFSP6y/fZvuJCZFokwZDqi1ZE24" +
            "8aEob86obktI8G+A53myGGSM";
}
