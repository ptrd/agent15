/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024 Peter Doornbosch
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

    public static String encodedSampleEcdsa384Certificate = "" +
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
}
