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

    /**
     * A sample CA certificate.
     *
     * Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             0c:d8:d1:3a:e0:dc:f4:45:3f:8c:b5:91:cd:23:c9:16:4b:69:03:07
     *         Signature Algorithm: sha256WithRSAEncryption
     *         Issuer: CN=SampleCA1
     *         Validity
     *             Not Before: Apr  1 10:19:41 2024 GMT
     *             Not After : May  1 10:19:41 2024 GMT
     *         Subject: CN=SampleCA1
     *         Subject Public Key Info:
     *             Public Key Algorithm: rsaEncryption
     *                 Public-Key: (2048 bit)
     */
    public static String encodedSampleCA1 =
            "MIIDCTCCAfGgAwIBAgIUDNjROuDc9EU/jLWRzSPJFktpAwcwDQYJKoZIhvcNAQEL" +
            "BQAwFDESMBAGA1UEAwwJU2FtcGxlQ0ExMB4XDTI0MDQwMTEwMTk0MVoXDTI0MDUw" +
            "MTEwMTk0MVowFDESMBAGA1UEAwwJU2FtcGxlQ0ExMIIBIjANBgkqhkiG9w0BAQEF" +
            "AAOCAQ8AMIIBCgKCAQEA2Bv1R0ft2tCB+4gkRg/yfZ43bHC0P8TwyBNakmFVc3Hb" +
            "AyHRWWuLtERXnVI4tZsay61VGjk9pFa+R5wpHb0ZtRgYV/1N7YFdIZzyQN0v3X8O" +
            "y2UTqYfYCAlHTZ8+UEN7MqS0mVwan/GfhKj5m1yx+zxQCLrCvahHoytY9jR3C6gi" +
            "0F/hdN9iICLgc51fOU5WMedyEjAWEh04H5Sg/D7N+w7DBB0okSaP38YoeQaLezmv" +
            "ChtAVo+XMQQPEXaaYgdG+s/yKdT5JWUQgqB+qtc48wnEC2oOUuxu/JZKd+BU3HOG" +
            "xLD7B2Bdm0YGSKt9yCp2L9PVJmlB4PrlAm8GWOgDIwIDAQABo1MwUTAdBgNVHQ4E" +
            "FgQU3Fg1NmjjZIszeMJsUrCeZM+64WUwHwYDVR0jBBgwFoAU3Fg1NmjjZIszeMJs" +
            "UrCeZM+64WUwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAENJY" +
            "gwTMq682WW+DXinok6Lxvyx0QrFtyQ5Noa3d8vmQ9bFXGCzUXuwDYmcZSqZlG56A" +
            "/rbDpBA7Fadx/CIpJOsMFL/awoG/itK7W290VKvF25J2gEdy3HSgFJDe0oAoZ7/8" +
            "0hCYHFPZ8pdvGLVm0zOt9AK2wy2m+W0ugSMT1MRgqgsipUSWSHewBImK865xYaQS" +
            "lajtrjePUQ2kNql5gtLp+URCNbQVLxnPRDmObSMYKPoWK6mzjEDvWgRTMSj+EsUT" +
            "nXoQ7A5EA78HAQLuYVb3TNZWSH7YVHNjrJ5ErI84xZPxWhv9RYZeKtKj61ea5xYQ" +
            "tt5eTeRexWhlHHax7Q==";

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
     */
    public static String encodedCA1SignedCert =
            "MIIDPzCCAiegAwIBAgIUFqpYSez/zC7fzZxwF+Az/evz7p4wDQYJKoZIhvcNAQEL" +
            "BQAwFDESMBAGA1UEAwwJU2FtcGxlQ0ExMB4XDTI0MDQwMTEwMjkyN1oXDTI0MDUw" +
            "MTEwMjkyN1owWzELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAf" +
            "BgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEUMBIGA1UEAwwLc2FtcGxl" +
            "MS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDV6+2D/c/fHYr2" +
            "NpngyimPiRQf7epqXmlI8x1Ka5NgYG2/BCgEGoMa/0pZ1LRNjMFbh+IbpshMf2oX" +
            "M0gbyC8kY+wprq9o+rCgA7DEKg/wVHTeut85584lc/Z/nG9rSkNDhnxc6/qTp+UC" +
            "IsqT27t9Qs2YQsgRyC3zdXVzGRAK2CiCVdbT5AJudQtnMOqexDyukfuu4tidjETQ" +
            "1oZ3xFtxDVKKK+zKYj7O69hEAmpN473R0HgKWyNJKr4zneFIWeqeZCyZYZZYfNiF" +
            "Kb445mVCF9D2jBObBqWV1n6FMmFds8E0pAo+SWj2JvHpJx2HG1otPT5lnLkj7XnP" +
            "UQFWsS4fAgMBAAGjQjBAMB0GA1UdDgQWBBTr7NM+Z/AdzOK2r+I5cAOlkCYhADAf" +
            "BgNVHSMEGDAWgBTcWDU2aONkizN4wmxSsJ5kz7rhZTANBgkqhkiG9w0BAQsFAAOC" +
            "AQEAG1PJzzzO8vchhlnW7nPzF0whaK3ARpiW3M3TzbMWjxaBVtFID3HgJ8hQuFl2" +
            "vSv3Yv07gGh7ZbpWd8Iq3oYwH94IeiBfSVGO2iD3GR+fzjk2bqtBlxNmn4tbk3Ya" +
            "LW4940mHczYiAz2QVbBSGUZfRgGdyxJKazT8PdUpjEfTpUH5lu7OkhCxlGnrg6gv" +
            "p/yYeO6WrbfRhet/9tMVtBRm4oRePDXdHEMoTl5uFAASoED0XRxF6hEC8eLoWGRC" +
            "eIAhuxnU0PFH/PRtplkU98A52rvz7Ab1TdYea+fAsc/9nK7OwwZfsXkd9GlYfmPJ" +
            "86giEJwN+yGN1WnMWBwSR3fCiQ==";

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
     * Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             52:af:1a:9e:6e:f0:9b:6d:5e:4a:21:7e:e6:c3:0c:fd:0e:eb:9b:ec
     *         Signature Algorithm: sha256WithRSAEncryption
     *         Issuer: CN=SampleCA2
     *         Validity
     *             Not Before: Apr  1 10:41:06 2024 GMT
     *             Not After : May  1 10:41:06 2024 GMT
     *         Subject: CN=SampleCA2
     *         Subject Public Key Info:
     *             Public Key Algorithm: rsaEncryption
     *                 Public-Key: (2048 bit)
     */
    public static String encodedSampleCA2 =
            "MIIDCTCCAfGgAwIBAgIUUq8anm7wm21eSiF+5sMM/Q7rm+wwDQYJKoZIhvcNAQEL" +
            "BQAwFDESMBAGA1UEAwwJU2FtcGxlQ0EyMB4XDTI0MDQwMTEwNDEwNloXDTI0MDUw" +
            "MTEwNDEwNlowFDESMBAGA1UEAwwJU2FtcGxlQ0EyMIIBIjANBgkqhkiG9w0BAQEF" +
            "AAOCAQ8AMIIBCgKCAQEAokHS7Aa24KbLn5iYabPaLatvlNrhhJBy51EM6gT3HS+C" +
            "qBmytCtwqBHh4pXlt4iCUyYZJIBRn9m77Rcvc7MyrdQY0U6QM9CWmjQeuc783Weu" +
            "k29Enb4BnNINa3cJxR1cAdJYvkTiSHckA0RBlpD3XQgyehTk3QSFi51pubuWV1GH" +
            "42oJU3kes+LdB81JzDd1EaAblGgiDhAxfWzUxs9mXwr6UyTcEGQP2aGDFOteEm4r" +
            "L9bTivra+rJov1FVZn7wM/aMqmpkWEiH4bgEakrvjjRkM/QNbo9eb8nvugjztvPR" +
            "gvtYTbvMVofjXGnJVGcjU5XY7Ha6EV2ybBTFx165VQIDAQABo1MwUTAdBgNVHQ4E" +
            "FgQUC7c1zHv3CToMr2Gj9SEHZfGEd+UwHwYDVR0jBBgwFoAUC7c1zHv3CToMr2Gj" +
            "9SEHZfGEd+UwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAbx+4" +
            "Oa/rDv9RgqQWzV9nUdBCPGrP5pBe92PliifsFqzIQh5AIeIAdzqGevEVlY8QTl1R" +
            "C1qPlye9A9hCkaMRQ9yULrb/8ej81iRlAGC1d3NraKIWqRdb+xw2/ysYUT0eSd7A" +
            "L3TABKt6egkWhVVuICW6bTrb4/1M03+mol5rzUBdHuj0+seIDr7tTLW/t8ffdUd1" +
            "1PJnDGN3MdMaM/YS5sU7djRT1higUF8Mr0NoyAYMU0XiKgIGlS1EY6VJXLVXPuys" +
            "0PK6UFB9KfB93GPPOXXWksAppxQF/u5i5QFaijCpk9tx3XVGkwSJqDvbXHS4p0eU" +
            "1bnpnUVOlgX3BJZGmg==";

    /**
     * A sample certificate signed by CA1.
     *
     * Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             6e:e9:58:30:7f:f0:df:e9:bf:2d:79:5c:46:78:c6:3d:4d:ec:dc:6c
     *         Signature Algorithm: sha256WithRSAEncryption
     *         Issuer: CN=SampleCA2
     *         Validity
     *             Not Before: Apr  1 10:43:06 2024 GMT
     *             Not After : May  1 10:43:06 2024 GMT
     *         Subject: C=AU, ST=Some-State, O=Internet Widgits Pty Ltd, CN=sample2.com
     *         Subject Public Key Info:
     *             Public Key Algorithm: rsaEncryption
     *                 Public-Key: (2048 bit)
     */
    public static String encodedCA2SignedCert =
            "MIIDPzCCAiegAwIBAgIUbulYMH/w3+m/LXlcRnjGPU3s3GwwDQYJKoZIhvcNAQEL" +
            "BQAwFDESMBAGA1UEAwwJU2FtcGxlQ0EyMB4XDTI0MDQwMTEwNDMwNloXDTI0MDUw" +
            "MTEwNDMwNlowWzELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAf" +
            "BgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEUMBIGA1UEAwwLc2FtcGxl" +
            "Mi5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDV2NwXKKPNIZco" +
            "c1LQs1EEJAVu7SJMREwtRKvBzhwibMiMPz1b3+KwGvFKG75nEsEuvOWX8M0poygX" +
            "l0zrsiM7gRPIn0wi2iY+b85W0Cu4SlFGUBedfnFZNBu+pL01McOK3jK2WsAD1Qmc" +
            "JiFT12h7fXXbmNhJ5I0iUXuFunz+pA29KcV4diikJmKj7nkRLWKhVFDAfU2wt1p5" +
            "uCtJs+q4bS77/o9ZmZFtbYrrP3uJ4Btcbo4+/Ei41uzn5wqo5NhjjDKikZg0t7fo" +
            "6hxxchv6cxjXL7Jc1AV4pY46CwDWltOnwS1FYnptXidk2PcUNZsJsF8pWoHkpxYK" +
            "o/C3cXDNAgMBAAGjQjBAMB0GA1UdDgQWBBQM4CVW4xEV9sr5iQWiksZTzAUW7DAf" +
            "BgNVHSMEGDAWgBQLtzXMe/cJOgyvYaP1IQdl8YR35TANBgkqhkiG9w0BAQsFAAOC" +
            "AQEASp4IWFV34rRQWk3rJLcCalN7rjpYMfC8l7xxixIsdwHKT9tkid7bwwyF/ICz" +
            "Cty37hTROQBNHBHkhdcGO5AfAMKU3U+hUf2eX5hguQp2UB1bhdEQaIz//mYIlov1" +
            "8Gvo9JC5yXJ4Nf44SJAxSXJo32lL6e2XGfw8XxCqrI2cnRaDTdIZcm18HZauCPTc" +
            "L5Y6QcrhBHeVXoiBqR1frcZqZdkp8QC5I54MiR3m44M6P9hYlZV3tQQNtDQW8QO2" +
            "Q9tAB9Ymv6Q74ltjhzNZaxcCy53d2nZDVCTd1IoClQkPtOO96gKWNvYuAeWuiKHF" +
            "gA25N4VfZKf2DMiRXMXAiTzlqA==";

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
}
