package net.luminis.tls.handshake;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

public class EngineTest {

    protected ECKey[] generateKeys() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));

            KeyPair keyPair = keyPairGenerator.genKeyPair();
            return new ECKey[] { (ECPrivateKey) keyPair.getPrivate(), (ECPublicKey) keyPair.getPublic() };
        } catch (NoSuchAlgorithmException e) {
            // Invalid runtime
            throw new RuntimeException("missing key pair generator algorithm EC");
        } catch (InvalidAlgorithmParameterException e) {
            // Impossible, would be programming error
            throw new RuntimeException();
        }
    }

    protected String encodedCertificate = "MIICxzCCAa+gAwIBAgIEJ4Jd0zANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDEwlr" +
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

    protected String encodedPrivateKey =
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


}

