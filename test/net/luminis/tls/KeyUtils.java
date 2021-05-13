package net.luminis.tls;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

public class KeyUtils {

    static public ECKey[] generateKeys() {
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

    static public ECPublicKey generatePublicKey() {
        return (ECPublicKey) generateKeys()[1];
    }
}
