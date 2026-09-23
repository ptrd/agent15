/*
 * Copyright © 2026 Peter Doornbosch, Chris Burdess
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
package tech.kwik.agent15.pqc.impl;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.junit.jupiter.api.Test;
import tech.kwik.agent15.engine.KeyExchange;

import java.security.SecureRandom;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Cross-checks MLKEMKeyExchange's raw wire-format bytes against Bouncy
 * Castle's independent ML-KEM implementation, in both directions. The
 * round-trip tests elsewhere only prove this code agrees with itself;
 * this proves the raw encapsulation-key/ciphertext bytes it produces and
 * consumes are the standards-conformant FIPS 203 encoding an unrelated
 * implementation also produces and accepts -- not just something that
 * happens to work against a second copy of the same code.
 */
class MLKEMInteropTest {

    @Test
    void mlkem768InteropsWithBouncyCastle() throws Exception {
        assertInteroperates(MLKEM768KeyExchange::new, MLKEMParameters.ml_kem_768,
                MLKEM768KeyExchange.ENCAPSULATION_KEY_LENGTH, MLKEM768KeyExchange.CIPHERTEXT_LENGTH);
    }

    @Test
    void mlkem1024InteropsWithBouncyCastle() throws Exception {
        assertInteroperates(MLKEM1024KeyExchange::new, MLKEMParameters.ml_kem_1024,
                MLKEM1024KeyExchange.ENCAPSULATION_KEY_LENGTH, MLKEM1024KeyExchange.CIPHERTEXT_LENGTH);
    }

    private void assertInteroperates(Supplier<KeyExchange> jdkKeyExchangeFactory, MLKEMParameters bcParameters,
            int encapsulationKeyLength, int ciphertextLength) throws Exception {
        // JDK generates a client key pair; Bouncy Castle parses the raw
        // bytes, encapsulates against them, and the JDK decapsulates.
        KeyExchange jdkClient = jdkKeyExchangeFactory.get();
        jdkClient.generateClientKeyPair();
        byte[] jdkClientShare = jdkClient.getClientKeyShare();
        assertThat(jdkClientShare).hasSize(encapsulationKeyLength);

        MLKEMPublicKeyParameters bcPublicKey = new MLKEMPublicKeyParameters(bcParameters, jdkClientShare);
        assertThat(bcPublicKey.getEncoded()).as("Bouncy Castle's own re-encoding of the parsed key must match the original bytes")
                .isEqualTo(jdkClientShare);

        SecretWithEncapsulation bcEncapsulated = new MLKEMGenerator(new SecureRandom()).generateEncapsulated(bcPublicKey);
        assertThat(bcEncapsulated.getEncapsulation()).hasSize(ciphertextLength);

        byte[] jdkSecret = jdkClient.clientComputeSharedSecret(bcEncapsulated.getEncapsulation());
        assertThat(jdkSecret).isEqualTo(bcEncapsulated.getSecret());

        // And the reverse: Bouncy Castle generates a key pair; the JDK's
        // server role parses its raw public key, encapsulates, and
        // Bouncy Castle decapsulates.
        MLKEMKeyPairGenerator bcKeyPairGenerator = new MLKEMKeyPairGenerator();
        bcKeyPairGenerator.init(new MLKEMKeyGenerationParameters(new SecureRandom(), bcParameters));
        AsymmetricCipherKeyPair bcKeyPair = bcKeyPairGenerator.generateKeyPair();
        MLKEMPublicKeyParameters bcServerPublicKey = (MLKEMPublicKeyParameters) bcKeyPair.getPublic();
        MLKEMPrivateKeyParameters bcServerPrivateKey = (MLKEMPrivateKeyParameters) bcKeyPair.getPrivate();

        KeyExchange jdkServer = jdkKeyExchangeFactory.get();
        byte[] jdkServerSecret = jdkServer.serverProcessClientKeyShare(bcServerPublicKey.getEncoded());
        byte[] jdkServerShare = jdkServer.getServerKeyShare();
        assertThat(jdkServerShare).hasSize(ciphertextLength);

        byte[] bcExtractedSecret = new MLKEMExtractor(bcServerPrivateKey).extractSecret(jdkServerShare);
        assertThat(bcExtractedSecret).isEqualTo(jdkServerSecret);
    }
}
