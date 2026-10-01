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

import tech.kwik.agent15.alert.InternalErrorAlert;
import tech.kwik.agent15.engine.SignatureAlgorithm;

import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

/**
 * ML-DSA (<a href="https://csrc.nist.gov/pubs/fips/204/final">FIPS 204</a>), the post-quantum signature scheme
 * underlying the mldsa44/mldsa65/mldsa87 TLS signature schemes.
 *
 * <p>Unlike RSA-PSS/ECDSA, a single JCA algorithm name ("ML-DSA") handles signing and verifying for all three
 * parameter sets; the parameter set is carried by the key itself. So the only thing that differs per subclass is
 * {@link #keyMatchesScheme}, which needs a way to tell an ML-DSA-44 key from an ML-DSA-65 or ML-DSA-87 one: the JDK's
 * {@code getAlgorithm()} reports "ML-DSA" for all three, but each parameter set's public key has a distinct, fixed
 * X.509-encoded length, which is what subclasses pass in here.
 */
public abstract class MLDSASignatureAlgorithm implements SignatureAlgorithm {

    private static final String JCA_ALGORITHM = "ML-DSA";

    private final int publicKeyEncodedLength;

    protected MLDSASignatureAlgorithm(int publicKeyEncodedLength) {
        this.publicKeyEncodedLength = publicKeyEncodedLength;
    }

    @Override
    public byte[] sign(byte[] content, PrivateKey certificatePrivateKey) throws InternalErrorAlert {
        try {
            Signature signature = Signature.getInstance(JCA_ALGORITHM);
            signature.initSign(certificatePrivateKey);
            signature.update(content);
            return signature.sign();
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing " + JCA_ALGORITHM + " support");
        }
        catch (InvalidKeyException e) {
            throw new InternalErrorAlert("invalid private key");
        }
        catch (SignatureException e) {
            // sign() throws SignatureException: if this signature object is not initialized properly or if this
            //                                   signature algorithm is unable to process the input data provided.
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean verify(byte[] content, byte[] signature, PublicKey certificatePublicKey) {
        boolean verified = false;
        try {
            Signature algorithm = Signature.getInstance(JCA_ALGORITHM);
            algorithm.initVerify(certificatePublicKey);
            algorithm.update(content);
            verified = algorithm.verify(signature);
        }
        catch (InvalidKeyException e) {
            // Not a matching key: verified stays false.
        }
        catch (SignatureException e) {
            // Not a valid signature: verified stays false.
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return verified;
    }

    @Override
    public boolean keyMatchesScheme(PublicKey publicKey) {
        if (!JCA_ALGORITHM.equals(publicKey.getAlgorithm())) {
            return false;
        }
        byte[] encoded = publicKey.getEncoded();
        return encoded != null && encoded.length == publicKeyEncodedLength;
    }

    /**
     * Generates a throwaway key pair for the given ML-DSA parameter set (e.g. "ML-DSA-65") and returns its public
     * key's X.509-encoded length, so subclasses don't have to hardcode a JDK/ASN.1-derived number.
     */
    protected static int computePublicKeyEncodedLength(String algorithm) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
            return keyPairGenerator.generateKeyPair().getPublic().getEncoded().length;
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing " + algorithm + " support");
        }
    }
}
