/*
 * Copyright © 2026 Peter Doornbosch
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
package tech.kwik.agent15.engine.impl;

import tech.kwik.agent15.alert.InternalErrorAlert;
import tech.kwik.agent15.engine.SignatureAlgorithm;
import tech.kwik.agent15.log.Logger;

import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public abstract class Ecdsa implements SignatureAlgorithm {

    @Override
    public byte[] sign(byte[] content, PrivateKey certificatePrivateKey) throws InternalErrorAlert {
        try {
            Signature algorithm = instantiateSignatureAlgorithm();
            algorithm.initSign(certificatePrivateKey);
            algorithm.update(content);
            return algorithm.sign();
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing " + signatureAlgorithmName() + " support");
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

    // Note that SHA...withECDSA excepts any EC public key, so additional check on the key's curve is necessary
    @Override
    public boolean verify(byte[] content, byte[] signature, PublicKey certificatePublicKey) {
        boolean verified = false;
        try {
            Signature algorithm = instantiateSignatureAlgorithm();
            algorithm.initVerify(certificatePublicKey);
            algorithm.update(content);
            verified = algorithm.verify(signature);
        }
        catch (InvalidKeyException e) {
            Logger.debug("Certificate verify: invalid key.");
        }
        catch (SignatureException e) {
            Logger.debug("Certificate verify: invalid signature.");
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return verified;
    }

    protected boolean keyMatchesScheme(String curveName, PublicKey publicKey) {
        if (!(publicKey instanceof ECPublicKey)) {
            return false;
        }
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec(curveName));
            ECParameterSpec expectedSpec = params.getParameterSpec(ECParameterSpec.class);
            ECParameterSpec actualSpec = ((ECPublicKey) publicKey).getParams();
            return expectedSpec.getCurve().equals(actualSpec.getCurve());
        }
        catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
            // NoSuchAlgorithmException from getInstance("EC"),
            // InvalidParameterSpecException from init(ECGenParameterSpec) and getParameterSpec(ECParameterSpec)
            throw new RuntimeException(e);
        }
    }

    protected Signature instantiateSignatureAlgorithm() throws NoSuchAlgorithmException {
        return Signature.getInstance(signatureAlgorithmName());
    }

    /**
     * Returns the JCA name of the signature algorithm this scheme uses, e.g. {@code SHA256withECDSA}.
     */
    protected abstract String signatureAlgorithmName();
}
