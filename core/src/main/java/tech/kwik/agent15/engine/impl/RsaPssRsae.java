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
import tech.kwik.agent15.env.AlgorithmMapping;
import tech.kwik.agent15.env.PlatformMapping;
import tech.kwik.agent15.log.Logger;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;

public abstract class RsaPssRsae implements SignatureAlgorithm {

    protected final AlgorithmMapping algorithmMapping;

    protected RsaPssRsae() {
        algorithmMapping = PlatformMapping.algorithmMapping();
    }

    @Override
    public byte[] sign(byte[] content, PrivateKey certificatePrivateKey) throws InternalErrorAlert {
        try {
            Signature algorithm = instantiateSignatureAlgorithm();
            algorithm.initSign(certificatePrivateKey);
            algorithm.update(content);
            return algorithm.sign();
        }
        catch (NoSuchAlgorithmException e) {
            noRsaSsaPssSupport();
            // Unreachable code, but the compiler doesn't know that
            return null;
        }
        catch (InvalidAlgorithmParameterException e) {
            // Fairly impossible (because the parameters is hard coded)
            throw new RuntimeException(e);
        }
        catch (SignatureException e) {
            // sign() throws SignatureException: if this signature object is not initialized properly or if this
            //                                   signature algorithm is unable to process the input data provided.
            throw new RuntimeException(e);
        }
        catch (InvalidKeyException e) {
            throw new InternalErrorAlert("invalid private key");
        }
    }

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
            noRsaSsaPssSupport();
        }
        catch (InvalidAlgorithmParameterException e) {
            // Fairly impossible (because the parameters is hard coded)
            throw new RuntimeException(e);
        }
        return verified;
    }

    @Override
    public boolean keyMatchesScheme(PublicKey publicKey) {
        return publicKey instanceof RSAPublicKey;
    }

    private static void noRsaSsaPssSupport() {
        boolean runningOnAndroid = System.getProperty("java.vendor") != null && System.getProperty("java.vendor").contains("Android");
        String msg = "Missing RSASSA-PSS support";
        if (runningOnAndroid) {
            msg += ". Did you set PlatformMapping.usePlatformMapping(PlatformMapping.Platform.Android)?";
        }
        throw new RuntimeException(msg);
    }

    protected abstract Signature instantiateSignatureAlgorithm() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException;
}
