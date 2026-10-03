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
package tech.kwik.agent15.engine;

import tech.kwik.agent15.alert.InternalErrorAlert;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * The signature algorithm that implements one TLS signature scheme.
 */
public interface SignatureAlgorithm {

    /**
     * Signs the given content with the given private key.
     * @param content  the content to sign
     * @param certificatePrivateKey  the private key associated with the certificate
     * @return  the signature
     * @throws InternalErrorAlert  when the private key cannot be used with this signature scheme
     */
    byte[] sign(byte[] content, PrivateKey certificatePrivateKey) throws InternalErrorAlert;

    /**
     * Verifies a signature over the given content with the given public key.
     * Note that this does not check that the public key matches this signature scheme; use
     * {@link #keyMatchesScheme} for that.
     * @param content  the content that was signed
     * @param signature  the signature to verify
     * @param certificatePublicKey  the public key of the certificate that (supposedly) created the signature
     * @return  whether the signature is valid
     */
    boolean verify(byte[] content, byte[] signature, PublicKey certificatePublicKey);

    /**
     * Checks whether the given public key can be used with this signature scheme; for EC keys this includes checking
     * that the key's curve is the one the scheme requires.
     * @param certificatePublicKey
     * @return
     */
    boolean keyMatchesScheme(PublicKey certificatePublicKey);
}

