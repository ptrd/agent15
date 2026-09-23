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

import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.alert.IllegalParameterAlert;
import tech.kwik.agent15.engine.KeyExchange;
import tech.kwik.agent15.util.ByteUtils;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Map;

import static tech.kwik.agent15.TlsConstants.NamedGroup.secp256r1;
import static tech.kwik.agent15.TlsConstants.NamedGroup.secp384r1;
import static tech.kwik.agent15.TlsConstants.NamedGroup.secp521r1;

/**
 * Implementation of the Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) key exchange algorithm.
 */
public class ECKeyExchange implements KeyExchange {

    /**
     * The length of the uncompressed point representation (1 + 2 * coordinate length), see
     * // https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.8.2
     */
    private static final Map<TlsConstants.NamedGroup, Integer> CURVE_KEY_LENGTHS = Map.of(
            secp256r1, 65,
            secp384r1, 97,
            secp521r1, 133
    );

    private TlsConstants.NamedGroup namedGroup;
    private PrivateKey privateKey;
    private ECPublicKey publicKey;

    public ECKeyExchange(TlsConstants.NamedGroup namedGroup) {
        if (namedGroup == secp256r1 || namedGroup == secp384r1 || namedGroup == secp521r1) {
            this.namedGroup = namedGroup;
        }
        else {
            throw new IllegalArgumentException("unsupported group " + namedGroup);
        }
    }

    @Override
    public void generateClientKeyPair() {
        generateKeyPair();
    }

    private void generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(new ECGenParameterSpec(namedGroup.toString()));
            KeyPair keyPair = keyPairGenerator.genKeyPair();
            privateKey = keyPair.getPrivate();
            publicKey = (ECPublicKey) keyPair.getPublic();
        }
        catch (NoSuchAlgorithmException e) {
            // Invalid runtime
            throw new RuntimeException("missing key pair generator algorithm EC");
        }
        catch (InvalidAlgorithmParameterException e) {
            // Impossible, would be programming error
            throw new RuntimeException();
        }
    }

    @Override
    public byte[] clientComputeSharedSecret(byte[] serverKeyShare) throws IllegalParameterAlert {
        ECPublicKey serverPublicKey = parseKeyShare(serverKeyShare);
        return computeSharedSecret(serverPublicKey);
    }

    private byte[] computeSharedSecret(ECPublicKey peerPublicKey) throws IllegalParameterAlert {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(peerPublicKey, true);

            return keyAgreement.generateSecret();
        }
        catch (InvalidKeyException e) {
            // This can be caused by an invalid public key
            throw new IllegalParameterAlert("invalid public key: " + e.getMessage());
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unsupported crypto: " + e);
        }
    }

    ECPublicKey parseKeyShare(byte[] keyExchangeData) throws IllegalParameterAlert {
        int keyLength = CURVE_KEY_LENGTHS.get(namedGroup);
        if (keyExchangeData.length != keyLength) {
            throw new IllegalParameterAlert("Invalid " + namedGroup.name() + " key length: " + keyExchangeData.length);
        }
        ByteBuffer buffer = ByteBuffer.wrap(keyExchangeData);
        int headerByte = buffer.get();
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8.2
        // "For secp256r1, secp384r1, and secp521r1, the contents are the serialized value of the following struct:
        //      struct {
        //          uint8 legacy_form = 4;
        //          opaque X[coordinate_length];
        //          opaque Y[coordinate_length];
        //      } UncompressedPointRepresentation;"
        if (headerByte == 4) {
            byte[] keyData = new byte[keyLength - 1];
            buffer.get(keyData);
            return rawToEncodedECPublicKey(namedGroup, keyData);
        }
        else {
            throw new IllegalParameterAlert("EC keys must be in legacy form");
        }
    }

    @Override
    public byte[] serverProcessClientKeyShare(byte[] keyExchangeData) throws IllegalParameterAlert {
        if (privateKey == null) {
            generateKeyPair();
        }
        return computeSharedSecret(parseKeyShare(keyExchangeData));
    }

    @Override
    public byte[] getClientKeyShare() {
        return serialize(publicKey);
    }

    @Override
    public byte[] getServerKeyShare() {
        return serialize(publicKey);
    }

    byte[] serialize(ECPublicKey key) {
        ByteBuffer buffer = ByteBuffer.allocate(CURVE_KEY_LENGTHS.get(namedGroup));

        // See https://tools.ietf.org/html/rfc8446#section-4.2.8.2, "For secp256r1, secp384r1, and secp521r1, ..."
        buffer.put((byte) 4);
        int coordinateLength = (CURVE_KEY_LENGTHS.get(namedGroup) - 1) / 2;
        byte[] affineX = key.getW().getAffineX().toByteArray();
        writeAffine(buffer, affineX, coordinateLength);
        byte[] affineY = key.getW().getAffineY().toByteArray();
        writeAffine(buffer, affineY, coordinateLength);
        return buffer.array();
    }

    /**
     * Writes an affine coordinate (as returned by BigInteger.toByteArray(), i.e. two's complement) to the buffer, as an
     * unsigned big endian value of exactly <code>coordinateLength</code> bytes.
     */
    private void writeAffine(ByteBuffer buffer, byte[] affine, int coordinateLength) {
        if (affine.length == coordinateLength) {
            buffer.put(affine);
        }
        else if (affine.length < coordinateLength) {
            for (int i = 0; i < coordinateLength - affine.length; i++) {
                buffer.put((byte) 0);
            }
            buffer.put(affine, 0, affine.length);
        }
        else {
            // Larger than the coordinate length: only allowed when the additional leading bytes are zero (which is the
            // case when the most significant bit of the coordinate is set).
            for (int i = 0; i < affine.length - coordinateLength; i++) {
                if (affine[i] != 0) {
                    throw new RuntimeException("W Affine more then " + coordinateLength + " bytes, leading bytes not 0 "
                            + ByteUtils.bytesToHex(affine));
                }
            }
            buffer.put(affine, affine.length - coordinateLength, coordinateLength);
        }
    }

    static ECPublicKey rawToEncodedECPublicKey(TlsConstants.NamedGroup curveName, byte[] rawBytes) {
        try {
            KeyFactory kf = KeyFactory.getInstance("EC");
            byte[] x = Arrays.copyOfRange(rawBytes, 0, rawBytes.length/2);
            byte[] y = Arrays.copyOfRange(rawBytes, rawBytes.length/2, rawBytes.length);
            ECPoint w = new ECPoint(new BigInteger(1,x), new BigInteger(1,y));
            return (ECPublicKey) kf.generatePublic(new ECPublicKeySpec(w, ecParameterSpecForCurve(curveName.name())));
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing support for EC algorithm");
        }
        catch (InvalidKeySpecException e) {
            throw new RuntimeException("Inappropriate parameter specification");
        }
    }

    static ECParameterSpec ecParameterSpecForCurve(String curveName) {
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec(curveName));
            return params.getParameterSpec(ECParameterSpec.class);
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing support for EC algorithm");
        }
        catch (InvalidParameterSpecException e) {
            throw new RuntimeException("Inappropriate parameter specification");
        }
    }

}
