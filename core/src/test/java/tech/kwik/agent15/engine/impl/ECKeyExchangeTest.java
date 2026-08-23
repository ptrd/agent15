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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.alert.IllegalParameterAlert;
import tech.kwik.agent15.util.ByteUtils;
import tech.kwik.agent15.util.FieldSetter;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ECKeyExchangeTest {

    private static final String CLIENT_KEY_EXCHANGE_DATA =
            "04"
            + "5d58e52e3deee2e8b78ec51e2d0cedb5080c8244bd3f651219cc48f3d3d40439"
            + "9d6748ab3eaaca0e32b927fc5e8107628e636b614cab332d8637c1d61caccdda";

    private static final String SERVER_KEY_EXCHANGE_DATA =
            "04"
            + "ace3b035eba5dd75860925b2c9b206656f2d1590f8c596d96a2a91adb442b378"
            + "240002c8ef8360ba6104033c02eb3ab9ebcce036c735892697dda158f91c786e";

    /**
     * The base point G of curve P-384 (secp384r1), see FIPS 186-4 section D.1.2.4 (and SEC 2 section 3.2.1), in
     * uncompressed point representation. Its X coordinate has its most significant bit set, its Y coordinate does not.
     */
    private static final String SECP384R1_BASE_POINT_X =
            "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38"
            + "5502f25dbf55296c3a545e3872760ab7";
    private static final String SECP384R1_BASE_POINT_Y =
            "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0"
            + "0a60b1ce1d7e819d7a431d7c90ea0e5f";
    private static final String SECP384R1_BASE_POINT = "04" + SECP384R1_BASE_POINT_X + SECP384R1_BASE_POINT_Y;

    /**
     * The P-384 key pair of RFC 6979 appendix A.2.6: private key x and public key U = xG. Both coordinates of U have
     * their most significant bit set, so their (unsigned) big endian representation needs 49 bytes as two's complement.
     */
    private static final String RFC6979_P384_PRIVATE_KEY =
            "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d8"
            + "96d5724e4c70a825f872c9ea60d2edf5";
    private static final String RFC6979_P384_PUBLIC_KEY_X =
            "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64"
            + "def8f0ea9055866064a254515480bc13";
    private static final String RFC6979_P384_PUBLIC_KEY_Y =
            "8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1"
            + "288b231c3ae0d4fe7344fd2533264720";
    private static final String RFC6979_P384_PUBLIC_KEY =
            "04" + RFC6979_P384_PUBLIC_KEY_X + RFC6979_P384_PUBLIC_KEY_Y;

    private ECKeyExchange ecKeyExchange;
    private ECKeyExchange secp384r1KeyExchange;

    @BeforeEach
    void initObjectUnderTest() {
        ecKeyExchange = new ECKeyExchange(TlsConstants.NamedGroup.secp256r1);
        secp384r1KeyExchange = new ECKeyExchange(TlsConstants.NamedGroup.secp384r1);
    }

    @Test
    void parseKeyShareExtractsAffineCoordinates() throws Exception {
        byte[] data = ByteUtils.hexToBytes(CLIENT_KEY_EXCHANGE_DATA);

        // When
        ECPublicKey ecPublicKey = ecKeyExchange.parseKeyShare(data);

        // Then: the X coordinate is the first half and the Y coordinate the second half of the point representation.
        assertThat(ecPublicKey.getW().getAffineX())
                .isEqualTo(new BigInteger("5d58e52e3deee2e8b78ec51e2d0cedb5080c8244bd3f651219cc48f3d3d40439", 16));
        assertThat(ecPublicKey.getW().getAffineY())
                .isEqualTo(new BigInteger("9d6748ab3eaaca0e32b927fc5e8107628e636b614cab332d8637c1d61caccdda", 16));
    }

    @Test
    void parsedKeyUsesSecp256r1DomainParameters() throws Exception {
        byte[] data = ByteUtils.hexToBytes(CLIENT_KEY_EXCHANGE_DATA);

        // When
        ECPublicKey ecPublicKey = ecKeyExchange.parseKeyShare(data);

        // Then
        assertThat(ecPublicKey.getParams().getCurve())
                .isEqualTo(ECKeyExchange.ecParameterSpecForCurve("secp256r1").getCurve());
        assertThat(ecPublicKey.getParams().getCurve().getField().getFieldSize()).isEqualTo(256);
    }

    @Test
    void parseKeyShareThatIsNotInLegacyFormThrows() {
        // Replace the legacy_form header byte (4) by the header byte of a compressed point.
        byte[] data = ByteUtils.hexToBytes(CLIENT_KEY_EXCHANGE_DATA);
        data[0] = 3;

        ECKeyExchange keyExchange = ecKeyExchange;

        assertThatThrownBy(() -> keyExchange.parseKeyShare(data))
                .hasMessageContaining("legacy form");
    }

    @Test
    void parseKeyShareThatIsTooShortThrows() {
        // One byte short of a complete uncompressed point representation.
        byte[] data = Arrays.copyOf(ByteUtils.hexToBytes(CLIENT_KEY_EXCHANGE_DATA), 64);

        assertThatThrownBy(() -> ecKeyExchange.parseKeyShare(data))
                .isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void parseEmptyKeyShareThrows() {
        assertThatThrownBy(() -> ecKeyExchange.parseKeyShare(new byte[0]))
                .isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void parseKeyShareThatIsTooLongThrows() {
        byte[] data = Arrays.copyOf(ByteUtils.hexToBytes(CLIENT_KEY_EXCHANGE_DATA), 66);

        assertThatThrownBy(() -> ecKeyExchange.parseKeyShare(data))
                .isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void creatingKeyExchangeForNonEcGroupThrows() {
        assertThatThrownBy(() -> new ECKeyExchange(TlsConstants.NamedGroup.x25519))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ECKeyExchange(TlsConstants.NamedGroup.ffdhe2048))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void serializeCreatesUncompressedPointRepresentation() throws Exception {
        ECPublicKey publicKey = ecKeyExchange.parseKeyShare(ByteUtils.hexToBytes(SERVER_KEY_EXCHANGE_DATA));

        // When
        byte[] serialized = ecKeyExchange.serialize(publicKey);

        // Then
        assertThat(serialized).isEqualTo(ByteUtils.hexToBytes(SERVER_KEY_EXCHANGE_DATA));
    }

    @Test
    void serializeLeftPadsAffineCoordinatesThatAreLessThan32Bytes() {
        ECPublicKey publicKey = keyWithCoordinates(BigInteger.ONE, BigInteger.valueOf(2));

        // When
        byte[] serialized = ecKeyExchange.serialize(publicKey);

        // Then
        assertThat(serialized).isEqualTo(ByteUtils.hexToBytes(
                "04" + "00".repeat(31) + "01" + "00".repeat(31) + "02"));
    }

    @Test
    void serializeStripsLeadingZeroFromAffineCoordinatesOf33Bytes() {
        // A coordinate with the most significant bit set leads to a 33 byte two's complement representation.
        ECPublicKey publicKey = keyWithCoordinates(BigInteger.ONE.shiftLeft(255), BigInteger.ONE);

        // When
        byte[] serialized = ecKeyExchange.serialize(publicKey);

        // Then
        assertThat(serialized).isEqualTo(ByteUtils.hexToBytes(
                "04" + "80" + "00".repeat(31) + "00".repeat(31) + "01"));
    }

    @Test
    void serializeAffineCoordinateThatDoesNotFitIn32BytesThrows() {
        ECPublicKey publicKey = keyWithCoordinates(BigInteger.ONE.shiftLeft(256), BigInteger.ONE);

        assertThatThrownBy(() -> ecKeyExchange.serialize(publicKey))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void ecParameterSpecIsAvailableForAllSupportedCurves() {
        assertThat(ECKeyExchange.ecParameterSpecForCurve("secp256r1").getCurve().getField().getFieldSize()).isEqualTo(256);
        assertThat(ECKeyExchange.ecParameterSpecForCurve("secp384r1").getCurve().getField().getFieldSize()).isEqualTo(384);
        assertThat(ECKeyExchange.ecParameterSpecForCurve("secp521r1").getCurve().getField().getFieldSize()).isEqualTo(521);
    }

    @Test
    void parseSecp384r1KeyShareExtractsAffineCoordinates() throws Exception {
        byte[] data = ByteUtils.hexToBytes(RFC6979_P384_PUBLIC_KEY);

        // When
        ECPublicKey ecPublicKey = secp384r1KeyExchange.parseKeyShare(data);

        // Then: the X coordinate is the first 48 bytes and the Y coordinate the last 48 bytes of the point representation.
        assertThat(ecPublicKey.getW().getAffineX()).isEqualTo(new BigInteger(RFC6979_P384_PUBLIC_KEY_X, 16));
        assertThat(ecPublicKey.getW().getAffineY()).isEqualTo(new BigInteger(RFC6979_P384_PUBLIC_KEY_Y, 16));
    }

    @Test
    void parseSecp384r1BasePointKeyShare() throws Exception {
        byte[] data = ByteUtils.hexToBytes(SECP384R1_BASE_POINT);

        // When
        ECPublicKey ecPublicKey = secp384r1KeyExchange.parseKeyShare(data);

        // Then: the parsed point is the generator of the curve's domain parameters.
        assertThat(ecPublicKey.getW())
                .isEqualTo(ECKeyExchange.ecParameterSpecForCurve("secp384r1").getGenerator());
    }

    @Test
    void parsedSecp384r1KeyUsesSecp384r1DomainParameters() throws Exception {
        byte[] data = ByteUtils.hexToBytes(RFC6979_P384_PUBLIC_KEY);

        // When
        ECPublicKey ecPublicKey = secp384r1KeyExchange.parseKeyShare(data);

        // Then
        assertThat(ecPublicKey.getParams().getCurve())
                .isEqualTo(ECKeyExchange.ecParameterSpecForCurve("secp384r1").getCurve());
        assertThat(ecPublicKey.getParams().getCurve().getField().getFieldSize()).isEqualTo(384);
    }

    @Test
    void parseSecp384r1KeyShareThatIsNotInLegacyFormThrows() {
        // Replace the legacy_form header byte (4) by the header byte of a compressed point.
        byte[] data = ByteUtils.hexToBytes(RFC6979_P384_PUBLIC_KEY);
        data[0] = 3;

        assertThatThrownBy(() -> secp384r1KeyExchange.parseKeyShare(data))
                .hasMessageContaining("legacy form");
    }

    @Test
    void parseSecp384r1KeyShareThatIsTooShortThrows() {
        // One byte short of a complete uncompressed point representation.
        byte[] data = Arrays.copyOf(ByteUtils.hexToBytes(RFC6979_P384_PUBLIC_KEY), 96);

        assertThatThrownBy(() -> secp384r1KeyExchange.parseKeyShare(data))
                .isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void parseSecp384r1KeyShareThatIsTooLongThrows() {
        byte[] data = Arrays.copyOf(ByteUtils.hexToBytes(RFC6979_P384_PUBLIC_KEY), 98);

        assertThatThrownBy(() -> secp384r1KeyExchange.parseKeyShare(data))
                .isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void parseSecp256r1SizedKeyShareAsSecp384r1Throws() {
        // A key share that would be valid for secp256r1 must be rejected by a secp384r1 key exchange.
        byte[] data = ByteUtils.hexToBytes(CLIENT_KEY_EXCHANGE_DATA);

        assertThatThrownBy(() -> secp384r1KeyExchange.parseKeyShare(data))
                .isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void serializeSecp384r1KeyCreatesUncompressedPointRepresentation() throws Exception {
        // The RFC 6979 public key; both its coordinates have their most significant bit set.
        ECPublicKey publicKey = secp384r1KeyExchange.parseKeyShare(ByteUtils.hexToBytes(RFC6979_P384_PUBLIC_KEY));

        // When
        byte[] serialized = secp384r1KeyExchange.serialize(publicKey);

        // Then
        assertThat(serialized).isEqualTo(ByteUtils.hexToBytes(RFC6979_P384_PUBLIC_KEY));
    }

    @Test
    void serializeSecp384r1BasePointCreatesUncompressedPointRepresentation() throws Exception {
        // The base point; its X coordinate needs 49 bytes as two's complement, its Y coordinate exactly 48.
        ECPublicKey publicKey = secp384r1KeyExchange.parseKeyShare(ByteUtils.hexToBytes(SECP384R1_BASE_POINT));

        // When
        byte[] serialized = secp384r1KeyExchange.serialize(publicKey);

        // Then
        assertThat(serialized).isEqualTo(ByteUtils.hexToBytes(SECP384R1_BASE_POINT));
    }

    @Test
    void serializeLeftPadsSecp384r1AffineCoordinatesThatAreLessThan48Bytes() {
        ECPublicKey publicKey = keyWithCoordinates(BigInteger.ONE, BigInteger.valueOf(2));

        // When
        byte[] serialized = secp384r1KeyExchange.serialize(publicKey);

        // Then
        assertThat(serialized).isEqualTo(ByteUtils.hexToBytes(
                "04" + "00".repeat(47) + "01" + "00".repeat(47) + "02"));
    }

    @Test
    void serializeStripsLeadingZeroFromSecp384r1AffineCoordinatesOf49Bytes() {
        // A coordinate with the most significant bit set leads to a 49 byte two's complement representation.
        ECPublicKey publicKey = keyWithCoordinates(BigInteger.ONE.shiftLeft(383), BigInteger.ONE);

        // When
        byte[] serialized = secp384r1KeyExchange.serialize(publicKey);

        // Then
        assertThat(serialized).isEqualTo(ByteUtils.hexToBytes(
                "04" + "80" + "00".repeat(47) + "00".repeat(47) + "01"));
    }

    @Test
    void serializeSecp384r1AffineCoordinateThatDoesNotFitIn48BytesThrows() {
        ECPublicKey publicKey = keyWithCoordinates(BigInteger.ONE.shiftLeft(384), BigInteger.ONE);

        assertThatThrownBy(() -> secp384r1KeyExchange.serialize(publicKey))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void generatedSecp384r1KeyShareHasKeyExchangeDataLength() {
        // When
        secp384r1KeyExchange.generateClientKeyPair();

        // Then: see https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.8.2
        assertThat(secp384r1KeyExchange.getClientKeyShare()).hasSize(97);
    }

    @Test
    void generatedSecp384r1KeyShareCanBeParsedBack() throws Exception {
        secp384r1KeyExchange.generateClientKeyPair();
        byte[] keyShare = secp384r1KeyExchange.getClientKeyShare();

        // When
        ECPublicKey parsed = secp384r1KeyExchange.parseKeyShare(keyShare);

        // Then
        assertThat(secp384r1KeyExchange.serialize(parsed)).isEqualTo(keyShare);
    }

    @Test
    void secp384r1SharedSecretMatchesRfc6979KeyPair() throws Exception {
        // Given: a key exchange that uses the private key x of RFC 6979 appendix A.2.6.
        ECKeyExchange keyExchange = secp384r1KeyExchangeWithPrivateKey(RFC6979_P384_PRIVATE_KEY);

        // When: the peer's key share is the base point G, so the ECDH result is the X coordinate of xG = U.
        byte[] sharedSecret = keyExchange.clientComputeSharedSecret(ByteUtils.hexToBytes(SECP384R1_BASE_POINT));

        // Then
        assertThat(sharedSecret).isEqualTo(ByteUtils.hexToBytes(RFC6979_P384_PUBLIC_KEY_X));
    }

    @Test
    void secp384r1ClientAndServerComputeSameSharedSecret() throws Exception {
        ECKeyExchange client = new ECKeyExchange(TlsConstants.NamedGroup.secp384r1);
        ECKeyExchange server = new ECKeyExchange(TlsConstants.NamedGroup.secp384r1);
        client.generateClientKeyPair();

        // When
        byte[] clientKeyShare = client.getClientKeyShare();
        byte[] serverSharedSecret = server.serverProcessClientKeyShare(clientKeyShare);
        byte[] clientSharedSecret = client.clientComputeSharedSecret(server.getServerKeyShare());

        // Then
        assertThat(clientSharedSecret).isEqualTo(serverSharedSecret);
        assertThat(clientSharedSecret).hasSize(48);
    }

    /**
     * Creates a secp384r1 key exchange object that uses the given private key, instead of a generated one, so its
     * result can be compared with published test vectors.
     */
    private ECKeyExchange secp384r1KeyExchangeWithPrivateKey(String privateKeyHex) throws Exception {
        ECPrivateKeySpec keySpec = new ECPrivateKeySpec(new BigInteger(privateKeyHex, 16),
                ECKeyExchange.ecParameterSpecForCurve("secp384r1"));
        PrivateKey privateKey = KeyFactory.getInstance("EC").generatePrivate(keySpec);

        ECKeyExchange keyExchange = new ECKeyExchange(TlsConstants.NamedGroup.secp384r1);
        FieldSetter.setField(keyExchange, ECKeyExchange.class, "privateKey", privateKey);
        return keyExchange;
    }

    /**
     * Creates a public key with the given affine coordinates; a mock is used because coordinates that are not on the
     * curve cannot be turned into a real key.
     */
    private ECPublicKey keyWithCoordinates(BigInteger x, BigInteger y) {
        ECPublicKey publicKey = mock(ECPublicKey.class);
        when(publicKey.getW()).thenReturn(new ECPoint(x, y));
        return publicKey;
    }
}
