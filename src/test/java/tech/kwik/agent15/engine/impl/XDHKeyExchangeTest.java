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
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class XDHKeyExchangeTest {

    // RFC 7748 section 6.1, Alice's public key (little endian, as sent on the wire).
    private static final String X25519_KEY_EXCHANGE_DATA =
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";

    // RFC 7748 section 6.2: "5 is the u-coordinate of the base point and is encoded as a byte with value 5, followed
    // by 55 zero bytes."
    private static final String X448_BASE_POINT = "05" + "00".repeat(55);

    // RFC 7748 section 6.2 test vector (all values little endian, as used on the wire).
    private static final String X448_ALICE_PRIVATE_KEY =
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d" +
            "d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b";
    private static final String X448_ALICE_PUBLIC_KEY =
            "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c" +
            "22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0";
    private static final String X448_BOB_PRIVATE_KEY =
            "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d" +
            "6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d";
    private static final String X448_BOB_PUBLIC_KEY =
            "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430" +
            "27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609";
    private static final String X448_SHARED_SECRET =
            "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b" +
            "b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d";

    private XDHKeyExchange xdhKeyExchange;

    @BeforeEach
    void initObjectUnderTest() {
        xdhKeyExchange = new XDHKeyExchange(TlsConstants.NamedGroup.x25519);
    }

    @Test
    void parseKeyShareInterpretsDataAsLittleEndian() throws Exception {
        byte[] data = ByteUtils.hexToBytes(X25519_KEY_EXCHANGE_DATA);

        // When
        XECPublicKey publicKey = xdhKeyExchange.parseKeyShare(data);

        // Then: u is the big endian value of the reversed byte string.
        assertThat(publicKey.getU())
                .isEqualTo(new BigInteger("6a4e9baa8ea9a4ebf41a38260d3abf0d5af73eb4dc7d8b7454a7308909f02085", 16));
    }

    @Test
    void parsedKeyUsesX25519DomainParameters() throws Exception {
        byte[] data = ByteUtils.hexToBytes(X25519_KEY_EXCHANGE_DATA);

        // When
        XECPublicKey publicKey = xdhKeyExchange.parseKeyShare(data);

        // Then: the named group is mapped to its uppercase JCA name.
        assertThat(((NamedParameterSpec) publicKey.getParams()).getName()).isEqualTo("X25519");
    }

    @Test
    void parseX448ClientKeyShare() throws Exception {
        // 56 bytes, little endian: u = 5
        byte[] data = ByteUtils.hexToBytes(X448_BASE_POINT);

        // When
        XECPublicKey publicKey = new XDHKeyExchange(TlsConstants.NamedGroup.x448).parseKeyShare(data);

        // Then
        assertThat(publicKey.getU()).isEqualTo(BigInteger.valueOf(5));
        assertThat(((NamedParameterSpec) publicKey.getParams()).getName()).isEqualTo("X448");
    }

    @Test
    void parseX448KeyShareInterpretsDataAsLittleEndian() throws Exception {
        byte[] data = ByteUtils.hexToBytes(X448_ALICE_PUBLIC_KEY);

        // When
        XECPublicKey publicKey = new XDHKeyExchange(TlsConstants.NamedGroup.x448).parseKeyShare(data);

        // Then: u is the big endian value of the reversed byte string (RFC 7748 section 6.2, Alice's public key).
        assertThat(publicKey.getU()).isEqualTo(new BigInteger(
                "a01fc432e5807f17530d1288da125b0cd453d941726436c8bbd9c522" +
                "2c3da7fa639ce03db8d23b274a0721a1aed5227de6e3b731ccf7089b", 16));
    }

    @Test
    void parseTooLongKeyShareThrows() {
        // One byte too many; without an explicit length check, the JCA would silently truncate the key data.
        byte[] data = ByteUtils.hexToBytes(X25519_KEY_EXCHANGE_DATA + "ff");

        assertThatThrownBy(() -> xdhKeyExchange.parseKeyShare(data))
                .isInstanceOf(IllegalParameterAlert.class)
                .hasMessageContaining("key length");
    }

    @Test
    void parseTooShortKeyShareThrows() {
        // One byte too few; without an explicit length check, the JCA would silently zero-pad the key data.
        byte[] data = ByteUtils.hexToBytes(X25519_KEY_EXCHANGE_DATA.substring(2));

        assertThatThrownBy(() -> xdhKeyExchange.parseKeyShare(data))
                .isInstanceOf(IllegalParameterAlert.class)
                .hasMessageContaining("key length");
    }

    @Test
    void parseEmptyKeyShareThrows() {
        assertThatThrownBy(() -> xdhKeyExchange.parseKeyShare(new byte[0]))
                .isInstanceOf(IllegalParameterAlert.class)
                .hasMessageContaining("key length");
    }

    @Test
    void parseX25519SizedX448KeyShareThrows() {
        // A 32 byte key share is valid for x25519, but not for x448.
        byte[] data = ByteUtils.hexToBytes(X25519_KEY_EXCHANGE_DATA);

        assertThatThrownBy(() -> new XDHKeyExchange(TlsConstants.NamedGroup.x448).parseKeyShare(data))
                .isInstanceOf(IllegalParameterAlert.class)
                .hasMessageContaining("key length");
    }

    @Test
    void parseKeyShareDoesNotModifyTheGivenArray() throws Exception {
        byte[] data = ByteUtils.hexToBytes(X25519_KEY_EXCHANGE_DATA);

        // When
        xdhKeyExchange.parseKeyShare(data);

        // Then
        assertThat(data).isEqualTo(ByteUtils.hexToBytes(X25519_KEY_EXCHANGE_DATA));
    }

    @Test
    void parsingSameKeyShareTwiceYieldsSameKey() throws Exception {
        byte[] data = ByteUtils.hexToBytes(X25519_KEY_EXCHANGE_DATA);

        // When
        XECPublicKey firstKey = xdhKeyExchange.parseKeyShare(data);
        XECPublicKey secondKey = xdhKeyExchange.parseKeyShare(data);

        // Then
        assertThat(secondKey.getU()).isEqualTo(firstKey.getU());
    }

    @Test
    void clientAndServerComputeSameSharedSecret() throws Exception {
        XDHKeyExchange client = new XDHKeyExchange(TlsConstants.NamedGroup.x25519);
        XDHKeyExchange server = new XDHKeyExchange(TlsConstants.NamedGroup.x25519);
        client.generateClientKeyPair();

        // When
        byte[] clientKeyShare = client.getClientKeyShare();
        byte[] serverSharedSecret = server.serverProcessClientKeyShare(clientKeyShare);
        byte[] clientSharedSecret = client.clientComputeSharedSecret(server.getServerKeyShare());

        // Then
        assertThat(clientSharedSecret).isEqualTo(serverSharedSecret);
    }

    @Test
    void creatingKeyExchangeForNonXdhGroupThrows() {
        assertThatThrownBy(() -> new XDHKeyExchange(TlsConstants.NamedGroup.secp256r1))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void serializeCreatesLittleEndianRepresentation() throws Exception {
        XECPublicKey publicKey = xdhKeyExchange.parseKeyShare(ByteUtils.hexToBytes(X25519_KEY_EXCHANGE_DATA));

        // When
        byte[] serialized = xdhKeyExchange.serialize(publicKey);

        // Then
        assertThat(serialized).isEqualTo(ByteUtils.hexToBytes(X25519_KEY_EXCHANGE_DATA));
    }

    @Test
    void serializePadsX25519KeyToKeyLength() {
        // u = 1, which is only one byte when represented as (big endian) integer.
        XECPublicKey publicKey = keyWithU(BigInteger.ONE);

        // When
        byte[] serialized = xdhKeyExchange.serialize(publicKey);

        // Then: little endian, padded with (trailing) zeros up to the key length.
        assertThat(serialized).isEqualTo(ByteUtils.hexToBytes("01" + "00".repeat(31)));
    }

    @Test
    void serializePadsX448KeyToKeyLength() {
        XECPublicKey publicKey = keyWithU(BigInteger.valueOf(5));

        // When
        byte[] serialized = new XDHKeyExchange(TlsConstants.NamedGroup.x448).serialize(publicKey);

        // Then
        assertThat(serialized).isEqualTo(ByteUtils.hexToBytes(X448_BASE_POINT));
    }

    @Test
    void serializeX448KeyCreatesLittleEndianRepresentation() throws Exception {
        XDHKeyExchange keyExchange = new XDHKeyExchange(TlsConstants.NamedGroup.x448);
        // Bob's public key from RFC 7748 section 6.2; note that its most significant byte is not zero.
        XECPublicKey publicKey = keyExchange.parseKeyShare(ByteUtils.hexToBytes(X448_BOB_PUBLIC_KEY));

        // When
        byte[] serialized = keyExchange.serialize(publicKey);

        // Then
        assertThat(serialized).isEqualTo(ByteUtils.hexToBytes(X448_BOB_PUBLIC_KEY));
    }

    @Test
    void serializeX448KeyWithHighestBitSetCreatesLittleEndianRepresentation() throws Exception {
        XDHKeyExchange keyExchange = new XDHKeyExchange(TlsConstants.NamedGroup.x448);
        // Alice's public key from RFC 7748 section 6.2; its most significant byte is 0xa0, so the sign bit of the
        // (unsigned) u-coordinate is set.
        XECPublicKey publicKey = keyExchange.parseKeyShare(ByteUtils.hexToBytes(X448_ALICE_PUBLIC_KEY));

        // When
        byte[] serialized = keyExchange.serialize(publicKey);

        // Then
        assertThat(serialized).isEqualTo(ByteUtils.hexToBytes(X448_ALICE_PUBLIC_KEY));
    }

    @Test
    void serializeKeyThatDoesNotFitInKeyLengthThrows() {
        XECPublicKey publicKey = keyWithU(BigInteger.ONE.shiftLeft(256));

        assertThatThrownBy(() -> xdhKeyExchange.serialize(publicKey))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void x25519LowOrderPointShouldNotProduceAllZeroSharedSecret() throws Exception {
        // Given
        XDHKeyExchange keyExchange = new XDHKeyExchange(TlsConstants.NamedGroup.x25519);
        // A key pair is required, to ensure the exception is caused by the peer's public key and not by a missing private key.
        keyExchange.generateClientKeyPair();

        // u=39382357... is a torsion point of small order: X25519(k, u) = 0 for any scalar k
        KeyFactory kf = KeyFactory.getInstance("XDH");
        BigInteger torsionU = new BigInteger("39382357235489614581723060781553021112529911719440698176882885853963445705823");
        XECPublicKey lowOrderPoint = (XECPublicKey) kf.generatePublic(new XECPublicKeySpec(new NamedParameterSpec("X25519"), torsionU));

        assertThatThrownBy(() ->
                // When
                keyExchange.computeSharedSecret(lowOrderPoint)
                // Then: the alert must be caused by the small order point, not by e.g. an unusable private key.
        ).isInstanceOf(IllegalParameterAlert.class)
                .hasMessageContaining("small order");
    }

    @Test
    void x448ClientComputesSharedSecretOfRfc7748TestVector() throws Exception {
        // Given: a client that uses Alice's private key (RFC 7748 section 6.2).
        XDHKeyExchange client = x448KeyExchangeWithPrivateKey(X448_ALICE_PRIVATE_KEY);

        // When: the server key share contains Bob's public key.
        byte[] sharedSecret = client.clientComputeSharedSecret(ByteUtils.hexToBytes(X448_BOB_PUBLIC_KEY));

        // Then
        assertThat(sharedSecret).isEqualTo(ByteUtils.hexToBytes(X448_SHARED_SECRET));
    }

    @Test
    void x448ServerComputesSharedSecretOfRfc7748TestVector() throws Exception {
        // Given: a server that uses Bob's private key (RFC 7748 section 6.2).
        XDHKeyExchange server = x448KeyExchangeWithPrivateKey(X448_BOB_PRIVATE_KEY);

        // When: the client key share contains Alice's public key.
        byte[] sharedSecret = server.serverProcessClientKeyShare(ByteUtils.hexToBytes(X448_ALICE_PUBLIC_KEY));

        // Then
        assertThat(sharedSecret).isEqualTo(ByteUtils.hexToBytes(X448_SHARED_SECRET));
    }

    @Test
    void x448PublicKeyComputedFromPrivateKeyMatchesRfc7748TestVector() throws Exception {
        // Given: Alice's private key (RFC 7748 section 6.2); public key is X448(a, 5).
        XDHKeyExchange alice = x448KeyExchangeWithPrivateKey(X448_ALICE_PRIVATE_KEY);

        // When
        byte[] publicKey = alice.clientComputeSharedSecret(ByteUtils.hexToBytes(X448_BASE_POINT));

        // Then
        assertThat(publicKey).isEqualTo(ByteUtils.hexToBytes(X448_ALICE_PUBLIC_KEY));
    }

    @Test
    void x448ComputeSharedSecretMatchesFirstRfc7748FunctionTestVector() throws Exception {
        // Given: the first X448 test vector of RFC 7748 section 5.2 (input scalar and input u-coordinate).
        XDHKeyExchange keyExchange = x448KeyExchangeWithPrivateKey(
                "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121" +
                "700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3");
        byte[] inputUCoordinate = ByteUtils.hexToBytes(
                "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9" +
                "814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086");

        // When
        byte[] outputUCoordinate = keyExchange.clientComputeSharedSecret(inputUCoordinate);

        // Then
        assertThat(outputUCoordinate).isEqualTo(ByteUtils.hexToBytes(
                "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f" +
                "e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f"));
    }

    @Test
    void x448ComputeSharedSecretMatchesSecondRfc7748FunctionTestVector() throws Exception {
        // Given: the second X448 test vector of RFC 7748 section 5.2 (input scalar and input u-coordinate).
        XDHKeyExchange keyExchange = x448KeyExchangeWithPrivateKey(
                "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c5" +
                "38345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f");
        byte[] inputUCoordinate = ByteUtils.hexToBytes(
                "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b" +
                "165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db");

        // When
        byte[] outputUCoordinate = keyExchange.clientComputeSharedSecret(inputUCoordinate);

        // Then
        assertThat(outputUCoordinate).isEqualTo(ByteUtils.hexToBytes(
                "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7" +
                "ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d"));
    }

    @Test
    void generatedX448KeyShareHasKeyExchangeDataLength() {
        XDHKeyExchange keyExchange = new XDHKeyExchange(TlsConstants.NamedGroup.x448);

        // When
        keyExchange.generateClientKeyPair();

        // Then: see https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.8.2
        assertThat(keyExchange.getClientKeyShare()).hasSize(56);
    }

    @Test
    void x448ClientAndServerComputeSameSharedSecret() throws Exception {
        XDHKeyExchange client = new XDHKeyExchange(TlsConstants.NamedGroup.x448);
        XDHKeyExchange server = new XDHKeyExchange(TlsConstants.NamedGroup.x448);
        client.generateClientKeyPair();

        // When
        byte[] clientKeyShare = client.getClientKeyShare();
        byte[] serverSharedSecret = server.serverProcessClientKeyShare(clientKeyShare);
        byte[] clientSharedSecret = client.clientComputeSharedSecret(server.getServerKeyShare());

        // Then
        assertThat(clientSharedSecret).isEqualTo(serverSharedSecret);
        assertThat(clientSharedSecret).hasSize(56);
    }

    /**
     * Creates an X448 key exchange object that uses the given private key, instead of a generated one, so its result
     * can be compared with published test vectors.
     */
    private XDHKeyExchange x448KeyExchangeWithPrivateKey(String privateKeyHex) throws Exception {
        // The scalar is encoded little endian, just as in RFC 7748.
        XECPrivateKeySpec keySpec = new XECPrivateKeySpec(NamedParameterSpec.X448, ByteUtils.hexToBytes(privateKeyHex));
        PrivateKey privateKey = KeyFactory.getInstance("XDH").generatePrivate(keySpec);

        XDHKeyExchange keyExchange = new XDHKeyExchange(TlsConstants.NamedGroup.x448);
        FieldSetter.setField(keyExchange, XDHKeyExchange.class, "privateKey", privateKey);
        return keyExchange;
    }

    private XECPublicKey keyWithU(BigInteger u) {
        XECPublicKey publicKey = mock(XECPublicKey.class);
        when(publicKey.getU()).thenReturn(u);
        return publicKey;
    }
}
