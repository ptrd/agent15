package net.luminis.tls.extension;

import net.luminis.tls.*;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * The TLS "key_share" extension contains the endpoint's cryptographic parameters.
 * See https://tools.ietf.org/html/rfc8446#section-4.2.8
 */
public class KeyShareExtension extends Extension {

    public static final Map<TlsConstants.NamedGroup, Integer> SEC_KEY_LENGTHS
            = Map.of(TlsConstants.NamedGroup.secp256r1, 32, TlsConstants.NamedGroup.secp384r1, 48, TlsConstants.NamedGroup.secp521r1, 66);


    private TlsConstants.HandshakeType handshakeType;
    private List<KeyShareEntry> keyShareEntries = new ArrayList<>();


    /**
     * Assuming KeyShareClientHello:
     * "In the ClientHello message, the "extension_data" field of this extension contains a "KeyShareClientHello" value..."
     * @param publicKey
     * @param ecCurve
     */
    public KeyShareExtension(ECPublicKey publicKey, TlsConstants.NamedGroup ecCurve, TlsConstants.HandshakeType handshakeType) {
        this.handshakeType = handshakeType;

        if (ecCurve != TlsConstants.NamedGroup.secp256r1) {
            throw new RuntimeException("Only secp256r1 is supported");
        }

        keyShareEntries.add(new ECKeyShareEntry(ecCurve, publicKey));
    }

    /**
     * Assuming KeyShareServerHello:
     * "In a ServerHello message, the "extension_data" field of this extension contains a KeyShareServerHello value..."
     * @param buffer
     * @return
     * @throws TlsProtocolException
     */
    public KeyShareExtension(ByteBuffer buffer, TlsConstants.HandshakeType handshakeType) throws TlsProtocolException {
        this(buffer, handshakeType, false);
    }

    public KeyShareExtension(ByteBuffer buffer, TlsConstants.HandshakeType handshakeType, boolean helloRetryRequestType) throws TlsProtocolException {
        int extensionDataLength = parseExtensionHeader(buffer, TlsConstants.ExtensionType.key_share);
        if (extensionDataLength < 2) {
            throw new DecodeErrorException("extension underflow");
        }

        if (handshakeType == TlsConstants.HandshakeType.client_hello) {
            int keyShareEntriesSize = buffer.getShort();
            if (extensionDataLength != 2 + keyShareEntriesSize) {
                throw new DecodeErrorException("inconsistent length");
            }
            int remaining = keyShareEntriesSize;
            while (remaining > 0) {
                remaining -= parseKeyShareEntry(buffer, helloRetryRequestType);
            }
            if (remaining != 0) {
                throw new DecodeErrorException("inconsistent length");
            }
        }
        else if (handshakeType == TlsConstants.HandshakeType.server_hello) {
            int remaining = extensionDataLength;
            remaining -= parseKeyShareEntry(buffer, helloRetryRequestType);
            if (remaining != 0) {
                throw new DecodeErrorException("inconsistent length");
            }
        }
        else {
            throw new IllegalArgumentException();
        }
    }

    protected int parseKeyShareEntry(ByteBuffer buffer, boolean namedGroupOnly) throws TlsProtocolException {
        int startPosition = buffer.position();
        if (namedGroupOnly && buffer.remaining() < 2 || !namedGroupOnly && buffer.remaining() < 4 ) {
            throw new DecodeErrorException("extension underflow");
        }

        int namedGroupValue = buffer.getShort();
        TlsConstants.NamedGroup namedGroup = Stream.of(TlsConstants.NamedGroup.values()).filter(it -> it.value == namedGroupValue).findAny()
                .orElseThrow(() -> new DecodeErrorException("Invalid named group"));

        if (namedGroup != TlsConstants.NamedGroup.secp256r1) {
            throw new RuntimeException("Unsupported named group " + namedGroup.name());
        }

        if (namedGroupOnly) {
            keyShareEntries.add(new ECKeyShareEntry(namedGroup, null));
        }
        else {
            int keyLength = buffer.getShort();
            if (buffer.remaining() < keyLength) {
                throw new DecodeErrorException("extension underflow");
            }
            if (keyLength != 1 + 2 * SEC_KEY_LENGTHS.get(namedGroup)) {
                throw new DecodeErrorException("Invalid key length");
            }
            int headerByte = buffer.get();
            if (headerByte == 4) {
                byte[] keyData = new byte[keyLength - 1];
                buffer.get(keyData);
                ECPublicKey ecPublicKey = rawToEncodedECPublicKey(namedGroup.name(), keyData);
                keyShareEntries.add(new ECKeyShareEntry(namedGroup, ecPublicKey));
            } else {
                throw new DecodeErrorException("EC keys must be in legacy form");
            }
        }
        return buffer.position() - startPosition;
    }

    @Override
    public byte[] getBytes() {
        short rawKeyLength = 65;
        short keyShareEntryLength = (short) (2 + 2 + rawKeyLength);   // Named Group: 2 bytes, key length: 2 bytes
        short extensionLength = keyShareEntryLength;
        if (handshakeType == TlsConstants.HandshakeType.client_hello) {
            extensionLength += 2;
        }

        ByteBuffer buffer = ByteBuffer.allocate(4 + extensionLength);
        buffer.putShort(TlsConstants.ExtensionType.key_share.value);
        buffer.putShort(extensionLength);  // Extension data length (in bytes)

        if (handshakeType == TlsConstants.HandshakeType.client_hello) {
            buffer.putShort(keyShareEntryLength);
        }

        for (KeyShareEntry keyShare: keyShareEntries) {
            buffer.putShort(keyShare.getNamedGroup().value);
            buffer.putShort(rawKeyLength);
            // See https://tools.ietf.org/html/rfc8446#section-4.2.8.2, "For secp256r1, secp384r1, and secp521r1, ..."
            buffer.put((byte) 4);
            byte[] affineX = ((ECPublicKey) keyShare.getKey()).getW().getAffineX().toByteArray();
            writeAffine(buffer, affineX);
            byte[] affineY = ((ECPublicKey) keyShare.getKey()).getW().getAffineY().toByteArray();
            writeAffine(buffer, affineY);
        }

        return buffer.array();
    }

    public List<KeyShareEntry> getKeyShareEntries() {
        return keyShareEntries;
    }

    private void writeAffine(ByteBuffer buffer, byte[] affine) {
        if (affine.length == 32) {
            buffer.put(affine);
        }
        else if (affine.length < 32) {
            for (int i = 0; i < 32 - affine.length; i++) {
                buffer.put((byte) 0);
            }
            buffer.put(affine, 0, affine.length);
        }
        else if (affine.length > 32) {
            for (int i = 0; i < affine.length - 32; i++) {
                if (affine[i] != 0) {
                    throw new RuntimeException("W Affine more then 32 bytes, leading bytes not 0 "
                            + ByteUtils.bytesToHex(affine));
                }
            }
            buffer.put(affine, affine.length - 32, 32);
        }
    }

    public static abstract class KeyShareEntry {
        protected TlsConstants.NamedGroup namedGroup;

        public TlsConstants.NamedGroup getNamedGroup() {
            return namedGroup;
        }

        public abstract PublicKey getKey();
    }

    public static class ECKeyShareEntry extends KeyShareEntry {
        private final ECPublicKey key;

        public ECKeyShareEntry(TlsConstants.NamedGroup namedGroup, ECPublicKey key) {
            this.namedGroup = namedGroup;
            this.key = key;
        }

        public ECPublicKey getKey() {
            return key;
        }
    }

    static ECPublicKey rawToEncodedECPublicKey(String curveName, byte[] rawBytes) {
        try {
            KeyFactory kf = KeyFactory.getInstance("EC");
            byte[] x = Arrays.copyOfRange(rawBytes, 0, rawBytes.length/2);
            byte[] y = Arrays.copyOfRange(rawBytes, rawBytes.length/2, rawBytes.length);
            ECPoint w = new ECPoint(new BigInteger(1,x), new BigInteger(1,y));
            return (ECPublicKey) kf.generatePublic(new ECPublicKeySpec(w, ecParameterSpecForCurve(curveName)));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing support for EC algorithm");
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException("Inappropriate parameter specification");
        }
    }

    static ECParameterSpec ecParameterSpecForCurve(String curveName) {
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec(curveName));
            return params.getParameterSpec(ECParameterSpec.class);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing support for EC algorithm");
        } catch (InvalidParameterSpecException e) {
            throw new RuntimeException("Inappropriate parameter specification");
        }
    }
}
