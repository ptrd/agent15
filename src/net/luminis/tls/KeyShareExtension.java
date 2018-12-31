package net.luminis.tls;

import java.nio.ByteBuffer;
import java.security.interfaces.ECPublicKey;
import java.util.stream.Stream;

// https://tools.ietf.org/html/rfc8446#section-4.2.8
public class KeyShareExtension extends Extension {

    private ECPublicKey publicKey;
    private String ecCurve;
    private TlsConstants.NamedGroup namedGroup;
    private byte[] serverSharedKey;

    public KeyShareExtension() {
    }

    /**
     * Assuming KeyShareClientHello:
     * "In the ClientHello message, the "extension_data" field of this extension contains a "KeyShareClientHello" value..."
     * @param publicKey
     * @param ecCurve
     */
    public KeyShareExtension(ECPublicKey publicKey, String ecCurve) {
        this.publicKey = publicKey;
        this.ecCurve = ecCurve;
        if (ecCurve != "secp256r1")
            throw new RuntimeException("Only secp256r1 is supported");
    }

    /**
     * Assuming KeyShareServerHello:
     * "In a ServerHello message, the "extension_data" field of this extension contains a KeyShareServerHello value..."
     * @param buffer
     * @return
     * @throws TlsProtocolException
     */
    public KeyShareExtension parse(ByteBuffer buffer) throws TlsProtocolException {
        int extensionType = buffer.getShort();
        if (extensionType != TlsConstants.ExtensionType.key_share.value) {
            throw new RuntimeException();  // Must be programming error
        }

        int extensionLength = buffer.getShort();

        int keyShareEntryPosition = buffer.position();
        parseKeyShareEntry(buffer);

        if (buffer.position() - keyShareEntryPosition != extensionLength)
            throw new TlsProtocolException("Incorrect length");

        return this;
    }

    protected void parseKeyShareEntry(ByteBuffer buffer) throws TlsProtocolException {
        int namedGroupValue = buffer.getShort();
        namedGroup = Stream.of(TlsConstants.NamedGroup.values()).filter(it -> it.value == namedGroupValue).findAny()
                .orElseThrow(() -> new TlsProtocolException("Unknown named group"));

        int keyLength = buffer.getShort();
        serverSharedKey = new byte[keyLength];
        buffer.get(serverSharedKey);
        Logger.debug("Server shared key (" + keyLength + "): " + ByteUtils.bytesToHex(serverSharedKey));
    }

    @Override
    public byte[] getBytes() {
        short rawKeyLength = 65;
        short keyShareEntryLength = (short) (2 + 2 + rawKeyLength);   // Named Group: 2 bytes, key length: 2 bytes
        short extensionLength = (short) (2 + 1 * keyShareEntryLength);

        ByteBuffer buffer = ByteBuffer.allocate(4 + extensionLength);
        buffer.putShort(TlsConstants.ExtensionType.key_share.value);
        buffer.putShort(extensionLength);  // Extension data length (in bytes)

        buffer.putShort(keyShareEntryLength);
        buffer.putShort(TlsConstants.NamedGroup.secp256r1.value);
        buffer.putShort(rawKeyLength);
        // See https://tools.ietf.org/html/rfc8446#section-4.2.8.2, "For secp256r1, secp384r1, and secp521r1, ..."
        buffer.put((byte) 4);
        byte[] affineX = publicKey.getW().getAffineX().toByteArray();
        if (affineX.length == 33 && affineX[0] == 0) {
            buffer.put(affineX, 1, 32);
        }
        else {
            buffer.put(affineX);
        }
        byte[] affineY = publicKey.getW().getAffineY().toByteArray();
        if (affineY.length == 33) {
            buffer.put(affineY, 1, 32);
        }
        else {
            buffer.put(affineY);
        }

        return buffer.array();
    }

    public byte[] getServerSharedKey() {
        return serverSharedKey;
    }
}
