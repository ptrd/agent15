package net.luminis.tls;

import java.nio.ByteBuffer;
import java.security.interfaces.ECPublicKey;

// https://tools.ietf.org/html/rfc8446#section-4.2.8
public class KeyShareExtension extends Extension {

    private final ECPublicKey publicKey;
    private final String ecCurve;

    public KeyShareExtension(ECPublicKey publicKey, String ecCurve) {
        this.publicKey = publicKey;
        this.ecCurve = ecCurve;
        if (ecCurve != "secp256r1")
            throw new RuntimeException("Only secp256r1 is supported");
    }

    @Override
    byte[] getBytes() {
        short rawKeyLength = 65;
        short keyShareEntryLength = (short) (2 + 2 + rawKeyLength);   // Named Group: 2 bytes
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
}
