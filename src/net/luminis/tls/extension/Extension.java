package net.luminis.tls.extension;

import net.luminis.tls.alert.DecodeErrorException;
import net.luminis.tls.TlsConstants;

import java.nio.ByteBuffer;

/**
 * A TLS Extension.
 * See https://tools.ietf.org/html/rfc8446#section-4.2
 */
public abstract class Extension {

    protected int parseExtensionHeader(ByteBuffer buffer, TlsConstants.ExtensionType expectedType, int minimumExtensionSize) throws DecodeErrorException {
        return parseExtensionHeader(buffer, expectedType.value, minimumExtensionSize);
    }

    protected int parseExtensionHeader(ByteBuffer buffer, int expectedType, int minimumExtensionSize) throws DecodeErrorException {
        if (buffer.limit() - buffer.position() < 4) {
            throw new DecodeErrorException("extension underflow");
        }
        int extensionType = buffer.getShort() & 0xffff;
        if (extensionType != expectedType) {
            throw new IllegalStateException();  // i.e. programming error
        }
        int extensionDataLength = buffer.getShort();
        if (extensionDataLength < minimumExtensionSize) {
            throw new DecodeErrorException(getClass().getSimpleName() + " can't be less than " + minimumExtensionSize + " bytes");
        }
        if (buffer.limit() - buffer.position() < extensionDataLength) {
            throw new DecodeErrorException("extension underflow");
        }
        return extensionDataLength;
    }


    public abstract byte[] getBytes();
}
