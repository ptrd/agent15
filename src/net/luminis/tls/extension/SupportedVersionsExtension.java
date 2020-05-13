package net.luminis.tls.extension;

import net.luminis.tls.DecodeErrorException;
import net.luminis.tls.TlsConstants;
import net.luminis.tls.TlsProtocolException;

import java.nio.ByteBuffer;

/**
 * The TLS supported versions extension.
 * See https://tools.ietf.org/html/rfc8446#section-4.2.1
 */
public class SupportedVersionsExtension extends Extension {

    private final TlsConstants.HandshakeType handshakeType;
    private short tlsVersion;

    public SupportedVersionsExtension(TlsConstants.HandshakeType handshakeType) {
        this.handshakeType = handshakeType;
        tlsVersion = 0x0304;
    }

    public SupportedVersionsExtension(ByteBuffer buffer, TlsConstants.HandshakeType handshakeType) throws TlsProtocolException {
        this.handshakeType = handshakeType;
        int extensionDataLength = parseExtensionHeader(buffer, TlsConstants.ExtensionType.supported_versions);

        if (handshakeType == TlsConstants.HandshakeType.client_hello) {
            int versionsLength = buffer.get() & 0xff;
            if (versionsLength % 2 == 0 && extensionDataLength == versionsLength + 1) {
                for (int i = 0; i < versionsLength; i += 2) {
                    short version = buffer.getShort();
                    // This implementation only supports TLS 1.3, so search for that version.
                    if (version == 0x0304 || tlsVersion == 0)  {
                        tlsVersion = version;
                    }
                }
            }
            else {
                throw new DecodeErrorException("invalid versions length");
            }
        }
        else if (handshakeType == TlsConstants.HandshakeType.server_hello) {
            if (extensionDataLength != 2) {
                throw new DecodeErrorException("Incorrect extension length");
            }
            tlsVersion = buffer.getShort();
        }
        else {
            throw new IllegalArgumentException();
        }
    }

    public byte[] getBytes() {
        ByteBuffer buffer = ByteBuffer.allocate(handshakeType.equals(TlsConstants.HandshakeType.client_hello)? 7: 6);
        buffer.putShort(TlsConstants.ExtensionType.supported_versions.value);

        if (handshakeType.equals(TlsConstants.HandshakeType.client_hello)) {
            buffer.putShort((short) 3);  // Extension data length (in bytes)
            buffer.put((byte) 0x02);     // TLS versions bytes
            buffer.put(new byte[] { (byte) 0x03, (byte) 0x04 });  // TLS 1.3
        }
        else {
            buffer.putShort((short) 2);  // Extension data length (in bytes)
            buffer.put(new byte[] { (byte) 0x03, (byte) 0x04 });  // TLS 1.3
        }

        return buffer.array();
    }

    public short getTlsVersion() {
        return tlsVersion;
    }
}
