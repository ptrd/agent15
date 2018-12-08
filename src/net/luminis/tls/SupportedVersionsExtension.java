package net.luminis.tls;


import java.nio.ByteBuffer;

public class SupportedVersionsExtension extends Extension {

    public SupportedVersionsExtension() {
    }

    public byte[] getBytes() {
        ByteBuffer buffer = ByteBuffer.allocate(7);
        buffer.putShort(TlsConstants.ExtensionType.supported_versions.value);
        buffer.putShort((short) 3);  // Extension data length (in bytes)
        buffer.put((byte) 0x02);     // TLS versions bytes
        buffer.put(new byte[] { (byte) 0x03, (byte) 0x04 });  // TLS 1.3

        return buffer.array();
    }
}
