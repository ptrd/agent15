package net.luminis.tls;

import java.nio.ByteBuffer;

public class PskKeyExchangeModesExtension extends Extension {

    @Override
    byte[] getBytes() {
        short extensionLength = 2;
        ByteBuffer buffer = ByteBuffer.allocate(4 + extensionLength);
        buffer.putShort(TlsConstants.ExtensionType.psk_key_exchange_modes.value);
        buffer.putShort(extensionLength);  // Extension data length (in bytes)

        buffer.put((byte) 1);  // 1 byte follows
        buffer.put(TlsConstants.PskKeyExchangeMode.psk_dhe_ke.value);

        return buffer.array();
    }
}
