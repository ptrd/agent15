package net.luminis.tls.extension;

import net.luminis.tls.DecodeErrorException;
import net.luminis.tls.TlsConstants;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * TLS Pre-Shared Key Exchange Modes extension.
 * See https://tools.ietf.org/html/rfc8446#section-4.2.9
 */
public class PskKeyExchangeModesExtension extends Extension {

    private final List<TlsConstants.PskKeyExchangeMode> keyExchangeModes = new ArrayList<>();

    public PskKeyExchangeModesExtension(TlsConstants.PskKeyExchangeMode keyExchangeMode) {
        keyExchangeModes.add(keyExchangeMode);
    }

    public PskKeyExchangeModesExtension(TlsConstants.PskKeyExchangeMode... keyExchangeModes) {
        for (TlsConstants.PskKeyExchangeMode keyExchangeMode: keyExchangeModes) {
            this.keyExchangeModes.add(keyExchangeMode);
        }
    }

    public PskKeyExchangeModesExtension(ByteBuffer buffer) throws DecodeErrorException {
        int extensionDataLength = parseExtensionHeader(buffer, TlsConstants.ExtensionType.psk_key_exchange_modes);
        int pskKeyExchangeModesLength = buffer.get();
        if (extensionDataLength != 1 + pskKeyExchangeModesLength) {
            throw new DecodeErrorException("inconsistent length");
        }
        for (int i = 0; i < pskKeyExchangeModesLength; i++) {
            int modeByte = buffer.get();
            if (modeByte == TlsConstants.PskKeyExchangeMode.psk_ke.value) {
                keyExchangeModes.add(TlsConstants.PskKeyExchangeMode.psk_ke);
            }
            else if (modeByte == TlsConstants.PskKeyExchangeMode.psk_dhe_ke.value) {
                keyExchangeModes.add(TlsConstants.PskKeyExchangeMode.psk_dhe_ke);
            }
            else {
                throw new DecodeErrorException("invalid psk key exchange mocde");
            }
        }
    }

    @Override
    public byte[] getBytes() {
        short extensionLength = (short) (1 + keyExchangeModes.size());
        ByteBuffer buffer = ByteBuffer.allocate(4 + extensionLength);
        buffer.putShort(TlsConstants.ExtensionType.psk_key_exchange_modes.value);
        buffer.putShort(extensionLength);  // Extension data length (in bytes)

        buffer.put((byte) keyExchangeModes.size());
        keyExchangeModes.forEach(mode -> buffer.put(mode.value));

        return buffer.array();
    }

    public List<TlsConstants.PskKeyExchangeMode> getKeyExchangeModes() {
        return keyExchangeModes;
    }
}
