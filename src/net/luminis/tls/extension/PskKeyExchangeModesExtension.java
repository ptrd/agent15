/*
 * Copyright © 2019, 2020, 2021, 2022 Peter Doornbosch
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
package net.luminis.tls.extension;

import net.luminis.tls.alert.DecodeErrorException;
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
        int extensionDataLength = parseExtensionHeader(buffer, TlsConstants.ExtensionType.psk_key_exchange_modes, 2);
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
