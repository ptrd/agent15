/*
 * Copyright © 2019, 2020, 2021 Peter Doornbosch
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

import net.luminis.tls.TlsConstants;
import net.luminis.tls.extension.Extension;

import java.nio.ByteBuffer;

// https://tools.ietf.org/html/rfc8446#section-4.2.10
public class EarlyDataExtension extends Extension {

    private Long maxEarlyDataSize;

    public Extension parse(ByteBuffer buffer) {
        int extensionType = buffer.getShort();
        if (extensionType != TlsConstants.ExtensionType.early_data.value) {
            throw new RuntimeException();  // Must be programming error
        }

        int extensionLength = buffer.getShort();
        // Only when used in New Session Ticket (message), the EarlyDataIndication value is non-empty.
        if (extensionLength == 4) {
            maxEarlyDataSize = buffer.getInt() & 0xffffffffL;
        }

        return this;
    }

    @Override
    public byte[] getBytes() {
        int extensionDataLength = maxEarlyDataSize == null? 0: 4;
        ByteBuffer buffer = ByteBuffer.allocate(4 + extensionDataLength);
        buffer.putShort(TlsConstants.ExtensionType.early_data.value);
        buffer.putShort((short) extensionDataLength);
        if (maxEarlyDataSize != null) {
            buffer.putInt((int) maxEarlyDataSize.longValue());
        }
        return buffer.array();
    }

    public long getMaxEarlyDataSize() {
        return maxEarlyDataSize;
    }

    @Override
    public String toString() {
        return "EarlyDataExtension " + (maxEarlyDataSize == null? "(empty)": "[" + maxEarlyDataSize + "]");
    }
}
