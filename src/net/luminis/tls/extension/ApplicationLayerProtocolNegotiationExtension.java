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

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

public class ApplicationLayerProtocolNegotiationExtension extends Extension {

    private final byte[] data;
    private List<String> protocols;

    public ApplicationLayerProtocolNegotiationExtension() {
        data = null;
    }

    public ApplicationLayerProtocolNegotiationExtension(String protocol) {
        byte[] protocolName = protocol.getBytes(Charset.forName("UTF-8"));
        protocols = List.of(protocol);

        ByteBuffer buffer = ByteBuffer.allocate(7 + protocolName.length);
        buffer.putShort(TlsConstants.ExtensionType.application_layer_protocol_negotiation.value);

        buffer.putShort((byte) (2 + 1 + protocolName.length));
        buffer.putShort((byte) (1 + protocolName.length));
        buffer.put((byte) protocolName.length);
        buffer.put(protocolName);

        data = new byte[buffer.limit()];
        buffer.flip();
        buffer.get(data);
    }

    public ApplicationLayerProtocolNegotiationExtension parse(ByteBuffer buffer) {
        int extensionType = buffer.getShort();
        if (extensionType != TlsConstants.ExtensionType.application_layer_protocol_negotiation.value) {
            throw new RuntimeException();  // Must be programming error
        }

        int extensionLength = buffer.getShort();
        int protocolsLength = buffer.getShort();
        protocols = new ArrayList<>();
        while (protocolsLength > 0) {
            int protocolNameLength = buffer.get() & 0xff;
            byte[] protocolBytes = new byte[protocolNameLength];
            buffer.get(protocolBytes);
            protocols.add(new String(protocolBytes));
            protocolsLength -= (1 + protocolNameLength);
        }

        return this;
    }

    @Override
    public byte[] getBytes() {
        return data;
    }

    public List<String> getProtocols() {
        return protocols;
    }

    @Override
    public String toString() {
        return "AlpnExtension " + protocols;
    }
}
