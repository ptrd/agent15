package net.luminis.tls;

import net.luminis.tls.extension.Extension;

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

    @Override
    public String toString() {
        return "AlpnExtension " + protocols;
    }
}
