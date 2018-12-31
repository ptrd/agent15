package net.luminis.tls;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;

public class ApplicationLayerProtocolNegotiationExtension extends Extension {

    private final byte[] data;

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

    @Override
    public byte[] getBytes() {
        return data;
    }
}
