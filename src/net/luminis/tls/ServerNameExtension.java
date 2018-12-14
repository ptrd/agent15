package net.luminis.tls;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;

public class ServerNameExtension extends Extension {

    private final String serverName;

    public ServerNameExtension(String serverName) {
        this.serverName = serverName;
    }

    @Override
    public byte[] getBytes() {
        short hostnameLength = (short) serverName.length();
        short extensionLength = (short) (hostnameLength + 2 + 1 + 2);

        ByteBuffer buffer = ByteBuffer.allocate(4 + extensionLength);
        buffer.putShort(TlsConstants.ExtensionType.server_name.value);
        buffer.putShort(extensionLength);  // Extension data length (in bytes)

        // https://tools.ietf.org/html/rfc6066#section-3
        buffer.putShort((short) (hostnameLength + 1 + 2));  // Length of server_name_list
        buffer.put((byte) 0x00);  // list entry is type 0x00 "DNS hostname"
        buffer.putShort(hostnameLength);  // Length of hostname
        buffer.put(serverName.getBytes(Charset.forName("ISO-8859-1")));

        return buffer.array();
    }
}
