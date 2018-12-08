package net.luminis.tls;

import java.nio.ByteBuffer;

public class SupportedGroupsExtension extends Extension {

    @Override
    byte[] getBytes() {
        TlsConstants.NamedGroup[] namedGroups = new TlsConstants.NamedGroup[] { TlsConstants.NamedGroup.secp256r1 };

        int extensionLength = 2 + namedGroups.length * 2;
        ByteBuffer buffer = ByteBuffer.allocate(4 + extensionLength);
        buffer.putShort(TlsConstants.ExtensionType.supported_groups.value);
        buffer.putShort((short) extensionLength);  // Extension data length (in bytes)

        buffer.putShort((short) (namedGroups.length * 2));
        for (TlsConstants.NamedGroup namedGroup: namedGroups) {
            buffer.putShort(namedGroup.value);
        }

        return buffer.array();
    }
}
