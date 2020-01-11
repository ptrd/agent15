package net.luminis.tls.extension;

import net.luminis.tls.TlsConstants;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * The TLS supported groups extension.
 * See https://tools.ietf.org/html/rfc8446#section-4.2.7
 */
public class SupportedGroupsExtension extends Extension {

    private final List<TlsConstants.NamedGroup> namedGroups = new ArrayList<>();

    public SupportedGroupsExtension(TlsConstants.NamedGroup namedGroup) {
        namedGroups.add(namedGroup);
    }

    public SupportedGroupsExtension(ByteBuffer buffer) {
        buffer.getShort();
        int extensionDataLength = buffer.getShort();
        int namedGroupsLength = buffer.getShort();

        for (int i = 0; i < namedGroupsLength; i += 2) {
            int namedGroup = buffer.getShort();
            Arrays.stream(TlsConstants.NamedGroup.values())
                    .filter(item -> item.value == namedGroup)
                    .forEach(group -> namedGroups.add(group));
        }
    }

    @Override
    public byte[] getBytes() {
        int extensionLength = 2 + namedGroups.size() * 2;
        ByteBuffer buffer = ByteBuffer.allocate(4 + extensionLength);
        buffer.putShort(TlsConstants.ExtensionType.supported_groups.value);
        buffer.putShort((short) extensionLength);  // Extension data length (in bytes)

        buffer.putShort((short) (namedGroups.size() * 2));
        for (TlsConstants.NamedGroup namedGroup: namedGroups) {
            buffer.putShort(namedGroup.value);
        }

        return buffer.array();
    }

    @Override
    public String toString() {
        return "SupportedGroupsExtension" + namedGroups;
    }

    public List<TlsConstants.NamedGroup> getNamedGroups() {
        return namedGroups;
    }
}
