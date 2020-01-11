package net.luminis.tls.extension;

import net.luminis.tls.ByteUtils;
import net.luminis.tls.TlsConstants;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;


class SupportedGroupsExtensionTest {

    @Test
    void testParseSingleGroup() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("000a000400020017"));

        SupportedGroupsExtension supportedGroupsExtension = new SupportedGroupsExtension(buffer);

        assertThat(supportedGroupsExtension.getNamedGroups()).contains(TlsConstants.NamedGroup.secp256r1);
    }

    @Test
    void testParseMultipleGroups() {
        ByteBuffer buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("000a000800060017001d0100"));

        SupportedGroupsExtension supportedGroupsExtension = new SupportedGroupsExtension(buffer);

        assertThat(supportedGroupsExtension.getNamedGroups())
                .contains(TlsConstants.NamedGroup.secp256r1, TlsConstants.NamedGroup.x25519, TlsConstants.NamedGroup.ffdhe2048);
    }

    @Test
    void testSerializeSingleGroup() {
        ByteBuffer buffer = ByteBuffer.wrap(new SupportedGroupsExtension(TlsConstants.NamedGroup.secp384r1).getBytes());

        SupportedGroupsExtension supportedGroupsExtension = new SupportedGroupsExtension(buffer);

        assertThat(supportedGroupsExtension.getNamedGroups()).contains(TlsConstants.NamedGroup.secp384r1);
    }

}