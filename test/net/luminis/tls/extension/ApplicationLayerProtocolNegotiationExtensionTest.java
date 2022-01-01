/*
 * Copyright © 2021, 2022 Peter Doornbosch
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
import net.luminis.tls.util.ByteUtils;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


class ApplicationLayerProtocolNegotiationExtensionTest {

    @Test
    void serializeALPNExtensionSingleProtocol() throws Exception {
        var extension = new ApplicationLayerProtocolNegotiationExtension("http/1.1");
        assertThat(extension.getBytes()).isEqualTo(ByteUtils.hexToBytes("0010 000b 0009 08 68 74 74 70 2f 31 2e 31"));
    }

    @Test
    void serializeALPNExtensionMultipleProtocols() throws Exception {
        var extension = new ApplicationLayerProtocolNegotiationExtension(List.of("h2", "http/1.1"));
        assertThat(extension.getBytes()).isEqualTo(ByteUtils.hexToBytes("0010 000e 000c 02 68 32 08 68 74 74 70 2f 31 2e 31"));
    }

    @Test
    void parseALPNExtensionSingleProtocol() throws Exception {
        var data = ByteUtils.hexToBytes("0010 000b 0009 08 68 74 74 70 2f 31 2e 31");
        var extension = new ApplicationLayerProtocolNegotiationExtension(ByteBuffer.wrap(data));

        assertThat(extension.getProtocols()).contains("http/1.1");
    }

    @Test
    void parseALPNExtensionMultipleProtocols() throws Exception {
        var data = ByteUtils.hexToBytes("0010 000e 000c 02 68 32 08 68 74 74 70 2f 31 2e 31");
        var extension = new ApplicationLayerProtocolNegotiationExtension(ByteBuffer.wrap(data));

        assertThat(extension.getProtocols()).contains("http/1.1", "h2");
    }

    @Test
    void parseInconsistentLengthsShouldThrow() throws Exception {
        var data = ByteUtils.hexToBytes("0010 000b 000a 08 68 74 74 70 2f 31 2e 31 31");

        assertThatThrownBy(() ->
                new ApplicationLayerProtocolNegotiationExtension(ByteBuffer.wrap(data))
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseInconsistentLengthsShouldThrow2() throws Exception {
        var data = ByteUtils.hexToBytes("0010 000b 0009 09 68 74 74 70 2f 31 2e 31");

        assertThatThrownBy(() ->
                new ApplicationLayerProtocolNegotiationExtension(ByteBuffer.wrap(data))
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseInconsistentLengthsShouldThrow3() throws Exception {
        var data = ByteUtils.hexToBytes("0010 000e 000c 02 68 32 09 68 74 74 70 2f 31 2e 31");

        assertThatThrownBy(() ->
                new ApplicationLayerProtocolNegotiationExtension(ByteBuffer.wrap(data))
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseInconsistentLengthsShouldThrow4() throws Exception {
        var data = ByteUtils.hexToBytes("0010 000b 0009 07 68 74 74 70 2f 31 2e 31");

        assertThatThrownBy(() ->
                new ApplicationLayerProtocolNegotiationExtension(ByteBuffer.wrap(data))
        ).isInstanceOf(DecodeErrorException.class);
    }
}