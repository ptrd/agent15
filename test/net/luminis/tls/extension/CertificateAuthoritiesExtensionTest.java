/*
 * Copyright © 2021 Peter Doornbosch
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

import javax.security.auth.x500.X500Principal;
import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


class CertificateAuthoritiesExtensionTest {

    @Test
    void parseValidExtension() throws Exception {
        var buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002f001a0018001630143112301006035504030c096c6f63616c686f7374"));

        var extension = new CertificateAuthoritiesExtension(buffer);
        assertThat(extension.getAuthorities()).hasSize(1);
        assertThat(extension.getAuthorities().get(0).equals(new X500Principal("CN=Localhost")));
    }

    @Test
    void serializeExtension() throws Exception {
        var originalExtension = new CertificateAuthoritiesExtension(new X500Principal("CN=Localhost"));
        var parsedExtension = new CertificateAuthoritiesExtension(ByteBuffer.wrap(originalExtension.getBytes()));
        assertThat(parsedExtension.getAuthorities()).hasSize(1);
        assertThat(parsedExtension.getAuthorities().get(0).equals(new X500Principal("CN=Localhost")));
    }

    @Test
    void parseExtensionInconsistentLength1() throws Exception {
        var buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002f00100018001630143112301006035504030c096c6f63616c686f7374"));

        assertThatThrownBy(() ->
                new CertificateAuthoritiesExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseExtensionInconsistentLength2() throws Exception {
        var buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002f001a0018001430143112301006035504030c096c6f63616c686f7374"));

        assertThatThrownBy(() ->
                new CertificateAuthoritiesExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseExtensionInconsistentLength3() throws Exception {
        var buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002f001a0028001630143112301006035504030c096c6f63616c686f7374"));

        assertThatThrownBy(() ->
                new CertificateAuthoritiesExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void possibleNegativeDnLength() throws Exception {
        var buffer = ByteBuffer.wrap(ByteUtils.hexToBytes("002f 001a 0018 f016 30143112301006035504030c096c6f63616c686f7374"));
        assertThatThrownBy(() ->
                new CertificateAuthoritiesExtension(buffer)
        ).isInstanceOf(DecodeErrorException.class);
    }
}