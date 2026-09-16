/*
 * Copyright © 2026 Peter Doornbosch
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
package tech.kwik.agent15.handshake;

import org.junit.jupiter.api.Test;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.extension.CookieExtension;
import tech.kwik.agent15.extension.Extension;
import tech.kwik.agent15.extension.KeyShareExtension;
import tech.kwik.agent15.extension.SupportedVersionsExtension;
import tech.kwik.agent15.util.ByteUtils;

import java.nio.ByteBuffer;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static tech.kwik.agent15.TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256;
import static tech.kwik.agent15.TlsConstants.NamedGroup.x25519;

class HelloRetryRequestTest {

    @Test
    void helloRetryRequestIsSentAsServerHelloMessage() {
        HelloRetryRequest hrr = new HelloRetryRequest(TLS_AES_128_GCM_SHA256, mandatoryExtensions());

        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.4: it has the same format as a ServerHello, and on
        // the wire it is a server_hello message.
        assertThat(hrr.getType()).isEqualTo(TlsConstants.HandshakeType.server_hello);
        assertThat(hrr.getBytes()[0]).isEqualTo(TlsConstants.HandshakeType.server_hello.value);
    }
    
    @Test
    void serializedHelloRetryRequestCanBeParsedBack() throws Exception {
        // Given
        List<Extension> extensions = List.of(
                new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello),
                new KeyShareExtension(x25519),
                new CookieExtension(ByteUtils.hexToBytes("cafebabe")));
        byte[] sessionId = ByteUtils.hexToBytes("0011223344556677");

        // When
        byte[] serialized = new HelloRetryRequest(TLS_AES_128_GCM_SHA256, sessionId, extensions).getBytes();
        HandshakeMessage parsed = ServerHello.parse(ByteBuffer.wrap(serialized), serialized.length);

        // Then
        assertThat(parsed).isInstanceOf(HelloRetryRequest.class);
        HelloRetryRequest hrr = (HelloRetryRequest) parsed;
        assertThat(hrr.getBytes()).isEqualTo(serialized);
        assertThat(hrr.getCipherSuite()).isEqualTo(TLS_AES_128_GCM_SHA256);
        assertThat(hrr.getLegacySessionIdEcho()).isEqualTo(sessionId);
    }

    private List<Extension> mandatoryExtensions() {
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.4
        // "The server's extensions MUST contain "supported_versions"."
        return List.of(new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello));
    }
}
