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

    @Test
    void withoutKeyShareExtensionThereIsNoSelectedGroup() {
        HelloRetryRequest hrr = new HelloRetryRequest(TLS_AES_128_GCM_SHA256, mandatoryExtensions());

        assertThat(hrr.hasKeyShareExtension()).isFalse();
        assertThat(hrr.getSelectedGroup()).isEmpty();
    }

    @Test
    void whenSelectedGroupIsUnknownKeyShareExtensionIsPresentButGroupIsNot() throws Exception {
        // Given: a key share extension selecting group 0x6666, which is not a group this implementation knows.
        String helloRetryRequestRandom = "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C";
        String hrrInHex = ("02 000000  0303 " + helloRetryRequestRandom + "  00  1301   00"
                //  extensions: length supported versions  key share (selected group: 6666)
                + "                    000c   002b00020304        00330002 6666").replaceAll(" ", "");
        byte[] data = setTlsMsgLength(ByteUtils.hexToBytes(hrrInHex));

        // When
        HelloRetryRequest hrr = (HelloRetryRequest) ServerHello.parse(ByteBuffer.wrap(data), data.length);

        // Then: the extension is there, but the group cannot be determined; the client must treat this as a group it
        // did not offer.
        assertThat(hrr.hasKeyShareExtension()).isTrue();
        assertThat(hrr.getSelectedGroup()).isEmpty();
    }

    @Test
    void withoutCookieExtensionThereIsNoCookie() {
        HelloRetryRequest hrr = new HelloRetryRequest(TLS_AES_128_GCM_SHA256, mandatoryExtensions());

        assertThat(hrr.getCookie()).isEmpty();
    }

    private List<Extension> mandatoryExtensions() {
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.4
        // "The server's extensions MUST contain "supported_versions"."
        return List.of(new SupportedVersionsExtension(TlsConstants.HandshakeType.server_hello));
    }

    private byte[] setTlsMsgLength(byte[] messageBytes) {
        int bodyLength = messageBytes.length - 4;
        messageBytes[1] = (byte) (bodyLength >> 16);
        messageBytes[2] = (byte) (bodyLength >> 8);
        messageBytes[3] = (byte) bodyLength;
        return messageBytes;
    }
}
