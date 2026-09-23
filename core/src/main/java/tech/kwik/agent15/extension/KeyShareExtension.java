/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
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
package tech.kwik.agent15.extension;

import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.TlsProtocolException;
import tech.kwik.agent15.alert.DecodeErrorException;

import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static tech.kwik.agent15.TlsConstants.NamedGroup.secp256r1;
import static tech.kwik.agent15.TlsConstants.NamedGroup.x25519;

/**
 * The TLS "key_share" extension contains the endpoint's cryptographic parameters.
 * See https://tools.ietf.org/html/rfc8446#section-4.2.8
 */
public class KeyShareExtension extends Extension {

    public static final List<TlsConstants.NamedGroup> supportedCurves = List.of(secp256r1, x25519);

    private TlsConstants.HandshakeType handshakeType;
    private List<KeyShareEntry> keyShareEntries = new ArrayList<>();


    public KeyShareExtension(byte[] keyExchangeData, TlsConstants.NamedGroup ecCurve, TlsConstants.HandshakeType handshakeType) {
        keyShareEntries.add(new KeyShareEntry(ecCurve, keyExchangeData));
        this.handshakeType = handshakeType;
    }

    public KeyShareExtension(ByteBuffer buffer, TlsConstants.HandshakeType handshakeType) throws TlsProtocolException {
        this(buffer, handshakeType, false);
    }

    public KeyShareExtension(ByteBuffer buffer, TlsConstants.HandshakeType handshakeType, boolean helloRetryRequestType) throws TlsProtocolException {
        int extensionDataLength = parseExtensionHeader(buffer, TlsConstants.ExtensionType.key_share, 1);
        if (extensionDataLength < 2) {
            throw new DecodeErrorException("extension underflow");
        }

        if (handshakeType == TlsConstants.HandshakeType.client_hello) {
            int keyShareEntriesSize = buffer.getShort()& 0xffff;
            if (extensionDataLength != 2 + keyShareEntriesSize) {
                throw new DecodeErrorException("inconsistent length");
            }
            int remaining = keyShareEntriesSize;
            while (remaining > 0) {
                remaining -= parseKeyShareEntry(buffer, helloRetryRequestType);
            }
            if (remaining != 0) {
                throw new DecodeErrorException("inconsistent length");
            }
        }
        else if (handshakeType == TlsConstants.HandshakeType.server_hello) {
            int remaining = extensionDataLength;
            remaining -= parseKeyShareEntry(buffer, helloRetryRequestType);
            if (remaining != 0) {
                throw new DecodeErrorException("inconsistent length");
            }
        }
        else {
            throw new IllegalArgumentException();
        }
    }

    protected int parseKeyShareEntry(ByteBuffer buffer, boolean namedGroupOnly) throws TlsProtocolException {
        int startPosition = buffer.position();
        if (namedGroupOnly && buffer.remaining() < 2 || !namedGroupOnly && buffer.remaining() < 4 ) {
            throw new DecodeErrorException("extension underflow");
        }

        Optional<TlsConstants.NamedGroup> recognizedNamedGroup = TlsConstants.decodeNamedGroup(buffer.getShort());

        if (namedGroupOnly) {
            recognizedNamedGroup.ifPresent(namedGroup -> keyShareEntries.add(new KeyShareEntry(namedGroup, null)));
        }
        else {
            int keyLength = buffer.getShort() & 0xffff;
            if (buffer.remaining() < keyLength) {
                throw new DecodeErrorException("extension underflow");
            }
            if (recognizedNamedGroup.isPresent()) {
                // Whether the key exchange data is valid for the given group, is up to the key exchange implementation.
                byte[] keyExchangeData = new byte[keyLength];
                buffer.get(keyExchangeData);
                keyShareEntries.add(new KeyShareEntry(recognizedNamedGroup.get(), keyExchangeData));
            }
            else {
                buffer.get(new byte[keyLength]);
            }
        }
        return buffer.position() - startPosition;
    }

    @Override
    public byte[] getBytes() {
        int keyShareEntryLength = keyShareEntries.stream()
                .mapToInt(ks -> 2 + 2 + ks.getKeyExchangeData().length)  // Named Group: 2 bytes, key length: 2 bytes
                .sum();
        int extensionLength = keyShareEntryLength;
        if (handshakeType == TlsConstants.HandshakeType.client_hello) {
            extensionLength += 2;
        }

        ByteBuffer buffer = ByteBuffer.allocate(4 + extensionLength);
        buffer.putShort(TlsConstants.ExtensionType.key_share.value);
        buffer.putShort((short) extensionLength);  // Extension data length (in bytes)

        if (handshakeType == TlsConstants.HandshakeType.client_hello) {
            buffer.putShort((short) keyShareEntryLength);
        }

        for (KeyShareEntry keyShare: keyShareEntries) {
            buffer.putShort(keyShare.getNamedGroup().value);
            byte[] keyExchangeData = keyShare.getKeyExchangeData();
            buffer.putShort((short) keyExchangeData.length);
            buffer.put(keyExchangeData);
        }

        return buffer.array();
    }

    public List<KeyShareEntry> getKeyShareEntries() {
        return keyShareEntries;
    }

    public static class KeyShareEntry {
        private TlsConstants.NamedGroup namedGroup;
        private final byte[] rawKey;

        public KeyShareEntry(TlsConstants.NamedGroup namedGroup, byte[] keyExchangeData) {
            this.namedGroup = namedGroup;
            this.rawKey = keyExchangeData;
        }

        public TlsConstants.NamedGroup getNamedGroup() {
            return namedGroup;
        }

        public byte[] getKeyExchangeData() {
            return rawKey;
        }

        public PublicKey getKey() {
            // TODO: remove
            return null;
        }
    }

    @Override
    public int getType() {
        return TlsConstants.ExtensionType.key_share.value;
    }
}
