package net.luminis.tls.extension;

import net.luminis.tls.TlsConstants;
import net.luminis.tls.TlsProtocolException;

import java.nio.ByteBuffer;


@FunctionalInterface
public interface ExtensionParser {

    Extension apply(ByteBuffer byteBuffer, TlsConstants.HandshakeType handshakeType) throws TlsProtocolException;
}

