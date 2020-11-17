package net.luminis.tls.handshake;

import net.luminis.tls.TlsProtocolException;

import java.io.IOException;

public interface ServerMessageProcessor extends MessageProcessor {

    default void received(ServerHello sh) throws TlsProtocolException, IOException {
    }

    default void received(EncryptedExtensions ee) throws TlsProtocolException, IOException {
    }

    default void received(CertificateMessage cm) throws TlsProtocolException, IOException {
    }

    default void received(CertificateVerifyMessage cv) throws TlsProtocolException, IOException {
    }

    default void received(NewSessionTicketMessage nst) throws TlsProtocolException, IOException {
    }

}

