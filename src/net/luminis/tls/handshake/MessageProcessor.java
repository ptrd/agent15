package net.luminis.tls.handshake;

import net.luminis.tls.TlsProtocolException;

import java.io.IOException;

public interface MessageProcessor {

    void received(ClientHello ch) throws TlsProtocolException, IOException;

    void received(ServerHello sh) throws TlsProtocolException, IOException;

    void received(EncryptedExtensions ee) throws TlsProtocolException, IOException;

    void received(CertificateMessage cm) throws TlsProtocolException, IOException;

    void received(CertificateVerifyMessage cv) throws TlsProtocolException, IOException;

    void received(FinishedMessage fm) throws TlsProtocolException, IOException;

    void received(NewSessionTicketMessage nst) throws TlsProtocolException, IOException;

}

