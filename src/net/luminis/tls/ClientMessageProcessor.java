package net.luminis.tls;

import java.io.IOException;

public interface ClientMessageProcessor {

    void received(ServerHello sh) throws TlsProtocolException, IOException;

    void received(EncryptedExtensions ee) throws TlsProtocolException, IOException;

    void received(CertificateMessage cm) throws TlsProtocolException, IOException;

    void received(CertificateVerifyMessage cv) throws TlsProtocolException, IOException;

    void received(FinishedMessage fm) throws TlsProtocolException, IOException;

    void received(NewSessionTicketMessage nst) throws TlsProtocolException, IOException;
}
