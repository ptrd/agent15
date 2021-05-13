package net.luminis.tls.handshake;

import java.io.IOException;

public interface ServerMessageSender {

    void send(ServerHello sh) throws IOException;

    void send(EncryptedExtensions ee) throws IOException;

    void send(CertificateMessage cm) throws IOException;

    void send(CertificateVerifyMessage cv) throws IOException;

    void send(FinishedMessage finished) throws IOException;
}

