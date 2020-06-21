package net.luminis.tls;

import java.io.IOException;

public interface ClientMessageSender {

    void send(ClientHello sh) throws IOException;

    void send(FinishedMessage fm) throws IOException;

}
