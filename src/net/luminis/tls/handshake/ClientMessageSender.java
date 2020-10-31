package net.luminis.tls.handshake;

import net.luminis.tls.handshake.ClientHello;
import net.luminis.tls.handshake.FinishedMessage;

import java.io.IOException;

public interface ClientMessageSender {

    void send(ClientHello sh) throws IOException;

    void send(FinishedMessage fm) throws IOException;

}
