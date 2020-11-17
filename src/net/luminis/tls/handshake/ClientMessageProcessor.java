package net.luminis.tls.handshake;


import net.luminis.tls.TlsProtocolException;
import net.luminis.tls.alert.UnexpectedMessageAlert;

public interface ClientMessageProcessor extends MessageProcessor {

    default void received(ClientHello ch) throws TlsProtocolException {
        throw new UnexpectedMessageAlert("no client hello expected");
    }

}
