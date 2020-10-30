package net.luminis.tls;

import net.luminis.tls.extension.Extension;

import java.util.List;

public interface TlsStatusEventHandler {

    void earlySecretsKnown();

    void handshakeSecretsKnown();

    void handshakeFinished();

    void newSessionTicketReceived(NewSessionTicket ticket);

    void extensionsReceived(List<Extension> extensions);
}

