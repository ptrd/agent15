package net.luminis.tls.engine;

import net.luminis.tls.engine.impl.TlsClientEngineImpl;

public class TlsClientEngineFactory {

    public static TlsClientEngine createClientEngine(ClientMessageSender clientMessageSender, TlsStatusEventHandler tlsStatusHandler) {
        return new TlsClientEngineImpl(clientMessageSender, tlsStatusHandler);
    }
}
