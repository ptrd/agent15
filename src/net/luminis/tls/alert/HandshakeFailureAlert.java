package net.luminis.tls.alert;

import net.luminis.tls.TlsProtocolException;

public class HandshakeFailureAlert extends TlsProtocolException {

    public HandshakeFailureAlert(String message) {
        super(message);
    }
}

