package net.luminis.tls.alert;

import net.luminis.tls.TlsProtocolException;

public class UnexpectedMessageAlert extends TlsProtocolException {

    public UnexpectedMessageAlert(String message) {
        super(message);
    }
}
