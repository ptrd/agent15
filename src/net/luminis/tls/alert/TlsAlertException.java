package net.luminis.tls.alert;

import net.luminis.tls.TlsProtocolException;

public class TlsAlertException extends TlsProtocolException {

    public TlsAlertException(String message) {
        super(message);
    }
}
