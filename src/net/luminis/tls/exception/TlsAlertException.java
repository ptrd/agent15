package net.luminis.tls.exception;

import net.luminis.tls.TlsProtocolException;

public class TlsAlertException extends TlsProtocolException {

    public TlsAlertException(String message) {
        super(message);
    }
}
