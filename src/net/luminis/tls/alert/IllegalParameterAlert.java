package net.luminis.tls.alert;

import net.luminis.tls.TlsProtocolException;

public class IllegalParameterAlert extends TlsProtocolException {

    public IllegalParameterAlert(String message) {
        super(message);
    }
}
