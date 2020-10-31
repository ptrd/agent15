package net.luminis.tls.alert;

import net.luminis.tls.TlsProtocolException;

public class DecryptErrorAlert extends TlsProtocolException {

    public DecryptErrorAlert(String message) {
        super(message);
    }
}
