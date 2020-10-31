package net.luminis.tls.alert;

import net.luminis.tls.TlsProtocolException;

public class UnsupportedExtensionAlert extends TlsProtocolException {

    public UnsupportedExtensionAlert(String message) {
        super(message);
    }
}
