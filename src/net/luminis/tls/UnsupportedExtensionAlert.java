package net.luminis.tls;

public class UnsupportedExtensionAlert extends TlsProtocolException {

    public UnsupportedExtensionAlert(String message) {
        super(message);
    }
}
