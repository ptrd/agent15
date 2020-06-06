package net.luminis.tls;

public class DecryptErrorAlert extends TlsProtocolException {

    public DecryptErrorAlert(String message) {
        super(message);
    }
}
