package net.luminis.tls;

public class UnexpectedMessageAlert extends TlsProtocolException {

    public UnexpectedMessageAlert(String message) {
        super(message);
    }
}
