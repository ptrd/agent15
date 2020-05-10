package net.luminis.tls;

public class IllegalParameterAlert extends TlsProtocolException {

    public IllegalParameterAlert(String message) {
        super(message);
    }
}
