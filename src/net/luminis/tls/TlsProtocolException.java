package net.luminis.tls;

public class TlsProtocolException extends Exception {

    public TlsProtocolException(String message) {
        super(message);
    }

    public TlsProtocolException(String message, Throwable cause) {
        super(message, cause);
    }
}
