package net.luminis.tls;

// https://tools.ietf.org/html/rfc8446#section-6.2
// "bad_certificate:  A certificate was corrupt, contained signatures that did not verify correctly, etc."
public class BadCertificateAlert extends TlsProtocolException {

    public BadCertificateAlert(String message) {
        super(message);
    }
}
