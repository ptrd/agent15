package net.luminis.tls.alert;

import net.luminis.tls.TlsConstants;

// https://tools.ietf.org/html/rfc8446#section-6.2
// "bad_certificate:  A certificate was corrupt, contained signatures that did not verify correctly, etc."
public class BadCertificateAlert extends ErrorAlert {

    public BadCertificateAlert(String message) {
        super(message, TlsConstants.AlertDescription.bad_certificate);
    }
}
