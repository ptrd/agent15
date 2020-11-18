package net.luminis.tls.alert;

import net.luminis.tls.TlsConstants;

/**
 * https://tools.ietf.org/html/rfc8446#section-6.2
 * "certificate_unknown:  Some other (unspecified) issue arose in processing the certificate, rendering it unacceptable."
 */
public class CertificateUnknownAlert extends ErrorAlert {

    public CertificateUnknownAlert(String message) {
        super(message, TlsConstants.AlertDescription.certificate_unknown);
    }
}
