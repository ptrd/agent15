package net.luminis.tls;

import java.security.cert.X509Certificate;

public interface HostnameVerifier {

    boolean verify(String hostname, X509Certificate serverCertificate);

}
