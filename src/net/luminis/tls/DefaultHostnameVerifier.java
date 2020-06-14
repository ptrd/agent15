package net.luminis.tls;

import java.security.Principal;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * A hostname verifier that requires that the server name equals the CN part of the certificate's subject DN,
 * or matches one of the dnsName-type "Subject Alternative Name" entries of the certificate.
 */
public class DefaultHostnameVerifier implements HostnameVerifier {

    @Override
    public boolean verify(String serverName, X509Certificate serverCertificate) {
        try {
            boolean matchesSan = verifyHostname(serverName, serverCertificate.getSubjectAlternativeNames());
            if (matchesSan) {
                return true;
            }
            else {
                return verifyHostname(serverName, serverCertificate.getSubjectDN());
            }
        } catch (CertificateParsingException e) {
            Logger.debug("Retrieving subject alternative names from certificate failed");
            return false;
        }
    }

    boolean verifyHostname(String serverName, Collection<List<?>> subjectAlternativeNames) {
        if (subjectAlternativeNames == null) {
            return false;
        }

        return subjectAlternativeNames.stream()
                // Each entry is a List whose first entry is an Integer (the name type, 0-8) and whose
                // second entry is a String or a byte array (the name, in string or ASN.1 DER encoded form, respectively).
                .filter(entryList -> entryList.get(0).equals(2))   // 2  is "dNSName"
                .map(entryList -> (String) entryList.get(1))
                .anyMatch(dnsName -> serverNameMatchesDnsName(serverName, dnsName));
    }

    boolean serverNameMatchesDnsName(String serverName, String dnsName) {
        if (serverName == null || dnsName == null || serverName.trim().equals("") || dnsName.trim().equals("")) {
            throw new IllegalArgumentException("can't be null or empty");
        }

        if (dnsName.startsWith("*.")) {
            int firstFullStop = serverName.indexOf(".");
            boolean matchesTrueSubdomain = firstFullStop > 0 && serverName.substring(firstFullStop + 1).equals(dnsName.substring(2));
            boolean matchesFullDomain = serverName.equals(dnsName.substring(2));
            return matchesTrueSubdomain || matchesFullDomain;
        }
        else {
            return serverName.equals(dnsName);
        }
    }

    boolean verifyHostname(String serverName, Principal subjectDN) {
        String dn = subjectDN.getName();
        boolean matches = Arrays.stream(dn.split(","))
                .map(s -> s.trim())
                .filter(s -> s.startsWith("CN="))
                .map(s -> s.replace("CN=", ""))
                .allMatch(s -> s.equals(serverName));
        return matches;
    }
}
