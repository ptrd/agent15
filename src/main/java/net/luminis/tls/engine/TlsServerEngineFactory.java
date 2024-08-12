/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024 Peter Doornbosch
 *
 * This file is part of Agent15, an implementation of TLS 1.3 in Java.
 *
 * Agent15 is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Agent15 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package net.luminis.tls.engine;

import net.luminis.tls.TlsConstants;
import net.luminis.tls.compat.InputStreamCompat;
import net.luminis.tls.engine.impl.TlsServerEngineImpl;
import net.luminis.tls.engine.impl.TlsSessionRegistryImpl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.stream.Collectors;

import static net.luminis.tls.TlsConstants.SignatureScheme.*;

public class TlsServerEngineFactory {

    private final List<X509Certificate> certificateChain;
    private final PrivateKey certificateKey;
    private final TlsSessionRegistry tlsSessionRegistry = new TlsSessionRegistryImpl();
    private final List<TlsConstants.SignatureScheme> preferredSignatureSchemes;

    /**
     * Creates a tls server engine factory, given an RSA certificate and its private key.
     * @param certificateFile
     * @param certificateKeyFile
     * @throws IOException
     * @throws CertificateException
     * @throws InvalidKeySpecException
     * @deprecated
     */
    @Deprecated
    public TlsServerEngineFactory(InputStream certificateFile, InputStream certificateKeyFile) throws IOException, CertificateException, InvalidKeySpecException {
        this(readCertificates(certificateFile), readPrivateKey(certificateKeyFile), null);
    }

    /**
     * Creates a tls server engine factory, extracting certificate and private key from the given keystore
     * @param keyStore      keystore containing the server certificate and its private key
     * @param alias         the alias of the certificate
     * @param keyPassword   the password for the private key
     * @throws IOException
     * @throws CertificateException
     * @throws InvalidKeySpecException
     */
    public TlsServerEngineFactory(KeyStore keyStore, String alias, char[] keyPassword) throws IOException, CertificateException, InvalidKeySpecException {
        this(getCertificates(keyStore, alias), getPrivateKey(keyStore, alias, keyPassword), null);
    }

    /**
     * Creates a tls server engine factory, extracting certificate and private key from the given keystore
     * @param keyStore      keystore containing the server certificate and its private key
     * @param alias         the alias of the certificate
     * @param keyPassword   the password for the private key
     * @param ecCurve       the curve name for ECDSA certificates (in case it cannot be derived from the certificate), or null for RSA certificates
     * @throws IOException
     * @throws CertificateException
     * @throws InvalidKeySpecException
     */
    public TlsServerEngineFactory(KeyStore keyStore, String alias, char[] keyPassword, String ecCurve) throws IOException, CertificateException, InvalidKeySpecException {
        this(getCertificates(keyStore, alias), getPrivateKey(keyStore, alias, keyPassword), ecCurve);
    }

    private TlsServerEngineFactory(List<X509Certificate> certificateChain, PrivateKey certificateKey, String ecCurve) throws CertificateException {
        this.certificateChain = certificateChain;
        this.certificateKey = certificateKey;
        preferredSignatureSchemes = preferredSignatureSchemes(certificateChain.get(0), ecCurve);
    }

    private static List<X509Certificate> getCertificates(KeyStore keyStore, String alias) {
        try {
            return Arrays.stream(keyStore.getCertificateChain(alias))
                    .map(c -> (X509Certificate) c)
                    .collect(Collectors.toList());
        }
        catch (KeyStoreException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static PrivateKey getPrivateKey(KeyStore keyStore, String alias, char[] password) {
        try {
            return (PrivateKey) keyStore.getKey(alias, password);
        }
        catch (KeyStoreException | UnrecoverableKeyException e) {
            throw new IllegalArgumentException(e);
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Algorithm not supported", e);
        }
    }

    public TlsServerEngine createServerEngine(ServerMessageSender serverMessageSender, TlsStatusEventHandler tlsStatusHandler) {
        TlsServerEngineImpl tlsServerEngine = new TlsServerEngineImpl(certificateChain, certificateKey, preferredSignatureSchemes, serverMessageSender, tlsStatusHandler, tlsSessionRegistry);
        tlsServerEngine.addSupportedCiphers(List.of(TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256));
        return tlsServerEngine;
    }

    static List<TlsConstants.SignatureScheme> preferredSignatureSchemes(X509Certificate certificate, String ecCurve) throws CertificateException {
        LinkedHashSet<TlsConstants.SignatureScheme> preferred = new LinkedHashSet<>();
        String algorithm = certificate.getPublicKey().getAlgorithm();
        if (algorithm.equals("RSA")) {
            RSAPublicKey rsaPublicKey = (RSAPublicKey) certificate.getPublicKey();
            int keySize = rsaPublicKey.getModulus().bitLength();
            if (keySize <= 2048) {
                preferred.add(rsa_pss_rsae_sha256);
            }
            else if (keySize >= 4096) {
                preferred.add(rsa_pss_rsae_sha512);
            }
            else {
                preferred.add(rsa_pss_rsae_sha384);
            }
            // And add all the others (without duplicates => LinkedHashSet)
            preferred.addAll(List.of(rsa_pss_rsae_sha256, rsa_pss_rsae_sha384, rsa_pss_rsae_sha512));
        }
        else if (algorithm.equals("EC")) {
            String curveName = ecCurve != null? ecCurve: determineCurveName(certificate);
            if (curveName != null) {
                // https://cabforum.org/working-groups/server/baseline-requirements/documents/
                // 7.1.3.2.2 ECDSA:
                // "If the signing key is P‐256, the signature MUST use ECDSA with SHA‐256."
                // "If the signing key is P‐384, the signature MUST use ECDSA with SHA‐384."
                // "If the signing key is P‐521, the signature MUST use ECDSA with SHA‐512."
                switch (curveName) {
                    case "secp256r1":
                        preferred.add(ecdsa_secp256r1_sha256);
                        break;
                    case "secp384r1":
                        preferred.add(ecdsa_secp384r1_sha384);
                        break;
                    case "secp521r1":
                        preferred.add(ecdsa_secp521r1_sha512);
                        break;
                    default:
                        throw new CertificateException("Unsupported EC curve " + curveName);
                }
            }
            else {
                throw new CertificateException("Unable to extract EC curve name from certificate (with public key: " + certificate.getPublicKey() + ")");
            }
        }
        else {
            throw new CertificateException("Unsupported certificate type " + algorithm);
        }
        return new ArrayList(preferred);
    }

    private static String determineCurveName(Certificate certificate) {
        ECPublicKey ecPublicKey = (ECPublicKey) certificate.getPublicKey();
        ECParameterSpec params = ecPublicKey.getParams();
        // Unfortunately, Java does not provide a proper way to get the curve name from the public key.
        // Standard JDK (with standard security providers) emits string representation like
        // "secp256r1 [NIST P-256,X9.62 prime256v1] (1.2.840.10045.3.1.7)", so:
        String paramsContents = params.toString();
        if (paramsContents.contains(" ")) {
            return paramsContents.substring(0, paramsContents.indexOf(" "));
        } else {
            return null;
        }
    }

    private static List<X509Certificate> readCertificates(InputStream file) throws IOException, CertificateException {
        String fileContent = new String(InputStreamCompat.readAllBytes(file), Charset.defaultCharset());
        String[] chunks = fileContent.split("-----END CERTIFICATE-----\n");

        List<X509Certificate> certs = new ArrayList<>();

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        for (int i = 0; i < chunks.length; i++) {
            if (chunks[i].startsWith("-----BEGIN CERTIFICATE-----")) {
                String encodedCertificate = chunks[i]
                        .replace("-----BEGIN CERTIFICATE-----", "")
                        .replaceAll(System.lineSeparator(), "")
                        .replace("-----END CERTIFICATE-----", "");
                Certificate certificate = certificateFactory.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(encodedCertificate)));
                certs.add((X509Certificate) certificate);
            }
        }

        return certs;
    }

    private static RSAPrivateKey readPrivateKey(InputStream file) throws IOException, InvalidKeySpecException {
        String key = new String(InputStreamCompat.readAllBytes(file), Charset.defaultCharset());

        String privateKeyPEM = key
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");
        byte[] encoded = Base64.getMimeDecoder().decode(privateKeyPEM);

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing key algorithm RSA");
        }
    }
}
