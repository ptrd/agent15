/**
 * Post-quantum cryptography for Agent15:
 * <ul>
 *     <li>the PQ/T hybrid key exchange groups of <a href="https://www.rfc-editor.org/rfc/rfc10024.html">RFC 10024</a>
 *     ({@code X25519MLKEM768}, {@code SecP256r1MLKEM768}, {@code SecP384r1MLKEM1024}), each combining a classical
 *     (EC or XDH) key exchange with ML-KEM (<a href="https://csrc.nist.gov/pubs/fips/203/final">FIPS 203</a>);</li>
 *     <li>the ML-DSA (<a href="https://csrc.nist.gov/pubs/fips/204/final">FIPS 204</a>) signature schemes
 *     ({@code mldsa44}, {@code mldsa65}, {@code mldsa87}).</li>
 * </ul>
 *
 * <p>These use {@code java.security.KEM} and the ML-KEM/ML-DSA key pair generators of the JDK, which is why this
 * module requires Java 25, where core Agent15 needs no more than Java 11.
 *
 * <p>Both are registered as services ({@link tech.kwik.agent15.engine.KeyExchangeFactory} and
 * {@link tech.kwik.agent15.engine.SignatureAlgorithmFactory}), so core Agent15 uses them automatically when this
 * module is present; there is no need to call anything in this module directly.
 */
module tech.kwik.agent15.pqc {

    exports tech.kwik.agent15.pqc;

    requires tech.kwik.agent15;

    provides tech.kwik.agent15.engine.KeyExchangeFactory with tech.kwik.agent15.pqc.HybridKeyExchangeFactory;
    provides tech.kwik.agent15.engine.SignatureAlgorithmFactory with tech.kwik.agent15.pqc.MLDSASignatureAlgorithmFactory;
}
