/**
 * The post-quantum/traditional hybrid key exchange groups of
 * <a href="https://www.rfc-editor.org/rfc/rfc10024.html">RFC 10024</a> for Agent15: {@code X25519MLKEM768},
 * {@code SecP256r1MLKEM768} and {@code SecP384r1MLKEM1024}, each combining a classical (EC or XDH) key exchange with
 * ML-KEM (<a href="https://csrc.nist.gov/pubs/fips/203/final">FIPS 203</a>).
 *
 * <p>These use {@code java.security.KEM} and the ML-KEM key pair generator of the JDK, which is why this module
 * requires Java 25, where core Agent15 needs no more than Java 11.
 *
 * <p>The groups are registered as a {@link tech.kwik.agent15.engine.KeyExchangeFactory} service, so core Agent15 uses
 * them automatically when this module is present; there is no need to call anything in this module directly.
 */
module tech.kwik.agent15.pqc {

    exports tech.kwik.agent15.pqc;

    requires tech.kwik.agent15;

    provides tech.kwik.agent15.engine.KeyExchangeFactory with tech.kwik.agent15.pqc.HybridKeyExchangeFactory;
}
