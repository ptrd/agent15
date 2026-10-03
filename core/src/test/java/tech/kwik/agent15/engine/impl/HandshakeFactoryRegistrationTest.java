/*
 * Copyright © 2026 Peter Doornbosch
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
package tech.kwik.agent15.engine.impl;

import org.junit.jupiter.api.Test;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.engine.KeyExchangeFactory;
import tech.kwik.agent15.engine.SignatureAlgorithm;
import tech.kwik.agent15.engine.SignatureAlgorithmFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static tech.kwik.agent15.TlsConstants.NamedGroup.x25519;
import static tech.kwik.agent15.TlsConstants.SignatureScheme.rsa_pss_rsae_sha256;

class HandshakeFactoryRegistrationTest {

    @Test
    void subclassOfCoreSignatureFactoryShouldNotGetCorePriority() {
        // A ServiceLoader-registered subclass must be treated as an extension, not as core, even though it is an
        // "instanceof" the core implementation -- otherwise a provider could shadow the real core implementation
        // for a scheme it doesn't actually come from.
        SignatureAlgorithmFactory subclass = new SignatureAlgorithmFactoryImpl() {
        };

        assertThat(HandshakeFactoryRegistration.priority(subclass))
                .isLessThan(HandshakeFactoryRegistration.priority(new SignatureAlgorithmFactoryImpl()));
    }

    @Test
    void subclassOfCoreKeyExchangeFactoryShouldNotGetCorePriority() {
        KeyExchangeFactory subclass = new KeyExchangeFactoryImpl() {
        };

        assertThat(HandshakeFactoryRegistration.priority(subclass))
                .isLessThan(HandshakeFactoryRegistration.priority(new KeyExchangeFactoryImpl()));
    }

    @Test
    void coreSignatureFactoryShouldWinOverExtensionForSameScheme() {
        SignatureAlgorithmFactory extension = mock(SignatureAlgorithmFactory.class);
        when(extension.getSupportedSignatureSchemes()).thenReturn(List.of(rsa_pss_rsae_sha256));
        when(extension.forSignatureScheme(rsa_pss_rsae_sha256)).thenReturn(mock(SignatureAlgorithm.class));

        Map<TlsConstants.SignatureScheme, SignatureAlgorithmFactory> map = new HashMap<>();
        HandshakeFactoryRegistration.putIfHigherPriority(
                map, rsa_pss_rsae_sha256, extension, HandshakeFactoryRegistration.priority(extension),
                HandshakeFactoryRegistration::priority);
        HandshakeFactoryRegistration.putIfHigherPriority(
                map, rsa_pss_rsae_sha256, new SignatureAlgorithmFactoryImpl(),
                HandshakeFactoryRegistration.priority(new SignatureAlgorithmFactoryImpl()),
                HandshakeFactoryRegistration::priority);

        assertThat(map.get(rsa_pss_rsae_sha256)).isInstanceOf(SignatureAlgorithmFactoryImpl.class);
    }

    @Test
    void extensionSignatureFactoryShouldNotOverrideCoreForSameScheme() {
        Map<TlsConstants.SignatureScheme, SignatureAlgorithmFactory> map = new HashMap<>();
        HandshakeFactoryRegistration.putIfHigherPriority(
                map, rsa_pss_rsae_sha256, new SignatureAlgorithmFactoryImpl(),
                HandshakeFactoryRegistration.priority(new SignatureAlgorithmFactoryImpl()),
                HandshakeFactoryRegistration::priority);

        SignatureAlgorithmFactory extension = mock(SignatureAlgorithmFactory.class);
        HandshakeFactoryRegistration.putIfHigherPriority(
                map, rsa_pss_rsae_sha256, extension, HandshakeFactoryRegistration.priority(extension),
                HandshakeFactoryRegistration::priority);

        assertThat(map.get(rsa_pss_rsae_sha256)).isInstanceOf(SignatureAlgorithmFactoryImpl.class);
    }

    @Test
    void coreKeyExchangeFactoryShouldWinOverExtensionForSameGroup() {
        KeyExchangeFactory extension = mock(KeyExchangeFactory.class);

        Map<TlsConstants.NamedGroup, KeyExchangeFactory> map = new HashMap<>();
        HandshakeFactoryRegistration.putIfHigherPriority(
                map, x25519, extension, HandshakeFactoryRegistration.priority(extension),
                HandshakeFactoryRegistration::priority);
        HandshakeFactoryRegistration.putIfHigherPriority(
                map, x25519, new KeyExchangeFactoryImpl(), HandshakeFactoryRegistration.priority(new KeyExchangeFactoryImpl()),
                HandshakeFactoryRegistration::priority);

        assertThat(map.get(x25519)).isInstanceOf(KeyExchangeFactoryImpl.class);
    }

    @Test
    void extensionKeyExchangeFactoryShouldNotOverrideCoreForSameGroup() {
        Map<TlsConstants.NamedGroup, KeyExchangeFactory> map = new HashMap<>();
        HandshakeFactoryRegistration.putIfHigherPriority(
                map, x25519, new KeyExchangeFactoryImpl(), HandshakeFactoryRegistration.priority(new KeyExchangeFactoryImpl()),
                HandshakeFactoryRegistration::priority);

        KeyExchangeFactory extension = mock(KeyExchangeFactory.class);
        HandshakeFactoryRegistration.putIfHigherPriority(
                map, x25519, extension, HandshakeFactoryRegistration.priority(extension),
                HandshakeFactoryRegistration::priority);

        assertThat(map.get(x25519)).isInstanceOf(KeyExchangeFactoryImpl.class);
    }
}
