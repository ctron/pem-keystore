/*******************************************************************************
 * Copyright (c) 2019 Red Hat Inc and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     Jens Reimann - initial API and implementation
 *******************************************************************************/
package de.dentrassi.crypto.pem;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;
import java.security.cert.Certificate;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class MutableTest {

    @BeforeAll
    public static void setup() {
        Security.addProvider(new PemKeyStoreProvider());
    }

    @AfterAll
    public static void cleanup() {
        Security.removeProvider("PEM");
    }

    private static KeyStore loadFrom(final String type, final String resourceName) throws Exception {
        try (final InputStream input = MutableTest.class.getResourceAsStream(resourceName)) {
            final KeyStore ks = KeyStore.getInstance(type, "PEM");
            ks.load(input, null);
            return ks;
        }
    }

    /**
     * Test is the key store is read only.
     */
    @Test
    public void testCannotMutate() throws Exception {

        // load a certificate from the first keystore

        final KeyStore ks1 = loadFrom("PEM", "/tls.crt");
        final Certificate cert = ks1.getCertificate("pem");

        // and try adding it to the second

        final KeyStore ks2 = loadFrom("PEM", "/privkey1.pem");

        // which has to fail

        assertThatThrownBy(() -> {
            ks2.setCertificateEntry("cert", cert);
        })
                .isInstanceOf(KeyStoreException.class)
                .hasMessage("Unsupported operation");

    }

    /**
     * Test if a new certificate entry can be added in a mutable keystore.
     */
    @Test
    public void testCanMutate1() throws Exception {

        // load a certificate from the first keystore

        final KeyStore ks1 = loadFrom("PEM", "/tls.crt");
        final Certificate cert = ks1.getCertificate("pem");

        // and try adding it to the second

        final KeyStore ks2 = loadFrom("PEM.MOD", "/privkey1.pem");

        ks2.setCertificateEntry("cert", cert);

        // which has to succeed, and return the expected entry

        final Certificate result = ks2.getCertificate("cert");
        assertEquals(cert, result);

    }

    /**
     * Test if a new certificate entry can be added in an empty, mutable keystore.
     */
    @ParameterizedTest
    @ValueSource(strings = { "PEM.MOD", "PEMCA.MOD", "PEMCFG.MOD" })
    public void testCanMutateEmptyCert(final String type) throws Exception {

        // load a certificate from the first keystore

        final KeyStore ks1 = loadFrom("PEM", "/tls.crt");
        final Certificate cert = ks1.getCertificate("pem");

        // and try adding it to the second

        final KeyStore ks2 = KeyStore.getInstance(type, "PEM");
        ks2.load(null, null);
        ks2.setCertificateEntry("cert", cert);

        // which has to succeed, and return the expected entry

        final Certificate result = ks2.getCertificate("cert");
        assertEquals(cert, result);

    }

    /**
     * Test if a new certificate entry can be added in an empty, mutable keystore.
     */
    @ParameterizedTest
    @ValueSource(strings = { "PEM.MOD", "PEMCA.MOD", "PEMCFG.MOD" })
    public void testCanMutateEmptyKey(final String type) throws Exception {

        // load a key + certificate chain from the first keystore

        final KeyStore ks1 = loadFrom("PEMCFG", "/tls.properties");
        final Key key = ks1.getKey("keycert", null);
        final Certificate[] chain = ks1.getCertificateChain("keycert");

        // and try adding it to the second

        final KeyStore ks2 = KeyStore.getInstance(type, "PEM");
        ks2.load(null, null);
        ks2.setKeyEntry("foo", key, null, chain);

        // which has to succeed, and return the expected entry

        final Key result = ks2.getKey("foo", null);
        assertEquals(key, result);

    }

}
