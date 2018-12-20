/*******************************************************************************
 * Copyright (c) 2018 Red Hat Inc and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     Jens Reimann - initial API and implementation
 *******************************************************************************/
package de.dentrassi.crypto.pem;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class PemConfigKeyStoreTest {

    @BeforeAll
    public static void setup() {
        Security.addProvider(new PemKeyStoreProvider());
    }

    @AfterAll
    public static void cleanup() {
        Security.removeProvider("PEM");
    }

    @Test
    public void test1() throws Exception {

        final KeyStore ks = KeyStore.getInstance("PEMCFG");
        try (FileInputStream stream = new FileInputStream(new File("src/test/resources/tls.properties"))) {
            ks.load(stream, new char[0]);
        }

        final Certificate[] chain = ks.getCertificateChain("keycert");
        final Certificate cert = ks.getCertificate("keycert");
        final Key key = ks.getKey("keycert", new char[0]);

        assertNotNull(chain);
        assertEquals(2, chain.length);

        assertNotNull(cert);
        assertNotNull(key);

    }
}
