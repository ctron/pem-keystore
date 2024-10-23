/*
 * Copyright (c) 2018 Red Hat Inc and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     Jens Reimann - initial API and implementation
 */

package de.dentrassi.crypto.pem;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import de.dentrassi.crypto.pem.AbstractPemKeyStore.Entry;

public class PemUtils {

    private static final String SOURCE_PREFIX = "source.";

    public static Map<String, Entry> loadFrom(final InputStream stream, final boolean chained)
            throws CertificateException, IOException {

        final Map<String, Entry> result = new HashMap<>();

        loadFrom(result, "pem", chained, stream);

        return result;
    }

    public static Map<String, Entry> loadFromConfiguration(final InputStream stream)
            throws CertificateException, IOException {

        final Map<String, Entry> result = new HashMap<>();

        final Properties p = new Properties();
        p.load(stream);

        final String alias = p.getProperty("alias", "pem");

        for (final String key : p.stringPropertyNames()) {
            if (key.startsWith(SOURCE_PREFIX)) {
                try (InputStream source = openResource(p.getProperty(key))) {
                    loadFrom(result, alias, true, source);
                }
            }
        }

        return result;

    }

    private static InputStream openResource(final String uri) throws IOException {
        if (uri.startsWith("classpath:")) {
            return Thread.currentThread().getContextClassLoader().getResourceAsStream(uri.substring(10));
        } else {
            return new FileInputStream(uri.startsWith("file://") ? uri.substring(7) : uri);
        }
    }

    private static void loadFrom(final Map<String, Entry> result, final String alias, final boolean chained,
            final InputStream stream) throws CertificateException, IOException {

        final List<Certificate> chain = new ArrayList<>();
        Key key = null;
        int counter = 0;

        Object object;
        try (PemReader pemReader = new PemReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            while ((object = pemReader.readObject()) != null) {

                if (object instanceof Certificate) {

                    final Certificate cert = (Certificate)object;

                    if (chained) {
                        if (cert instanceof X509Certificate) {
                            chain.add(cert);
                        }
                    } else {
                        result.put(alias + "-" + counter++, new Entry(null, new Certificate[] { cert }));
                    }

                } else if (object instanceof KeyPair) {

                    key = ((KeyPair)object).getPrivate();

                } else if (object instanceof PrivateKey) {

                    key = (PrivateKey)object;

                }
            }
        }

        final Certificate[] certificateChain = chain.isEmpty() ? null
                : chain.toArray(new X509Certificate[chain.size()]);

        final Entry e = new Entry(key, certificateChain);

        result.compute(alias, (k, v) -> {
            if (v != null) {
                return v.merge(e);
            } else {
                return e;
            }
        });

    }
}
