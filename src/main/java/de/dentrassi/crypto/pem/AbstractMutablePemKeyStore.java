/*
 * Copyright (c) 2019 Sergio Moreno and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *    Sergio Moreno - Initial implementation
 *    Jens Reimann - minor cleanups
 */

package de.dentrassi.crypto.pem;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Class that implements a few mutation methods in the keystore.<br>
 * It's abstract to allow to subclasses to choose how have to load its keys and certificates.
 * <p>
 * This is a mutable, but not peristable implementation, of a keystore. It is intended for use cases where an
 * application expects the keystore to be mutable, and so we try to give our best to fulfill this expectation. However
 * we do not implement the "store" methods.
 * </p>
 */
public abstract class AbstractMutablePemKeyStore extends AbstractPemKeyStore {

    @Override
    protected Map<String, Entry> initializeEmpty() {
        return new HashMap<>();
    }

    @Override
    public void engineSetKeyEntry(final String alias, final Key key, final char[] password, final Certificate[] chain)
            throws KeyStoreException {

        Objects.requireNonNull(alias);
        Objects.requireNonNull(key);

        final Entry entry = new Entry(key, chain.clone());
        this.entries.put(alias, entry);

    }

    @Override
    public void engineSetKeyEntry(final String alias, final byte[] key, final Certificate[] chain)
            throws KeyStoreException {

        // Actually we should implement this operaton, but currently we don't

        throw new KeyStoreException("Unsupported operation");

    }

    @Override
    public void engineSetCertificateEntry(final String alias, final Certificate cert) throws KeyStoreException {

        Objects.requireNonNull(alias);
        Objects.requireNonNull(cert);

        final Entry entry = new Entry(null, new Certificate[] { cert });
        this.entries.put(alias, entry);

    }

    @Override
    public void engineDeleteEntry(final String alias) throws KeyStoreException {

        this.entries.remove(alias);

    }

    @Override
    public void engineStore(final OutputStream stream, final char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        throw new IOException("Unsupported operation");
    }

}
