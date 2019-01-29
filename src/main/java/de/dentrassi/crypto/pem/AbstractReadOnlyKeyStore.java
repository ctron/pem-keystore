/*******************************************************************************
 * Copyright (c) 2018, 2019 Red Hat Inc and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     Jens Reimann - initial API and implementation
 *******************************************************************************/

package de.dentrassi.crypto.pem;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.Map;

/**
 * An abstract implementation of {@link KeyStoreSpi}, implementing only mutating operations as "not supported". <br>
 * This idea behind this implementation, is to provide a base class which implements all operations, which would change
 * the state of the key store, throwing an "unsupported operation". This allows sub-classes of this implementation to
 * focus on implementing the "get" style methods only.
 */
public abstract class AbstractReadOnlyKeyStore extends AbstractPemKeyStore {

    @Override
    protected Map<String, Entry> initializeEmpty() {
        return Collections.emptyMap();
    }

    @Override
    public void engineSetKeyEntry(final String alias, final Key key, final char[] password, final Certificate[] chain)
            throws KeyStoreException {
        throw new KeyStoreException("Unsupported operation");
    }

    @Override
    public void engineSetKeyEntry(final String alias, final byte[] key, final Certificate[] chain)
            throws KeyStoreException {
        throw new KeyStoreException("Unsupported operation");
    }

    @Override
    public void engineSetCertificateEntry(final String alias, final Certificate cert) throws KeyStoreException {
        throw new KeyStoreException("Unsupported operation");
    }

    @Override
    public void engineDeleteEntry(final String alias) throws KeyStoreException {
        throw new KeyStoreException("Unsupported operation");
    }

    @Override
    public void engineStore(final OutputStream stream, final char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException {

        throw new IOException("Unsupported operation");
    }

}
