/*
 * Copyright (c) 2018, 2019 Red Hat Inc and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     Jens Reimann - initial API and implementation
 */

package de.dentrassi.crypto.pem;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Map;

public final class PemKeyStore {

    private PemKeyStore() {
    }

    public final static class Immutable extends AbstractReadOnlyKeyStore {

        @Override
        protected Map<String, Entry> load(final InputStream stream) throws IOException, NoSuchAlgorithmException, CertificateException {
            return PemUtils.loadFrom(stream, true);
        }

    }

    public final static class Mutable extends AbstractMutablePemKeyStore {

        @Override
        protected Map<String, Entry> load(final InputStream stream) throws IOException, NoSuchAlgorithmException, CertificateException {
            return PemUtils.loadFrom(stream, true);
        }

    }

}
