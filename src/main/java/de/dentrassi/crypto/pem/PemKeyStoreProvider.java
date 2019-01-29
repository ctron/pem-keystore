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

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

public class PemKeyStoreProvider extends Provider {

    private static final long serialVersionUID = 1L;

    public PemKeyStoreProvider() {
        super("PEM", 1, "Provides PEM based KeyStores");
        setup();
    }

    private void setup() {
        AccessController.doPrivileged(new PrivilegedAction<Void>() {

            @Override
            public Void run() {
                performSetup();
                return null;
            }
        });
    }

    private void performSetup() {
        put("KeyStore.PEM", "de.dentrassi.crypto.pem.PemKeyStore$Immutable");
        put("KeyStore.PEM.MOD", "de.dentrassi.crypto.pem.PemKeyStore$Mutable");

        put("KeyStore.PEMCFG", "de.dentrassi.crypto.pem.PemConfigKeyStore$Immutable");
        put("KeyStore.PEMCFG.MOD", "de.dentrassi.crypto.pem.PemConfigKeyStore$Mutable");

        put("KeyStore.PEMCA", "de.dentrassi.crypto.pem.PemBundleKeyStore$Immutable");
        put("KeyStore.PEMCA.MOD", "de.dentrassi.crypto.pem.PemBundleKeyStore$Mutable");

    }
}
