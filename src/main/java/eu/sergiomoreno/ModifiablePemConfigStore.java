/*******************************************************************************
 * Copyright (c) 2019 Sergio Moreno.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 *Contributors:
 *		Sergio Moreno - Initial implementation
 *******************************************************************************/

package eu.sergiomoreno;

import java.security.Key;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.util.HashMap;

import de.dentrassi.crypto.pem.PemConfigKeyStore;


public class ModifiablePemConfigStore extends PemConfigKeyStore{
	
	public ModifiablePemConfigStore() {
		super();
		super.entries = new HashMap<>();
	}
	
	
	@Override
    public void engineSetKeyEntry(final String alias, final Key key, final char[] password, final Certificate[] chain)
            throws KeyStoreException {

        final Entry entry = new Entry(key, chain);
        super.entries.put(alias, entry);

    }

}
