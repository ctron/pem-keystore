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

package de.dentrassi.crypto.pem;

import java.security.Key;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.util.HashMap;


/**
 * Class that implements {@link #engineSetKeyEntry(String, Key, char[], Certificate[])}.<br/>
 * In its constructor a Map<String,Entry> is created and settled to {@link AbstractPemKeyStore#entries}
 * to make this class mutable. <br/>
 * It's abstract to allow to subclasses to choose how have to load its keys and certificates.
 * 
 * @author Sergio Moreno
 *
 */
public abstract class AbstractMutablePemKeyStore extends AbstractPemKeyStore{
	
	public AbstractMutablePemKeyStore() {
		super();
		this.entries = new HashMap<String,Entry>();
	}
	
	
	@Override
    public void engineSetKeyEntry(final String alias, final Key key, final char[] password, final Certificate[] chain)
            throws KeyStoreException {
        final Entry entry = new Entry(key, chain);
        this.entries.put(alias, entry);
    }

}
