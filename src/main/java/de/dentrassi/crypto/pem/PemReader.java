/*
 * Copyright (c) 2024 Red Hat Inc and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     Domenico Francesco Bruscino - initial PemReader implementation
 */

package de.dentrassi.crypto.pem;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Reader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import com.hierynomus.asn1.ASN1InputStream;
import com.hierynomus.asn1.ASN1OutputStream;
import com.hierynomus.asn1.encodingrules.der.DERDecoder;
import com.hierynomus.asn1.encodingrules.der.DEREncoder;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.constructed.ASN1Sequence;
import com.hierynomus.asn1.types.constructed.ASN1TaggedObject;
import com.hierynomus.asn1.types.primitive.ASN1Integer;
import com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier;
import com.hierynomus.asn1.types.string.ASN1BitString;
import com.hierynomus.asn1.types.string.ASN1OctetString;

public class PemReader extends BufferedReader {

    private static final String BEGIN = "-----BEGIN ";
    private static final String CERTIFICATE = "CERTIFICATE";
    private static final String X509_CERTIFICATE = "X509 CERTIFICATE";
    private static final String EC_PRIVATE_KEY = "EC PRIVATE KEY";
    private static final String EC_PUBLIC_KEY_OBJ_ID = "1.2.840.10045.2.1";
    private static final String DSA_PRIVATE_KEY = "DSA PRIVATE KEY";
    private static final String RSA_PRIVATE_KEY = "RSA PRIVATE KEY";
    private static final String PRIVATE_KEY = "PRIVATE KEY";
    private static final String END = "-----END ";
    private static final List<String> KEY_ALGORITHMS = Arrays.asList("RSA", "DSA", "EC");

    private static List<KeyFactory> keyFactories;

    private static List<KeyFactory> getKeyFactories() {
        if (keyFactories == null) {
            keyFactories = new ArrayList<>();

            KEY_ALGORITHMS.forEach(s -> {
                try {
                    keyFactories.add(KeyFactory.getInstance(s));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
        }

        return keyFactories;
    }

    public PemReader(Reader in) {
        super(in);
    }

    public Object readObject() throws CertificateException, IOException {
        byte[] objectContent = null;
        String objectType = null;

        String line = readLine();

        while (line != null && !line.startsWith(BEGIN)) {
            line = readLine();
        }

        if (line != null) {
            line = line.substring(BEGIN.length()).trim();
            int index = line.indexOf('-');

            if (index > 0 && line.endsWith("-----") && (line.length() - index) == 5) {
                objectType = line.substring(0, index);

                StringBuffer buffer = new StringBuffer();
                String endMarker = END + objectType + "-----";
                while ((line = readLine()) != null && line.indexOf(endMarker) != 0) {
                    if (line.indexOf(':') < 0) {
                        buffer.append(line.trim());
                    }
                }
                objectContent = Base64.getDecoder().decode(buffer.toString());
            }
        }

        if (objectContent != null) {
            if (CERTIFICATE.equals(objectType) || X509_CERTIFICATE.equals(objectType)) {
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                try (ByteArrayInputStream contentInputStream = new ByteArrayInputStream(objectContent)) {
                    return certificateFactory.generateCertificate(contentInputStream);
                }
            } else if (EC_PRIVATE_KEY.equals(objectType)) {
            /*
            https://datatracker.ietf.org/doc/html/rfc5915
            ECPrivateKey ::= SEQUENCE {
              version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
              privateKey     OCTET STRING,
              parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
              publicKey  [1] BIT STRING OPTIONAL
            }
            */
                try (ASN1InputStream asn1In = new ASN1InputStream(new DERDecoder(), objectContent)) {
                    ASN1Sequence pkcs1Sequence = asn1In.readObject();
                    try (ByteArrayOutputStream pkcs8Out = new ByteArrayOutputStream()) {
                        try (ASN1OutputStream asn1Out = new ASN1OutputStream(new DEREncoder(), pkcs8Out)) {
                            List<ASN1Object> outObjects = new ArrayList<>();
                            outObjects.add(new ASN1Integer(0));
                            outObjects.add(new ASN1Sequence(Arrays.asList(new ASN1ObjectIdentifier(EC_PUBLIC_KEY_OBJ_ID), ((ASN1TaggedObject) pkcs1Sequence.get(2)).getObject())));
                            outObjects.add(new ASN1OctetString(objectContent));
                            asn1Out.writeObject(new ASN1Sequence(outObjects));
                        }

                        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8Out.toByteArray());
                        try {
                            KeyFactory ecKeyFactory = KeyFactory.getInstance("EC");

                            PublicKey ecPublicKey = null;
                            ECPrivateKey ecPrivateKey = (ECPrivateKey) ecKeyFactory.generatePrivate(keySpec);

                            if (pkcs1Sequence.size() > 3) {
                                byte[] ecPointBytes = ((ASN1BitString) ((ASN1TaggedObject) pkcs1Sequence.get(3)).getObject()).getValueBytes();
                                if (ecPointBytes[0] == 4) {
                                    byte[] ecPointXBytes = new byte[32];
                                    byte[] ecPointYBytes = new byte[32];
                                    System.arraycopy(ecPointBytes, 1, ecPointXBytes, 0, 32);
                                    System.arraycopy(ecPointBytes, 33, ecPointYBytes, 0, 32);
                                    ECPoint ecPoint = new ECPoint(new BigInteger(1, ecPointXBytes), new BigInteger(1, ecPointYBytes));
                                    ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecPoint, ecPrivateKey.getParams());
                                    ecPublicKey = ecKeyFactory.generatePublic(publicKeySpec);
                                }
                            }

                            return new KeyPair(ecPublicKey, ecPrivateKey);
                        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                            throw new IOException(e);
                        }
                    }
                }
            } else if (DSA_PRIVATE_KEY.equals(objectType)) {
            /*
            https://datatracker.ietf.org/doc/html/draft-woodhouse-cert-best-practice-01
            DSAPrivateKey ::= SEQUENCE {
                version  INTEGER, -- should be zero
                p        INTEGER,
                q        INTEGER,
                g        INTEGER,
                pub      INTEGER, -- public
                priv     INTEGER, -- private
            }
            */
                try (ASN1InputStream asn1InputStream = new ASN1InputStream(new DERDecoder(), objectContent)) {
                    ASN1Sequence pkcs1Sequence = asn1InputStream.readObject();

                    //BigInteger y, BigInteger p, BigInteger q, BigInteger g)
                    DSAPublicKeySpec publicKeySpec = new DSAPublicKeySpec(((ASN1Integer) pkcs1Sequence.get(4)).getValue(), ((ASN1Integer) pkcs1Sequence.get(1)).getValue(), ((ASN1Integer) pkcs1Sequence.get(2)).getValue(), ((ASN1Integer) pkcs1Sequence.get(3)).getValue());

                    //BigInteger x, BigInteger p, BigInteger q, BigInteger g
                    DSAPrivateKeySpec privateKeySpec = new DSAPrivateKeySpec(((ASN1Integer) pkcs1Sequence.get(5)).getValue(), ((ASN1Integer) pkcs1Sequence.get(1)).getValue(), ((ASN1Integer) pkcs1Sequence.get(2)).getValue(), ((ASN1Integer) pkcs1Sequence.get(3)).getValue());

                    try {
                        KeyFactory dsaKeyFactory = KeyFactory.getInstance("DSA");
                        PublicKey dsaPublicKey = dsaKeyFactory.generatePublic(publicKeySpec);
                        PrivateKey dsaPrivateKey = dsaKeyFactory.generatePrivate(privateKeySpec);
                        return new KeyPair(dsaPublicKey, dsaPrivateKey);
                    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                        throw new IOException(e);
                    }
                }
            } else if (RSA_PRIVATE_KEY.equals(objectType)) {
            /*
            https://datatracker.ietf.org/doc/html/rfc8017
            RSAPrivateKey ::= SEQUENCE {
                version           Version,
                modulus           INTEGER,  -- n
                publicExponent    INTEGER,  -- e
                privateExponent   INTEGER,  -- d
                prime1            INTEGER,  -- p
                prime2            INTEGER,  -- q
                exponent1         INTEGER,  -- d mod (p-1)
                exponent2         INTEGER,  -- d mod (q-1)
                coefficient       INTEGER,  -- (inverse of q) mod p
                otherPrimeInfos   OtherPrimeInfos OPTIONAL
            }
            */
                try (ASN1InputStream asn1InputStream = new ASN1InputStream(new DERDecoder(), objectContent)) {
                    ASN1Sequence pkcs1Sequence = asn1InputStream.readObject();

                    //BigInteger modulus, BigInteger publicExponent
                    RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(((ASN1Integer) pkcs1Sequence.get(1)).getValue(), ((ASN1Integer) pkcs1Sequence.get(2)).getValue());

                    //BigInteger modulus, BigInteger publicExponent, BigInteger privateExponent, BigInteger primeP, BigInteger primeQ, BigInteger primeExponentP, BigInteger primeExponentQ, BigInteger crtCoefficient
                    RSAPrivateCrtKeySpec privateKeySpec = new RSAPrivateCrtKeySpec(((ASN1Integer) pkcs1Sequence.get(1)).getValue(), ((ASN1Integer) pkcs1Sequence.get(2)).getValue(), ((ASN1Integer) pkcs1Sequence.get(3)).getValue(), ((ASN1Integer) pkcs1Sequence.get(4)).getValue(), ((ASN1Integer) pkcs1Sequence.get(5)).getValue(), ((ASN1Integer) pkcs1Sequence.get(6)).getValue(), ((ASN1Integer) pkcs1Sequence.get(7)).getValue(), ((ASN1Integer) pkcs1Sequence.get(8)).getValue());

                    try {
                        KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
                        PublicKey rsaPublicKey = rsaKeyFactory.generatePublic(publicKeySpec);
                        PrivateKey rsaPrivateKey = rsaKeyFactory.generatePrivate(privateKeySpec);
                        return new KeyPair(rsaPublicKey, rsaPrivateKey);
                    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                        throw new IOException(e);
                    }
                }
            } else if (PRIVATE_KEY.equals(objectType)) {
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(objectContent);

                InvalidKeySpecException firstException = null;
                for (KeyFactory factory : getKeyFactories()) {
                    try {
                        return factory.generatePrivate(keySpec);
                    } catch (InvalidKeySpecException e) {
                        if (firstException == null)
                            firstException = e;
                    }
                }
                throw new IOException("Private key could not be loaded", firstException);
            } else {
                throw new IOException("Invalid object: " + objectType);
            }
        }

        return null;
    }
}
