# PKCS #1 PEM KeyStore for Java [![Maven Central](https://img.shields.io/maven-central/v/de.dentrassi.crypto/pem-keystore.svg "Maven Central Status")](http://search.maven.org/#search|gav|1|g%3A%22de.dentrassi.crypto%22%20AND%20a%3A%22pem-keystore%22)


Working with PKCS #1 PEM based certificates in Java is an itch. Here is the scratch.

## Adding the dependency

Include the project into your application (e.g. with Maven):

~~~xml
<dependency>
	<groupId>de.dentrassi.crypto</groupId>
	<artifactId>pem-keystore</artifactId>
	<version>2.0.0</version>
</dependency>
~~~

## The security Provider

The projects acts as a Java security provider. Providing only a `KeyStore`
implementation. However you need to make Java aware of the security provider.
There are several ways to do this:

### Via direct invocation

You can manually specify the security provider:

~~~java
KeyStore keyStore = KeyStore.getInstance("PEM", new PemKeyStoreProvider() );
~~~

This way the security provider will only be used for this single call.

### Via manual registration

You can manually register the security provider at the start of your application:

~~~java
Security.addProvider(new PemKeyStoreProvider());
KeyStore keyStore = KeyStore.getInstance("PEM");
~~~

This will make the provider available to the whole application. As this provider
currently is the only provider supporting `PEM` at the moment, the order is not
important. But you can always use `Security.insertProviderAt` instead:

~~~java
Security.insertProviderAt(new PemKeyStoreProvider(), 10);
~~~

### Via configuration

It is also possible to configure the provider in `<JRE>/conf/security/java.security` file.
Also see: https://docs.oracle.com/javase/10/security/howtoimplaprovider.htm#GUID-831AA25F-F702-442D-A2E4-8DA6DEA16F33

## Using it

The basic usage of the PEM KeyStore is:

~~~java
KeyStore keyStore = KeyStore.getInstance("PEM");
try ( InputStream in = … ) {
  keyStore.load ( in, null );
}

// Use X509Certificates from the KeyStore
~~~

But the reality is more complex of course ;-)

### Reading Key/Cert from two files

Sometimes, like when using OpenShift, key and certificate come in two different files.
However the whole "KeyStore" construct is built around the idea that only one file/resource
exists, which stores the information.

For this case, or also for Let's Encrypt, you can use the `PEMCFG` KeyStore type. It is
variation of the `PEM` store and initially loads a Java properties while, which then
points towards the different files to load.

A properties file looks like:

~~~
alias=alias-name
source.key=/etc/tls/tls.key
source.cert=/etc/tls/tls.crt
~~~

The `alias` property defines under which alias the key/cert will be provided. Every
property key starting with `source.` will be used a file system path to load an
additional source. Certificates will be chained together and presented alongside the key.

The remainder of the key, the part after the `source.`, will be ignored.

### Reading a CA bundle

Java keystores can either store one or more certificate chains. Java only uses the tip
of the chain as a trusted certificate. So when you have a PKCS #1 PEM file, it is not clear
if this is a chain of certificates, or a set of root certificates to trust.

By default certificates get chained together when read. However the `PEMCA` Keystore will
store certificates individually:

~~~java
KeyStore keyStore = KeyStore.getInstance("PEMCA");
try ( InputStream in = … ) {
  keyStore.load ( in, null );
}

// Use X509Certificates from the KeyStore
~~~

In this case the alias will be used as a prefix, and the entries will be named `<alias>-#`,
where `#` is an increasing index, starting with `0` (zero).
 
