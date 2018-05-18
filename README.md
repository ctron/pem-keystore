# PEM KeyStore for Java

Working with PEM based certificates in Java is an itch. Here is the scratch.

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

## Adding the dependency

Include the project into your application (e.g. with Maven):

~~~xml
<dependency>
	<groupId>de.dentrassi.crypto</groupId>
	<artifactId>pem-keystore</artifactId>
	<version>1.0.0</version>
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
