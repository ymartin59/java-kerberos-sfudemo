# Java 8 Kerberos MS-SFU Demonstration Code

This small Maven Java project demonstrates how to use Kerberos SFU extension
implemented in OpenJDK since version 8.

## Background

Microsoft has implemented Kerberos extension known as MS-SFU in its
ActiveDirectory product to allow impersonation and propose a more secure
alternative to Kerberos V5 delegation, often known as _Kerberos constrained
delegation_.

Reference: https://msdn.microsoft.com/en-us/library/cc246071.aspx

In Java 8, MS-SFU support has been implemented in JGSS API:
https://docs.oracle.com/javase/8/docs/technotes/guides/security/jgss/jgss-features.html

## Deployment example

Suppose your Java code has to access a webservice (REST or SOAP, so over HTTP)
which requires SPNEGO authentication - care to not mismatch with Kerberos V5
HTTP authentication.

The webservice expects the user to authenticate itself with his Kerberos
credentials thanks to a TGS generated from his TGT.

Suppose your Java code has authenticated a visitor thanks to any other
authentication mechanism than Kerberos/SPNEGO, for instance with SAML
assertions, preventing the use of standard Kerberos delegation. The only way
for your code to generate a TGS targetting the webservice on behalf of a
visitor is to use SFU Kerberos extensions, also known as a impersonation and
Kerberos constrained delegation.

## Principle

From the visitor's login, the Java code trusted as a service in ActiveDirectory
has to send `S4U2proxy` command to generate a TGS ticket for the target
webservice SPN on behalf of him.

In Java, JGSS API method `impersonate` is used to create specific GSS
credentials in that purpose. At TGS generation, ActiveDirectory checks for
Kerberos constrained delegation configuration set on the Java service account.

## Deployment

Suppose a webservice is available at `http://webservice-host.domain.ltd` and
requires SPNEGO authentication with SPN `HTTP/webservice-host.domain.ltd` in
realm `DOMAIN.LTD`.

Here is the procedure to create a service account for your Java code:

* Create a standard user account `javaservice` with no password expiration and
   user cannot change password options

* Generate its keytab with command

```
ktpass -princ HTTP/javaservice@DOMAIN.LTD -mapuser DOMAIN\javaservice
 -pass <password> -crypto all -ptype KRB5_NT_PRINCIPAL
 -out C:\Temp\javaservice.keytab
```

* In `javaservice` account properties, grant constrained Kerberos delegation
   to webservice SPN `HTTP/webservice-host.domain.ltd` by looking its
   corresponding service account.

* Copy keytab on your system and edit template `java.login.config`

```
service {
  com.sun.security.auth.module.Krb5LoginModule required
  useKeyTab=true
  storeKey=true
  doNotPrompt=true
  keyTab="/path/to/javaservice.keytab"
  principal="javaservice@DOMAIN.LTD";
};
```

* Simply run `mvn test`

Required system properties to run the code are visible in source code
documentation and in Maven `pom.xml` file. Java 8 with unlimited JCE may be
required if AES-256 is selected at Kerberos JAAS login.

## Credits

This code has been designed from OpenJDK JGSS test cases:
http://cr.openjdk.java.net/~weijun/6355584/webrev.00/test/sun/security/krb5/auto/

Many thanks to Achim Grolms for his [good introduction](http://grolmsnet.de/kerbtut/)
to Kerberos concepts.
