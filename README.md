# Java 8 Kerberos MS-SFU Demonstration Code

This small Maven Java project demonstrates how to use Kerberos SFU extension
implemented in OpenJDK since version 8.

## Background

Microsoft has implemented Kerberos extension known as _Kerberos constrained
delegation_ (MS-SFU) in its ActiveDirectory product to allow impersonation and
propose a more secure alternative to Kerberos V5 delegation.

Reference documentation: https://msdn.microsoft.com/en-us/library/cc246071.aspx

[The protocol overview](https://msdn.microsoft.com/en-us/library/cc246080.aspx)
compares MS-SFU delegation with Kerberos V5 delegation. MS-SFU grants
confidentiality for user's TGT credentials.

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

From the visitor's login name, the Java code trusted as a service in
ActiveDirectory uses `S4U2self` message to get a service ticket (TGS) for the
visitor. This process is also known as protocol transition.

In Java, JGSS API method `impersonate` is used to create specific GSS
credentials in that purpose. At TGS generation, ActiveDirectory checks for
Kerberos constrained delegation configuration set on the Java service account.

Thanks to this service ticket, code uses `S4U2proxy` message to generate a TGS
ticket for the target webservice SPN on behalf of the visitor.

## Use case

Suppose a webservice is available at `http://webservice-host.domain.ltd` and
requires SPNEGO authentication with SPN `HTTP/webservice-host.domain.ltd` in
realm `DOMAIN.LTD`.

Accord to Kerberos RFC, based on URI, a client (a browser) has to do a DNS
lookup from hostname and a reverse-DNS lookup to create SPN using a FQDN.

Here, the SPN `HTTP/webservice-host.domain.ltd` is supposed to be
canonicalized.

If a DNS alias and virtual host is defined for your service, you should apply
hostname canonicalization, this demonstration code does not.

## Deployment

Here is the procedure to create a service account for your Java code:

* Create a standard user account `javaservice` with no password expiration and
   user cannot change password options

* Generate its keytab with command

```
ktpass -princ HTTP/javaservice@DOMAIN.LTD -mapuser DOMAIN\javaservice
 -pass <password> -crypto all -ptype KRB5_NT_PRINCIPAL
 -out C:\Temp\javaservice.keytab
```

* In `javaservice` account properties, grant constrained Kerberos delegation to
   webservice canonicalized SPN `HTTP/webservice-host.domain.ltd` by looking
   its corresponding service account.

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

* Edit POM file to set target service SPN and a user login to test with
* Simply run `mvn test`

Required system properties to run the code are visible in source code
documentation and in Maven `pom.xml` file. Java 8 with unlimited JCE may be
required if AES-256 is selected at Kerberos JAAS login.

## Credits

This code has been designed from OpenJDK JGSS test cases:
http://cr.openjdk.java.net/~weijun/6355584/webrev.00/test/sun/security/krb5/auto/

Many thanks to Achim Grolms for his [good introduction](http://grolmsnet.de/kerbtut/)
to Kerberos concepts.
