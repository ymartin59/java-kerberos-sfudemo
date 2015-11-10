/**
 * Demonstration usage of Kerberos MS-SFU extension with Java 8.
 * Runs with stock Oracle Java 8 runtime. No other dependencies required.
 *
 * Required properties before LoginContext initialization, may be set
 * on command line or at runtime:
 * java.security.auth.login.config=/path/to/java.login.config
 * javax.security.auth.useSubjectCredsOnly=false
 *
 * File content example for "/path/to/java.login.config":

service {
  com.sun.security.auth.module.Krb5LoginModule required
  useKeyTab=true
  storeKey=true
  doNotPrompt=true
  keyTab="/path/to/servicelogin-account.keytab"
  principal="servicelogin@DOMAIN.LTD";
};

 * For debug purpose only, the following properties should be enabled:
 * -Dsun.security.krb5.debug=true -Dsun.security.jgss.debug=true
 *
 * @author Yves Martin
 */
package sfudemo;

import java.io.IOException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Base64;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import com.sun.security.jgss.ExtendedGSSContext;
import com.sun.security.jgss.ExtendedGSSCredential;

/**
 * Kerberos S4U2self demonstration test case.
 *
 * 1. Do initial JAAS login as "servicelogin" with Kerberos LoginContext set in
 * java.login.conf and keytab
 * 2. Generate GSS credential for target user to impersonate
 * 3. Generate SPNEGO token for target service on behalf of target user
 *
 */
public class KerberosDemo {

    /**
     * Re-usable service Subject obtained by Kerberbos LoginContext
     * configured with java.login.conf
     */
    Subject serviceSubject;
    /** Re-usable service GSSCredentials in initiator only mode. */
    GSSCredential serviceCredentials;

    /**
     * Required class to handle user/password authentication,
     * even if it is useless when keytab is defined in login.conf
     */
    class UserPasswordCallbackHandler implements CallbackHandler {
        private String username;
        private String password;

        public UserPasswordCallbackHandler(String u, String p) {
            this.username = u;
            this.password = p;
        }

        public void handle(Callback[] callbacks)
            throws IOException, UnsupportedCallbackException {
            for (int i = 0; i < callbacks.length; i++) {
                if (callbacks[i] instanceof NameCallback) {
                    NameCallback nc = (NameCallback)callbacks[i];
                    nc.setName(username);
                } else if (callbacks[i] instanceof PasswordCallback) {
                    PasswordCallback pc = (PasswordCallback)callbacks[i];
                    pc.setPassword(password.toCharArray());
                } else throw new UnsupportedCallbackException
                           (callbacks[i], "Unrecognised callback");
            }
        }
    }

    /**
     * Process JAAS login.
     * @throws LoginException
     */
    public Subject doInitialLogin() throws LoginException {
        // PasswordCallbackHandler is only useful if login.config keytab is out of order (no not provide login/password here)
        LoginContext lc = new LoginContext("service", new UserPasswordCallbackHandler("servicelogin","servicepassword"));
        lc.login();
        serviceSubject = lc.getSubject();
        return lc.getSubject();
    }


    /**
     * Generate target user credentials thanks to S4U2self mechanism.
     *
     * @param someone target user
     * @return target user GSS credentials
     * @throws Exception if impersonation is not allowed for servicelogin
     */
    public GSSCredential impersonate(final String someone) throws Exception {
        try {
            GSSCredential creds = Subject.doAs(this.serviceSubject, new PrivilegedExceptionAction<GSSCredential>() {
	            public GSSCredential run() throws Exception {
	                GSSManager manager = GSSManager.getInstance();
	                if (serviceCredentials == null) {
                            serviceCredentials = manager.createCredential(GSSCredential.INITIATE_ONLY);
	                }
	                GSSName other = manager.createName(someone, GSSName.NT_USER_NAME);
	                return ((ExtendedGSSCredential)serviceCredentials).impersonate(other);
	                // return serviceCredentials; // alternative to skip impersonation (as intermediate test)
	            }
	        });
            return creds;
        } catch (PrivilegedActionException pae) {
            throw pae.getException();
        }
    }

    /**
     * Obtains a service context for a target SPN.
     *
     * @param target SPN to get context and token for
     * @param userCredentials target user credentials
     * @param mech GSS mech
     * @throws Exception in case of failure
     */
    public ExtendedGSSContext startAsClient(final String target,
                                            final GSSCredential userCredentials,
                                            final Oid mech)
        throws Exception {
        ExtendedGSSContext context =
            Subject.doAs(this.serviceSubject, new PrivilegedExceptionAction<ExtendedGSSContext>() {
                    public ExtendedGSSContext run() throws Exception {
                        GSSManager manager = GSSManager.getInstance();
                        ExtendedGSSContext extendedContext =
                            (ExtendedGSSContext) manager.createContext(manager.createName(target, null),
                                                                       mech,
                                                                       userCredentials,
                                                                       GSSContext.DEFAULT_LIFETIME);
                        extendedContext.requestMutualAuth(true);
                        extendedContext.requestConf(true);
                        return extendedContext;
                    }
                });
        return context;
    }

    /**
     * Generate a context and TGS token for a target user
     *
     * @param targetUserName user to impersonate
     * @param targetService target service SPN
     * @return Base64 token
     * @throws Exception many thinks may fail
     */
    public String generateToken(String targetUserName, String targetService) throws Exception {
        final Oid SPNEGO_OID = new Oid("1.3.6.1.5.5.2");

        // Get impersonated user credentials
        GSSCredential impersonatedUserCreds = impersonate(targetUserName);
        System.out.println("Credentials for " + targetUserName + ": " + impersonatedUserCreds);

        // Create context for target service
        ExtendedGSSContext context = startAsClient(targetService, impersonatedUserCreds, SPNEGO_OID);
        final byte[] token = context.initSecContext(new byte[0], 0, 0);
        System.out.println("Context srcName " + context.getSrcName());
        System.out.println("Context targName " + context.getTargName());

        final String result = Base64.getEncoder().encodeToString(token);
        System.out.println("Token " + Base64.getEncoder().encodeToString(token));

        // Free context
        context.dispose();
        // Free impersonated user credentials
        impersonatedUserCreds.dispose();

        return result;
    }

    /** Expected argument: target user name and target SVN. */
    public static void main(String[] args) {
        try {
            KerberosDemo test = new KerberosDemo();
            System.out.println("Service subject: " + test.doInitialLogin());

            String targetUserName = "undef";
            String targetSPN = "HTTP/webservice-host.domain.ltd";
            if (args.length == 2) {
                targetUserName = args[0];
                targetSPN = args[1];
            } else {
                System.err.println("Usage: userToImpersonate targetSPN");
                System.exit(1);
            }

            test.generateToken(targetUserName, targetSPN);

            // Both serviceSubject and serviceCredentials can be kept
            // for the whole server JVM lifetime
            // but renewed when GSSExceptions are thrown.

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
