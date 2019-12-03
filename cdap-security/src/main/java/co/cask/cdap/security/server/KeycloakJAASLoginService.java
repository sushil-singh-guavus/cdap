package co.cask.cdap.security.server;
import org.eclipse.jetty.plus.jaas.callback.ObjectCallback;
import org.eclipse.jetty.plus.jaas.callback.RequestParameterCallback;
import org.eclipse.jetty.security.DefaultIdentityService;
import org.eclipse.jetty.security.IdentityService;
import org.eclipse.jetty.security.LoginService;
import org.eclipse.jetty.server.AbstractHttpConnection;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.UserIdentity;
import org.eclipse.jetty.util.Loader;
import org.eclipse.jetty.util.component.AbstractLifeCycle;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

/* ---------------------------------------------------- */
/** JAASLoginService
 *
 * Creates a UserRealm suitable for use with JAAS
 */
public class KeycloakJAASLoginService extends AbstractLifeCycle implements LoginService {
    private static final Logger LOG = Log.getLogger(KeycloakJAASLoginService.class);

    public static String defaultRoleClassName = "org.eclipse.jetty.plus.jaas.JAASRole";
    public static String[] defaultRoleClassNames = {defaultRoleClassName};

    protected String[] roleClassNames = defaultRoleClassNames;
    protected String callbackHandlerClass;
    protected String realmName;
    protected String loginModuleName;
    protected JAASUserPrincipal defaultUser = new JAASUserPrincipal(null, null, null);
    protected IdentityService identityService;
    protected Configuration configuration;
    public LoginContext loginContext = null;

    /* ---------------------------------------------------- */
    /**
     * Constructor.
     *
     */
    public KeycloakJAASLoginService() {
    }


    /* ---------------------------------------------------- */
    /**
     * Constructor.
     *
     * @param name the name of the realm
     */
    public KeycloakJAASLoginService(String name) {
        this();
        realmName = name;
        loginModuleName = name;
    }


    /* ---------------------------------------------------- */
    /**
     * Get the name of the realm.
     *
     * @return name or null if not set.
     */
    @Override
    public String getName() {
        return realmName;
    }


    /* ---------------------------------------------------- */
    /**
     * Set the name of the realm
     *
     * @param name a <code>String</code> value
     */
    public void setName (String name) {
        realmName = name;
    }

    /* ------------------------------------------------------------ */
    /** Get the identityService.
     * @return the identityService
     */
    @Override
    public IdentityService getIdentityService() {
        return identityService;
    }

    /* ------------------------------------------------------------ */
    /** Set the identityService.
     * @param identityService the identityService to set
     */
    @Override
    public void setIdentityService(IdentityService identityService) {
        this.identityService = identityService;
    }

    /* ------------------------------------------------------------ */
    /**
     * Set the name to use to index into the config
     * file of LoginModules.
     *
     * @param name a <code>String</code> value
     */
    public void setLoginModuleName (String name) {
        loginModuleName = name;
    }

    public void setConfiguration(Configuration configuration) {
        this.configuration = configuration;
    }

    /* ------------------------------------------------------------ */
    public void setCallbackHandlerClass (String classname) {
        callbackHandlerClass = classname;
    }

    /* ------------------------------------------------------------ */
    public void setRoleClassNames (String[] classnames) {
        ArrayList<String> tmp = new ArrayList<>();

        if (classnames != null) {
            tmp.addAll(Arrays.asList(classnames));
        }

        if (!tmp.contains(defaultRoleClassName)) {
            tmp.add(defaultRoleClassName);
        }
        roleClassNames = tmp.toArray(new String[tmp.size()]);
    }

    /* ------------------------------------------------------------ */
    public String[] getRoleClassNames() {
        return roleClassNames;
    }

    /* ------------------------------------------------------------ */
    /**
     * @see org.eclipse.jetty.util.component.AbstractLifeCycle#doStart()
     */
    @Override
    protected void doStart() throws Exception {
        if (identityService == null) {
            identityService = new DefaultIdentityService();
        }
        super.doStart();
    }

    /* ------------------------------------------------------------ */
    @Override
    public UserIdentity login(final String username, final Object credentials) {
        try {
            CallbackHandler callbackHandler = null;


            if (callbackHandlerClass == null) {
                callbackHandler = new CallbackHandler() {
                    @Override
                    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                        for (Callback callback: callbacks) {
                            if (callback instanceof NameCallback) {
                                ((NameCallback) callback).setName(username);
                            } else if (callback instanceof PasswordCallback) {
                                ((PasswordCallback) callback).setPassword(credentials.toString().toCharArray());
                            } else if (callback instanceof ObjectCallback) {
                                ((ObjectCallback) callback).setObject(credentials);
                            } else if (callback instanceof RequestParameterCallback) {
                                AbstractHttpConnection connection = AbstractHttpConnection.getCurrentConnection();
                                Request request = (connection == null ? null : connection.getRequest());

                                if (request != null) {
                                    RequestParameterCallback rpc = (RequestParameterCallback) callback;
                                    rpc.setParameterValues(Arrays.asList(request.getParameterValues(rpc.getParameterName())));
                                }
                            } else {
                                throw new UnsupportedCallbackException(callback);
                            }
                        }
                    }
                };
            } else {
                Class clazz = Loader.loadClass(getClass(), callbackHandlerClass);
                callbackHandler = (CallbackHandler) clazz.newInstance();
            }
            //set up the login context
            //TODO jaspi requires we provide the Configuration parameter
            Subject subject = new Subject();

            LoginContext loginContext = null;
            try {
                loginContext = new LoginContext(loginModuleName, subject, callbackHandler, configuration);
                loginContext.login();
            } catch (LoginException e) {
                e.printStackTrace();
            }


            //login success
            JAASUserPrincipal userPrincipal = new JAASUserPrincipal(username, subject, null);
            subject.getPrincipals().add(userPrincipal);

            return identityService.newUserIdentity(subject, userPrincipal, null);
        } catch (InstantiationException e) {
            LOG.info(e.getMessage());
            LOG.debug(e);
        } catch (IllegalAccessException e) {
            LOG.info(e.getMessage());
            LOG.debug(e);
        } catch (ClassNotFoundException e) {
            LOG.info(e.getMessage());
            LOG.debug(e);
        }
        return null;
    }

    /* ------------------------------------------------------------ */
    @Override
    public boolean validate(UserIdentity user) {
        // TODO optionally check user is still valid
        return true;
    }

    /* ------------------------------------------------------------ */
    private String getUserName(CallbackHandler callbackHandler) throws IOException, UnsupportedCallbackException {
        NameCallback nameCallback = new NameCallback("foo");
        callbackHandler.handle(new Callback[] {nameCallback});
        return nameCallback.getName();
    }

    /* ------------------------------------------------------------ */
    @Override
    public void logout(UserIdentity user) {
        Set<JAASUserPrincipal> userPrincipals = user.getSubject().getPrincipals(JAASUserPrincipal.class);
        LoginContext loginContext = userPrincipals.iterator().next().getLoginContext();
        try {
            loginContext.logout();
        } catch (LoginException e) {
            LOG.warn(e);
        }
    }

    /* ------------------------------------------------------------ */
    @SuppressWarnings({ "unchecked", "rawtypes" })
    private String[] getGroups (Subject subject) {
        //get all the roles of the various types
        String[] roleClassNames = getRoleClassNames();
        Collection<String> groups = new LinkedHashSet<>();
        try {
            for (String roleClassName : roleClassNames) {
                Class loadClass = Thread.currentThread().getContextClassLoader().loadClass(roleClassName);
                Set<Principal> rolesForType = subject.getPrincipals(loadClass);
                for (Principal principal : rolesForType) {
                    groups.add(principal.getName());
                }
            }

            return groups.toArray(new String[groups.size()]);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

}

