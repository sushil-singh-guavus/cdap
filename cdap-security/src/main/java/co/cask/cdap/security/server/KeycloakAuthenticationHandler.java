package co.cask.cdap.security.server;

import org.eclipse.jetty.security.Authenticator;
import org.eclipse.jetty.security.DefaultIdentityService;
import org.eclipse.jetty.security.IdentityService;
import org.eclipse.jetty.security.LoginService;

import javax.security.auth.login.Configuration;

public class KeycloakAuthenticationHandler extends AbstractAuthenticationHandler {

    private IdentityService identityService;

    @Override
    protected LoginService getHandlerLoginService() {
        KeycloakJAASLoginService keycloakLoginService = new KeycloakJAASLoginService();
        keycloakLoginService.setConfiguration(getLoginModuleConfiguration());
        return keycloakLoginService;
    }

    @Override
    protected Authenticator getHandlerAuthenticator() {
        return new KeycloakBasicAuthenticator(handlerProps);
    }

    @Override
    protected IdentityService getHandlerIdentityService() {
        if (identityService == null) {
            identityService = new DefaultIdentityService();
        }
        return identityService;
    }

    @Override
    protected Configuration getLoginModuleConfiguration() {
        return null;
    }


}

