package co.cask.cdap.security.server;

import org.eclipse.jetty.security.DefaultUserIdentity;
import org.eclipse.jetty.security.authentication.BasicAuthenticator;

import org.eclipse.jetty.security.authentication.DeferredAuthentication;

import java.io.IOException;
import java.util.*;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.http.HttpHeaders;
import org.eclipse.jetty.security.ServerAuthException;
import org.eclipse.jetty.security.UserAuthentication;
import org.eclipse.jetty.server.Authentication;
import org.eclipse.jetty.server.Authentication.User;
import org.eclipse.jetty.server.UserIdentity;
import org.eclipse.jetty.util.B64Code;
import org.eclipse.jetty.util.StringUtil;
import org.eclipse.jetty.util.security.Constraint;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.representations.AccessTokenResponse;
import org.mortbay.log.Log;

import com.google.common.base.Strings;


public class KeycloakBasicAuthenticator extends BasicAuthenticator {

    private Map<String, String> handlerProps;

    /* ------------------------------------------------------------ */
    public KeycloakBasicAuthenticator(Map<String, String> handlerProps)
    {
        this.handlerProps = handlerProps;
    }

    /* ------------------------------------------------------------ */
    /**
     * @see org.eclipse.jetty.security.Authenticator#getAuthMethod()
     */
    public String getAuthMethod()
    {
        return Constraint.__BASIC_AUTH;
    }



    /* ------------------------------------------------------------ */
    /**
     * @see org.eclipse.jetty.security.Authenticator#validateRequest(javax.servlet.ServletRequest, javax.servlet.ServletResponse, boolean)
     */
    public Authentication validateRequest(ServletRequest req, ServletResponse res, boolean mandatory) throws ServerAuthException
    {
        HttpServletRequest request = (HttpServletRequest)req;
        HttpServletResponse response = (HttpServletResponse)res;


        final String authorizationHeader = request.getHeader("Authorization");
        String wireToken;

        if (authorizationHeader!=null && !Strings.isNullOrEmpty(authorizationHeader) && (authorizationHeader.trim().toLowerCase().startsWith("bearer "))) {
            wireToken = authorizationHeader.substring(7);
        } else {
            wireToken = getJWTTokenFromCookie(request,null);
        }

        //Getting from Metaservice
        if (Strings.isNullOrEmpty(wireToken)) {
            wireToken = request.getHeader("keycloakToken");
            Log.info("keycloak token : " + wireToken);
        }

        // keycloak Token verification
        if (!Strings.isNullOrEmpty(wireToken)) {
            return new UserAuthentication(getAuthMethod(), new DefaultUserIdentity(null,null,null));
        }


        String credentials = request.getHeader(HttpHeaders.AUTHORIZATION);
        Log.info("credentials : " + credentials);

        try
        {
            if (!mandatory)
                return new DeferredAuthentication(this);

            if (credentials != null)
            {
                return new UserAuthentication(getAuthMethod(), new DefaultUserIdentity(null,null,null));
            }

            if (DeferredAuthentication.isDeferred(response))
                return Authentication.UNAUTHENTICATED;

            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "basic realm=\"" + _loginService.getName() + '"');
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return Authentication.SEND_CONTINUE;
        }
        catch (IOException e)
        {
            throw new ServerAuthException(e);
        }
    }

    public boolean secureResponse(ServletRequest req, ServletResponse res, boolean mandatory, User validatedUser) throws ServerAuthException
    {
        return true;
    }

    private String getJWTTokenFromCookie(HttpServletRequest request,String cookiename) {
        String rawCookie = request.getHeader("cookie");
        if (rawCookie == null) {
            return null;
        }
        String cookieToken = null;
        String cookieName = "hadoop-jwt";

        if(cookieName!=null){
            cookieName=cookiename;
        }

        String[] rawCookieParams = rawCookie.split(";");
        for(String rawCookieNameAndValue :rawCookieParams) {
            String[] rawCookieNameAndValuePair = rawCookieNameAndValue.split("=");
            if ((rawCookieNameAndValuePair.length > 1) &&
                    (rawCookieNameAndValuePair[0].trim().equalsIgnoreCase(cookieName))) {
                cookieToken = rawCookieNameAndValuePair[1];
                break;
            }
        }
        return cookieToken;
    }
}

