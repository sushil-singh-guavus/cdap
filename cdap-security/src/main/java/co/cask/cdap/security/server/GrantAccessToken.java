/*
 * Copyright © 2014 Cask Data, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package co.cask.cdap.security.server;

import co.cask.cdap.common.conf.CConfiguration;
import co.cask.cdap.common.conf.Constants;
import co.cask.cdap.common.io.Codec;
import co.cask.cdap.security.auth.AccessToken;
import co.cask.cdap.security.auth.AccessTokenIdentifier;
import co.cask.cdap.security.auth.TokenManager;
import co.cask.cdap.security.spi.authorization.UnauthorizedException;
import com.google.common.base.Charsets;
import com.google.common.base.Strings;
import com.google.gson.JsonObject;
import com.google.inject.Inject;
import io.netty.handler.codec.http.HttpHeaderNames;
import org.apache.commons.codec.binary.Base64;
import org.eclipse.jetty.http.HttpHeaders;
import org.eclipse.jetty.util.B64Code;
import org.eclipse.jetty.util.StringUtil;
import org.keycloak.OAuth2Constants;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.rotation.AdapterTokenVerifier;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.util.Http;
import org.keycloak.authorization.client.util.HttpResponseException;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessTokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

/**
 * Generate and grant access token to authorized users.
 */
@Path("/")
public class GrantAccessToken {
  private static final Logger LOG = LoggerFactory.getLogger(GrantAccessToken.class);
  private final TokenManager tokenManager;
  private final Codec<AccessToken> tokenCodec;
  private final long tokenExpiration;
  private final long extendedTokenExpiration;
  private static KeycloakDeployment deployment;

  /**
   * Create a new GrantAccessToken object to generate tokens for authorized users.
   */
  @Inject
  public GrantAccessToken(TokenManager tokenManager,
                          Codec<AccessToken> tokenCodec,
                          CConfiguration cConf) {
    this.tokenManager = tokenManager;
    this.tokenCodec = tokenCodec;
    this.tokenExpiration = cConf.getLong(Constants.Security.TOKEN_EXPIRATION);
    this.extendedTokenExpiration = cConf.getLong(Constants.Security.EXTENDED_TOKEN_EXPIRATION);
    this.deployment = KeycloakDeploymentBuilder.build(Thread.currentThread().getContextClassLoader().getResourceAsStream("keycloak.json"));

  }

  /**
   * Initialize the TokenManager.
   */
  public void init() {
    tokenManager.start();
  }

  /**
   * Stop the TokenManager.
   */
  public void destroy() {
    tokenManager.stop();
  }

  /**
   * Paths to get Access Tokens.
   */
  public static final class Paths {
    public static final String GET_TOKEN = "token";
    public static final String GET_TOKEN_FROM_KEYCLOAK = "keycloakToken";
    public static final String GET_REFRESH_TOKEN = "refreshToken";
    public static final String GET_EXTENDED_TOKEN = "extendedtoken";
    public static final String LOGOUT_END_POINT = "logout";
  }

  /**
   * Get an AccessToken.
   */
  @Path(Paths.GET_TOKEN)
  @GET
  @Produces("application/json")
  public Response token(@Context HttpServletRequest request, @Context HttpServletResponse response)
      throws IOException, ServletException {
    grantToken(request, response, tokenExpiration);
    return Response.status(200).build();
  }

  @Path(Paths.GET_TOKEN_FROM_KEYCLOAK)
    @GET
    @Produces("application/json")
    public Response tokenFromKeycloak(@Context HttpServletRequest request, @Context HttpServletResponse response)
            throws IOException, ServletException {
        try {
            AccessToken token = getTokenUsingKeycloak(request, response);
            if (token != null)
                return Response.status(200).build();
        } catch (Exception ex) {
            LOG.debug(ex.getMessage());
        }
        return Response.status(401).build();
    }


   @Path(Paths.GET_REFRESH_TOKEN)
    @POST
    @Produces("application/json")
    public Response refreshtokenFromKeycloak(@Context HttpServletRequest request, @Context HttpServletResponse response)
            throws HttpResponseException, VerificationException {

        List<String> userGroups = Collections.emptyList();

        long issueTime = System.currentTimeMillis();

        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        String auth=null;

        if (authorizationHeader!=null && !Strings.isNullOrEmpty(authorizationHeader) && (authorizationHeader.trim().toLowerCase().startsWith("bearer "))) {
            auth = authorizationHeader.substring(7);
        }

        if (auth != null) {
            try {
                String client_id = request.getParameter(OAuth2Constants.CLIENT_ID);
                String client_secret = request.getParameter(OAuth2Constants.CLIENT_SECRET);
                String refresh_token = request.getParameter(OAuth2Constants.REFRESH_TOKEN);
                String refreshUrl = deployment.getTokenUrl();

                Http http = new Http(new org.keycloak.authorization.client.Configuration(), (params, headers) -> {
                });
                AccessTokenResponse acesstokenresponse = null;
                acesstokenresponse = http.<AccessTokenResponse>post(refreshUrl)
                        .authentication()
                        .client()
                        .form()
                        .param(OAuth2Constants.GRANT_TYPE, OAuth2Constants.REFRESH_TOKEN)
                        .param(OAuth2Constants.REFRESH_TOKEN, refresh_token)
                        .param(OAuth2Constants.CLIENT_ID, client_id)
                        .param(OAuth2Constants.CLIENT_SECRET, client_secret)
                        .response()
                        .json(AccessTokenResponse.class)
                        .execute();

                org.keycloak.representations.AccessToken keycloakToken = AdapterTokenVerifier.verifyToken(acesstokenresponse.getToken(), deployment);
                long expireDuration = keycloakToken.getExpiration() - keycloakToken.getIssuedAt();
                long expireTime = issueTime + expireDuration * 1000;
                String refreshToken = acesstokenresponse.getRefreshToken();
                String username = keycloakToken.getPreferredUsername();
                AccessTokenIdentifier tokenIdentifier = new AccessTokenIdentifier(username, userGroups, issueTime, expireTime, acesstokenresponse.getToken());
                AccessToken cdapToken = tokenManager.signIdentifier(tokenIdentifier);
                setResponse(request, response, cdapToken, refreshToken, 1000 * expireDuration);
            } catch (HttpResponseException ex) {
                LOG.debug(ex.getMessage());
                return Response.status(ex.getStatusCode()).build();
            } catch (VerificationException e) {
                LOG.debug("Authorization header missing/invalid");
            } catch (Exception ex) {
                LOG.debug("Exception Occured while getting refresh token " + ex.getMessage());
            }
        }
        return Response.status(401).build();
    }

   private void setResponse(HttpServletRequest request, HttpServletResponse response, AccessToken token, String refreshToken,
                             long tokenValidity) throws IOException, ServletException {

        /* TO BE DONE */
        JsonObject json = new JsonObject();
        byte[] encodedIdentifier = Base64.encodeBase64(tokenCodec.encode(token));
        json.addProperty(ExternalAuthenticationServer.ResponseFields.ACCESS_TOKEN,
                new String(encodedIdentifier, Charsets.UTF_8));
        json.addProperty(ExternalAuthenticationServer.ResponseFields.TOKEN_TYPE,
                ExternalAuthenticationServer.ResponseFields.TOKEN_TYPE_BODY);
        json.addProperty(ExternalAuthenticationServer.ResponseFields.EXPIRES_IN,
                TimeUnit.SECONDS.convert(tokenValidity, TimeUnit.MILLISECONDS));

        if (refreshToken != null && !refreshToken.isEmpty()) {
            json.addProperty(OAuth2Constants.REFRESH_TOKEN, refreshToken);
        }

        response.getOutputStream().print(json.toString());
        response.setStatus(HttpServletResponse.SC_OK);
    }


  /**
   * Get a long lasting Access Token.
   */
  @Path(Paths.GET_EXTENDED_TOKEN)
  @GET
  @Produces("application/json")
  public Response extendedToken(@Context HttpServletRequest request, @Context HttpServletResponse response)
    throws IOException, ServletException {
    grantToken(request, response, extendedTokenExpiration);
    return Response.status(200).build();
  }

  private AccessToken getTokenUsingKeycloak(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException, UnauthorizedException {

        /* TO BE DONE */

        String username;
        String refreshTokenString;
        org.keycloak.representations.AccessToken keycloakToken = null;
        List<String> userGroups = Collections.emptyList();
        String authorizationHeader = request.getHeader("keycloakToken");
        String wireToken;

        if(authorizationHeader==null)
            authorizationHeader = request.getAttribute("keycloakToken").toString();

        if (authorizationHeader != null && !Strings.isNullOrEmpty(authorizationHeader)) {
            wireToken = authorizationHeader;
        } else {
            wireToken = getJWTTokenFromCookie(request);
        }
        if (Strings.isNullOrEmpty(wireToken)) {
            LOG.debug("No valid 'Bearer Authorization' or 'Cookie' found in header, send 401");
            return null;
        }

        try {
//            refreshTokenString = request.getHeader("refreshToken");
//            RefreshToken refreshToken = TokenVerifier.create(refreshTokenString, org.keycloak.representations.RefreshToken.class).getToken();
            keycloakToken = AdapterTokenVerifier.verifyToken(wireToken, deployment);
//            if (!refreshToken.getSessionState().equals(keycloakToken.getSessionState())) {
//                throw new UnauthorizedException("Session States of access and refresh tokens don't match");
//            }

            username = keycloakToken.getPreferredUsername();

        } catch (VerificationException e) {
            Response.status(401).build();
            throw new UnauthorizedException("Authorization header missing/invalid");
        }

        if (keycloakToken.isExpired()) {
            LOG.debug("token expiry date: " + new Date(keycloakToken.getExpiration()));
            Response.status(401).build();
            throw new UnauthorizedException("Token expired.");
        }

        long issueTime = (long) keycloakToken.getIssuedAt() * 1000;
        long expireTime = (long) keycloakToken.getExpiration() * 1000;

        AccessTokenIdentifier tokenIdentifier = new AccessTokenIdentifier(username, userGroups, issueTime, expireTime, wireToken);
        AccessToken cdapToken = tokenManager.signIdentifier(tokenIdentifier);
        LOG.debug("Issued token for user {}", username);

//        setResponse(request, response, cdapToken, null, (expireTime - issueTime));

        return cdapToken;
    }


  private static String getJWTTokenFromCookie(HttpServletRequest request) {
        String rawCookie = request.getHeader("cookie");
        if (rawCookie == null) {
            return null;
        }
        String cookieToken = null;
        String cookieName = "hadoop-jwt";

        String[] rawCookieParams = rawCookie.split(";");
        for (String rawCookieNameAndValue : rawCookieParams) {
            String[] rawCookieNameAndValuePair = rawCookieNameAndValue.split("=");
            if ((rawCookieNameAndValuePair.length > 1) &&
                    (rawCookieNameAndValuePair[0].trim().equalsIgnoreCase(cookieName))) {
                cookieToken = rawCookieNameAndValuePair[1];
                break;
            }
        }
        return cookieToken;
    }


  private void grantToken(HttpServletRequest request, HttpServletResponse response, long tokenValidity)
    throws IOException, ServletException {

            String username = null;
        String password = null;

        String credentials = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (credentials != null) {
            int space = credentials.indexOf(' ');
            if (space > 0) {
                String method = credentials.substring(0, space);
                if ("basic".equalsIgnoreCase(method)) {
                    credentials = credentials.substring(space + 1);
                    credentials = B64Code.decode(credentials, StringUtil.__ISO_8859_1);
                    int i = credentials.indexOf(':');
                    if (i > 0) {
                        username = credentials.substring(0, i);
                        password = credentials.substring(i+1);
                        AuthzClient client = AuthzClient.create();
                        AccessTokenResponse keycloakResponse = client.obtainAccessToken(username,password);
                        if(keycloakResponse.getToken()!=null) {
                            // CREATE NEW CDAP TOKEN BASED ON KEYCLOAK ACCESS AND REFRESH TOKEN
                            request.setAttribute("keycloakToken",keycloakResponse.getToken());
                            AccessToken cdapToken = getTokenUsingKeycloak(request,response);
                            String refreshToken = keycloakResponse.getRefreshToken();
                            long expireDuration = keycloakResponse.getExpiresIn();
                            setResponse(request, response, cdapToken, refreshToken, 1000 * expireDuration);
                            return;
                        }
                    }
                }
            }
        }


    //String username = request.getUserPrincipal().getName();
    List<String> userGroups = Collections.emptyList();

    long issueTime = System.currentTimeMillis();
    long expireTime = issueTime + tokenValidity;
    // Create and sign a new AccessTokenIdentifier to generate the AccessToken.
    AccessTokenIdentifier tokenIdentifier = new AccessTokenIdentifier(username, userGroups, issueTime, expireTime);
    AccessToken token = tokenManager.signIdentifier(tokenIdentifier);
    LOG.debug("Issued token for user {}", username);

    // Set response headers
    response.setContentType("application/json;charset=UTF-8");
    response.addHeader(HttpHeaderNames.CACHE_CONTROL.toString(), "no-store");
    response.addHeader(HttpHeaderNames.PRAGMA.toString(), "no-cache");

    // Set response body
    JsonObject json = new JsonObject();
    byte[] encodedIdentifier = Base64.encodeBase64(tokenCodec.encode(token));
    json.addProperty(ExternalAuthenticationServer.ResponseFields.ACCESS_TOKEN,
                     new String(encodedIdentifier, Charsets.UTF_8));
    json.addProperty(ExternalAuthenticationServer.ResponseFields.TOKEN_TYPE,
                     ExternalAuthenticationServer.ResponseFields.TOKEN_TYPE_BODY);
    json.addProperty(ExternalAuthenticationServer.ResponseFields.EXPIRES_IN,
                     TimeUnit.SECONDS.convert(tokenValidity, TimeUnit.MILLISECONDS));

    response.getOutputStream().print(json.toString());
    response.setStatus(HttpServletResponse.SC_OK);
  }
}
