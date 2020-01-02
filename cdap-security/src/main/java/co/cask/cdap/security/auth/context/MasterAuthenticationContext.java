/*
 * Copyright © 2016 Cask Data, Inc.
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

package co.cask.cdap.security.auth.context;

import co.cask.cdap.common.io.Codec;
import co.cask.cdap.proto.security.Principal;
import co.cask.cdap.security.auth.AccessTokenCodec;
import co.cask.cdap.security.auth.AccessTokenIdentifier;
import co.cask.cdap.security.auth.KeyIdentifier;
import co.cask.cdap.security.guice.SecurityModule;
import co.cask.cdap.security.guice.SecurityModules;
import co.cask.cdap.security.spi.authentication.AuthenticationContext;
import co.cask.cdap.security.spi.authentication.SecurityRequestContext;
import com.google.common.base.Throwables;
import com.google.inject.Guice;
import org.apache.commons.codec.binary.Base64;
import org.apache.hadoop.security.UserGroupInformation;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * An {@link AuthenticationContext} for HTTP requests in the Master. The authentication details in this context are
 * derived from:
 * <ol>
 *   <li>{@link SecurityRequestContext}, when the request; or</li>
 *   <li>{@link UserGroupInformation}, when the master itself is asynchronously updating privileges in the
 *   authorization policy cache.</li>
 * </ol>
 *SecurityRequestContext
 * @see
 * @see UserGroupInformation
 */
public class MasterAuthenticationContext implements AuthenticationContext {

  @Override
  public Principal getPrincipal() {
    // When requests come in via rest endpoints, the userId is updated inside SecurityRequestContext, so give that
    // precedence.
    String userId = SecurityRequestContext.getUserId();
    // This userId can be null, when the master itself is asynchoronously updating the policy cache, since
    // during that process the router will not set the SecurityRequestContext. In that case, obtain the userId from
    // the UserGroupInformation, which will be the user that the master is running as.
    if (userId == null) {
      try {
        userId = UserGroupInformation.getCurrentUser().getShortUserName();
      } catch (IOException e) {
        throw Throwables.propagate(e);
      }
    }
    if(SecurityRequestContext.getAccessToken()!=null) {

      try {
//        String accessToken =  (Guice.createInjector(new SecurityModules().getDistributedModules()).getInstance(AccessTokenCodec.class).decode(Base64.decodeBase64(SecurityRequestContext.getAccessToken()))).toString();
      String accessToken = new String(Base64.decodeBase64(SecurityRequestContext.getAccessToken().trim()));
        String [] keycloakToken1 = accessToken.substring(userId.length() + 2).split("\\�");
        String keycloakToken = (keycloakToken1[1].trim()).replaceAll("[^\\p{ASCII}]", "");
        return new Principal(userId, Principal.PrincipalType.USER, null, keycloakToken);
      }catch (Exception ex){
        System.out.println(ex.getMessage());
      }
    }
    return new Principal(userId, Principal.PrincipalType.USER);
  }
}
