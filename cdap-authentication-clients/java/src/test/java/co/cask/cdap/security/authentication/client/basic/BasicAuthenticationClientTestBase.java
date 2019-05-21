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

package co.cask.cdap.security.authentication.client.basic;

import co.cask.cdap.security.authentication.client.AccessToken;
import co.cask.cdap.security.authentication.client.AuthenticationClient;
import co.cask.common.http.exception.HttpFailureException;
import co.cask.http.AbstractHttpHandler;
import co.cask.http.HttpHandler;
import co.cask.http.HttpResponder;
import co.cask.http.NettyHttpService;
import com.google.common.base.Charsets;
import com.google.common.base.Objects;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Sets;
import com.google.common.net.HttpHeaders;
import com.google.common.util.concurrent.AbstractIdleService;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import javax.ws.rs.GET;
import javax.ws.rs.Path;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 *
 */
public abstract class BasicAuthenticationClientTestBase {
  public static final String USERNAME = "admin";
  public static final String PASSWORD = "realtime";
  public static final String TOKEN = "SuccessGeneratedToken";
  public static final String NEW_TOKEN = "SuccessGeneratedSecondToken";
  public static final String TOKEN_TYPE = "Bearer";
  public static final String EMPTY_TOKEN_USERNAME = "emptyToken";
  public static final String EXPIRED_TOKEN_USERNAME = "expiredToken";
  public static final Long TOKEN_LIFE_TIME = 86400L;
  private static final String USERNAME_PROP_NAME = "security_auth_client_username";
  private static final String PASSWORD_PROP_NAME = "security_auth_client_password";
  private static final String VERIFY_SSL_CERT_PROP_NAME = "security.auth.client.verify.ssl.cert";
  private static final String VERIFY_SSL_CERT_PROP_VALUE = "false";

  protected static TestHttpService authEnabledRouter;
  protected static TestHttpService authDisabledRouter;
  protected static TestHttpService noAuthServerRouter;
  protected static TestHttpService authServer;

  protected static boolean sslEnabled;

  /*@Test
  public void testSuccessGetAccessToken() throws IOException {
    Properties testProperties = new Properties();
    testProperties.setProperty(USERNAME_PROP_NAME, USERNAME);
    testProperties.setProperty(PASSWORD_PROP_NAME, PASSWORD);
    testProperties.setProperty(VERIFY_SSL_CERT_PROP_NAME, VERIFY_SSL_CERT_PROP_VALUE);

    AuthenticationClient authenticationClient = new BasicAuthenticationClient();
    authenticationClient.setConnectionInfo(authEnabledRouter.getBindAddress().getHostName(),
                                           authEnabledRouter.getBindAddress().getPort(), sslEnabled);
    authenticationClient.configure(testProperties);
    AccessToken accessToken = authenticationClient.getAccessToken();
    assertTrue(accessToken != null);
    assertEquals(TOKEN, accessToken.getValue());
    assertEquals(TOKEN_TYPE, accessToken.getTokenType());
    assertEquals(TOKEN_LIFE_TIME, accessToken.getExpiresIn());
  }*/

  /*@Test
  public void testNotAuthorizedGetAccessToken() throws IOException {
    Properties testProperties = new Properties();
    testProperties.setProperty(USERNAME_PROP_NAME, "test");
    testProperties.setProperty(PASSWORD_PROP_NAME, "test");
    testProperties.setProperty(VERIFY_SSL_CERT_PROP_NAME, VERIFY_SSL_CERT_PROP_VALUE);

    AuthenticationClient authenticationClient = new BasicAuthenticationClient();
    authenticationClient.setConnectionInfo(authEnabledRouter.getBindAddress().getHostName(),
                                           authEnabledRouter.getBindAddress().getPort(), sslEnabled);
    authenticationClient.configure(testProperties);
    try {
      authenticationClient.getAccessToken();
      fail("Expected unauthorized status.");
    } catch (HttpFailureException e) {
      assertEquals(HttpURLConnection.HTTP_UNAUTHORIZED, e.getStatusCode());
    }
  }*/

  /*@Test(expected = IOException.class)
  public void testEmptyTokenGetAccessToken() throws IOException {
    Properties testProperties = new Properties();
    testProperties.setProperty(USERNAME_PROP_NAME, EMPTY_TOKEN_USERNAME);
    testProperties.setProperty(PASSWORD_PROP_NAME, PASSWORD);
    testProperties.setProperty(VERIFY_SSL_CERT_PROP_NAME, VERIFY_SSL_CERT_PROP_VALUE);

    AuthenticationClient authenticationClient = new BasicAuthenticationClient();
    authenticationClient.setConnectionInfo(authEnabledRouter.getBindAddress().getHostName(),
                                           authEnabledRouter.getBindAddress().getPort(), sslEnabled);
    authenticationClient.configure(testProperties);
    authenticationClient.getAccessToken();
  }*/

  /*@Test
  public void testExpiredTokenGetAccessToken() throws IOException {
    Properties testProperties = new Properties();
    testProperties.setProperty(USERNAME_PROP_NAME, EXPIRED_TOKEN_USERNAME);
    testProperties.setProperty(PASSWORD_PROP_NAME, PASSWORD);
    testProperties.setProperty(VERIFY_SSL_CERT_PROP_NAME, VERIFY_SSL_CERT_PROP_VALUE);

    AuthenticationClient authenticationClient = new BasicAuthenticationClient();
    authenticationClient.setConnectionInfo(authEnabledRouter.getBindAddress().getHostName(),
                                           authEnabledRouter.getBindAddress().getPort(), sslEnabled);
    authenticationClient.configure(testProperties);
    AccessToken accessToken = authenticationClient.getAccessToken();
    assertEquals(TOKEN, accessToken.getValue());
    accessToken = authenticationClient.getAccessToken();
    assertTrue(accessToken != null);
    assertEquals(NEW_TOKEN, accessToken.getValue());
    assertEquals(TOKEN_TYPE, accessToken.getTokenType());
  }*/

  @Test(expected = IllegalArgumentException.class)
  public void testEmptyUsernameConfigure() throws IOException {
    Properties testProperties = new Properties();
    testProperties.setProperty(USERNAME_PROP_NAME, StringUtils.EMPTY);
    testProperties.setProperty(PASSWORD_PROP_NAME, PASSWORD);
    testProperties.setProperty(VERIFY_SSL_CERT_PROP_NAME, VERIFY_SSL_CERT_PROP_VALUE);

    AuthenticationClient authenticationClient = new BasicAuthenticationClient();
    authenticationClient.setConnectionInfo(authEnabledRouter.getBindAddress().getHostName(),
                                           authEnabledRouter.getBindAddress().getPort(), sslEnabled);
    authenticationClient.configure(testProperties);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testEmptyPassConfigure() throws IOException {
    Properties testProperties = new Properties();
    testProperties.setProperty(USERNAME_PROP_NAME, USERNAME);
    testProperties.setProperty(PASSWORD_PROP_NAME, StringUtils.EMPTY);
    testProperties.setProperty(VERIFY_SSL_CERT_PROP_NAME, VERIFY_SSL_CERT_PROP_VALUE);

    AuthenticationClient authenticationClient = new BasicAuthenticationClient();
    authenticationClient.setConnectionInfo(authEnabledRouter.getBindAddress().getHostName(),
                                           authEnabledRouter.getBindAddress().getPort(), sslEnabled);
    authenticationClient.configure(testProperties);
  }

  @Test(expected = IllegalStateException.class)
  public void testSecondCallConfigure() throws IOException {
    Properties testProperties = new Properties();
    testProperties.setProperty(USERNAME_PROP_NAME, USERNAME);
    testProperties.setProperty(PASSWORD_PROP_NAME, PASSWORD);
    testProperties.setProperty(VERIFY_SSL_CERT_PROP_NAME, VERIFY_SSL_CERT_PROP_VALUE);

    AuthenticationClient authenticationClient = new BasicAuthenticationClient();
    authenticationClient.configure(testProperties);
    authenticationClient.configure(testProperties);
  }

  @Test(expected = IllegalStateException.class)
  public void testSecondCallSetConnectionInfo() throws IOException {

    AuthenticationClient authenticationClient = new BasicAuthenticationClient();
    authenticationClient.setConnectionInfo(authEnabledRouter.getBindAddress().getHostName(),
                                           authEnabledRouter.getBindAddress().getPort(), sslEnabled);
    authenticationClient.setConnectionInfo("localhost", 443, true);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testEmptyPropertiesConfigure() throws IOException {
    AuthenticationClient authenticationClient = new BasicAuthenticationClient();
    authenticationClient.configure(new Properties());
  }

  @Test
  public void testIsAuthEnabled() throws IOException {
    Properties testProperties = new Properties();
    testProperties.setProperty(USERNAME_PROP_NAME, USERNAME);
    testProperties.setProperty(PASSWORD_PROP_NAME, PASSWORD);
    testProperties.setProperty(VERIFY_SSL_CERT_PROP_NAME, VERIFY_SSL_CERT_PROP_VALUE);

    AuthenticationClient authenticationClient = new BasicAuthenticationClient();
    authenticationClient.setConnectionInfo(authEnabledRouter.getBindAddress().getHostName(),
                                           authEnabledRouter.getBindAddress().getPort(), sslEnabled);
    authenticationClient.configure(testProperties);
    assertTrue(authenticationClient.isAuthEnabled());
  }

  /*@Test(expected = IOException.class)
  public void testEmptyUrlListIsAuthEnabled() throws IOException {
    Properties testProperties = new Properties();
    testProperties.setProperty(USERNAME_PROP_NAME, USERNAME);
    testProperties.setProperty(PASSWORD_PROP_NAME, PASSWORD);
    testProperties.setProperty(VERIFY_SSL_CERT_PROP_NAME, VERIFY_SSL_CERT_PROP_VALUE);

    AuthenticationClient authenticationClient = new BasicAuthenticationClient();
    authenticationClient.setConnectionInfo(noAuthServerRouter.getBindAddress().getHostName(),
                                           noAuthServerRouter.getBindAddress().getPort(), sslEnabled);
    authenticationClient.configure(testProperties);
    assertTrue(authenticationClient.isAuthEnabled());
  }*/

  /*@Test
  public void testAuthDisabledIsAuthEnabled() throws IOException {
    Properties testProperties = new Properties();
    testProperties.setProperty(USERNAME_PROP_NAME, USERNAME);
    testProperties.setProperty(PASSWORD_PROP_NAME, PASSWORD);
    testProperties.setProperty(VERIFY_SSL_CERT_PROP_NAME, VERIFY_SSL_CERT_PROP_VALUE);

    AuthenticationClient authenticationClient = new BasicAuthenticationClient();
    authenticationClient.setConnectionInfo(authDisabledRouter.getBindAddress().getHostName(),
                                           authDisabledRouter.getBindAddress().getPort(), sslEnabled);
    authenticationClient.configure(testProperties);
    assertFalse(authenticationClient.isAuthEnabled());
  }*/

  public static class AuthServer extends AbstractHttpHandler {
    private int expiredRequestsCounter = 0;

    @GET
    @Path("/token")
    public void getToken(HttpRequest request,
                         HttpResponder responder) throws Exception {
      String authHeaderVal = request.getHeader(HttpHeaders.AUTHORIZATION);
      if (StringUtils.isNotEmpty(authHeaderVal)) {
        authHeaderVal = authHeaderVal.replace("Basic ", StringUtils.EMPTY);
        String credentialsStr = new String(Base64.decodeBase64(authHeaderVal), Charsets.UTF_8);
        String[] credentials = credentialsStr.split(":");
        String username = credentials[0];
        String password = credentials[1];
        if (USERNAME.equals(username) && PASSWORD.equals(password)) {
          responder.sendJson(HttpResponseStatus.OK, getTokenMap(TOKEN, TOKEN_TYPE, TOKEN_LIFE_TIME));
        } else if (EMPTY_TOKEN_USERNAME.equals(username)) {
          responder.sendJson(HttpResponseStatus.OK, getTokenMap("", TOKEN_TYPE, TOKEN_LIFE_TIME));
        } else if (EXPIRED_TOKEN_USERNAME.equals(username)) {
          if (expiredRequestsCounter == 0) {
            ++expiredRequestsCounter;
            responder.sendJson(HttpResponseStatus.OK, getTokenMap(TOKEN, TOKEN_TYPE, 5L));
          } else {
            responder.sendJson(HttpResponseStatus.OK, getTokenMap(NEW_TOKEN, TOKEN_TYPE, TOKEN_LIFE_TIME));
          }
        } else {
          responder.sendStatus(HttpResponseStatus.UNAUTHORIZED);
        }
      } else {
        responder.sendStatus(HttpResponseStatus.BAD_REQUEST);
      }
    }

    private static Map<String, String> getTokenMap(String token, String tokenType, Long tokenLife) {
      return ImmutableMap.of("access_token", token,
                             "token_type", tokenType,
                             "expires_in", String.valueOf(tokenLife));
    }
  }

  public static class Router extends AbstractHttpHandler {
    private final boolean authEnabled;
    private final List<String> authUris;

    public Router(boolean authEnabled, List<String> authUris) {
      this.authEnabled = authEnabled;
      this.authUris = authUris;
    }

    @GET
    @Path("/ping")
    public void testHttpStatus(@SuppressWarnings("UnusedParameters") HttpRequest request,
                               HttpResponder responder) throws Exception {
      if (authEnabled) {
        responder.sendJson(HttpResponseStatus.UNAUTHORIZED, ImmutableMap.of("auth_uri", authUris));
      } else {
        responder.sendString(HttpResponseStatus.OK, "OK.");
      }
    }
  }

  public static final class TestHttpService extends AbstractIdleService {

    private final NettyHttpService httpService;

    public TestHttpService(Set<? extends HttpHandler> handlers, boolean sslEnabled) throws Exception {
      NettyHttpService.Builder serviceBuilder = NettyHttpService.builder()
        .setHost("localhost")
        .addHttpHandlers(Sets.newHashSet(handlers))
        .setWorkerThreadPoolSize(10)
        .setExecThreadPoolSize(10)
        .setConnectionBacklog(20000);

      if (sslEnabled) {
        URL keystore = getClass().getClassLoader().getResource("cert.jks");
        Assert.assertNotNull(keystore);
        serviceBuilder.enableSSL(new File(keystore.toURI()), "secret", "secret");
      }

      this.httpService = serviceBuilder.build();
    }

    public InetSocketAddress getBindAddress() {
      return httpService.getBindAddress();
    }

    @Override
    protected void startUp() throws Exception {
      httpService.startAndWait();
    }

    @Override
    protected void shutDown() throws Exception {
      httpService.stopAndWait();
    }

    @Override
    public String toString() {
      return Objects.toStringHelper(this)
        .add("bindAddress", getBindAddress())
        .toString();
    }
  }
}
