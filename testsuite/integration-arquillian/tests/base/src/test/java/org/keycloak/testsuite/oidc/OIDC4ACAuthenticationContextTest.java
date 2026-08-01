/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.testsuite.oidc;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.common.Profile;
import org.keycloak.common.util.PemUtils;
import org.keycloak.crypto.AesGcmContentEncryptionProvider;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.RsaCekManagementProvider;
import org.keycloak.jose.jwe.JWEConstants;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AuthorizationResponseToken;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.UserInfo;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.testsuite.admin.AdminApiUtil;
import org.keycloak.testsuite.arquillian.annotation.EnableFeature;
import org.keycloak.testsuite.broker.util.SimpleHttpDefault;
import org.keycloak.testsuite.client.resources.TestApplicationResourceUrls;
import org.keycloak.testsuite.client.resources.TestOIDCEndpointsApplicationResource;
import org.keycloak.testsuite.pages.AppPage;
import org.keycloak.testsuite.util.oauth.AccessTokenResponse;
import org.keycloak.testsuite.util.oauth.AuthorizationEndpointResponse;
import org.keycloak.util.JsonSerialization;
import org.keycloak.util.TokenUtil;

import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.junit.Before;
import org.junit.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Browser-flow integration coverage for the experimental OIDC4AC native
 * password adapter and immutable authorization-event delivery.
 */
@EnableFeature(value = Profile.Feature.OIDC4AC, skipRestart = true)
public class OIDC4ACAuthenticationContextTest extends AbstractOIDCScopeTest {

    private static final String CLIENT_ID = "test-app";
    private static final String CLIENT_SECRET = "password";

    @Before
    public void configureClient() {
        oauth.client(CLIENT_ID);
        oauth.scope("openid");
    }

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {
        // The standard test realm already supplies test-app and test-user.
    }

    @Test
    public void passwordAuthenticationIsProjectedPerLocationAndReusedOnRefresh() throws IOException {
        AccessTokenResponse response = login(passwordClaimsRequest());

        IDToken idToken = oauth.verifyIDToken(response.getIdToken());
        Map<String, Object> idTokenDetail = onlyAuthenticationDetail(idToken);
        Map<String, Object> idTokenMetadata = object(idTokenDetail, "amr_metadata");
        assertEquals("pwd", idTokenDetail.get("amr_identifier"));
        assertNotNull(idTokenMetadata.get("time"));

        UserInfo userInfo = oauth.doUserInfoRequest(response.getAccessToken()).getUserInfo();
        Map<String, Object> userInfoDetail = onlyAuthenticationDetail(userInfo);
        Map<String, Object> userInfoMetadata = object(userInfoDetail, "amr_metadata");
        assertEquals("pwd", userInfoDetail.get("amr_identifier"));
        assertEquals(idTokenMetadata.get("time"), userInfoMetadata.get("time"));
        assertFalse(userInfoDetail.containsKey("amr_properties"));

        AccessTokenResponse refreshResponse = oauth.doRefreshTokenRequest(response.getRefreshToken());
        assertEquals(200, refreshResponse.getStatusCode());
        IDToken refreshedIdToken = oauth.verifyIDToken(refreshResponse.getIdToken());
        Map<String, Object> refreshedDetail = onlyAuthenticationDetail(refreshedIdToken);
        assertEquals(idTokenDetail, refreshedDetail);
    }

    @Test
    public void authenticationDetailsAreNotCopiedToAccessToken() throws IOException {
        AccessTokenResponse response = login(passwordClaimsRequest());
        AccessToken accessToken = oauth.verifyToken(response.getAccessToken());
        assertFalse(accessToken.getOtherClaims().containsKey("amr_details"));
        assertFalse(accessToken.getOtherClaims().containsKey("amr"));
    }

    @Test
    public void offlineRefreshRetainsTheAuthenticationSnapshot() throws IOException {
        AccessTokenResponse response = login(passwordClaimsRequest(), "openid offline_access");
        IDToken initial = oauth.verifyIDToken(response.getIdToken());
        Map<String, Object> initialDetail = onlyAuthenticationDetail(initial);
        AccessToken initialAccessToken = oauth.verifyToken(response.getAccessToken());
        assertTrue(initialAccessToken.getScope().contains("offline_access"));
        assertFalse(initialAccessToken.getOtherClaims().containsKey("amr_details"));

        AccessTokenResponse refreshResponse = oauth.doRefreshTokenRequest(response.getRefreshToken());
        assertEquals(200, refreshResponse.getStatusCode());
        IDToken refreshed = oauth.verifyIDToken(refreshResponse.getIdToken());
        assertEquals(initialDetail, onlyAuthenticationDetail(refreshed));
        assertFalse(oauth.verifyToken(refreshResponse.getAccessToken()).getOtherClaims().containsKey("amr_details"));
    }

    @Test
    public void realmSwitchGatesWellKnownOidc4acMetadata() throws IOException {
        RealmRepresentation realm = managedRealm.admin().toRepresentation();
        Map<String, String> attributes = new LinkedHashMap<>();
        if (realm.getAttributes() != null) {
            attributes.putAll(realm.getAttributes());
        }
        attributes.put("oidc4ac.enabled", "false");
        realm.setAttributes(attributes);
        managedRealm.admin().update(realm);
        try (CloseableHttpClient client = HttpClientBuilder.create().build()) {
            OIDCConfigurationRepresentation disabled = SimpleHttpDefault
                    .doGet(getAuthServerRoot().toString() + "realms/test/.well-known/openid-configuration", client)
                    .asJson(OIDCConfigurationRepresentation.class);
            assertFalse(disabled.getClaimsSupported().contains("amr_details"));
            assertFalse(disabled.getOtherClaims().containsKey("amr_identifiers_supported"));
        } finally {
            attributes.put("oidc4ac.enabled", "true");
            realm.setAttributes(attributes);
            managedRealm.admin().update(realm);
        }
    }

    @Test
    public void encryptedJarmPreservesGenericAuthenticationRequirementError() throws Exception {
        TestOIDCEndpointsApplicationResource oidcClientEndpointsResource = testingClient.testApp().oidcClientEndpoints();
        oidcClientEndpointsResource.generateKeys(JWEConstants.RSA_OAEP);

        var clientResource = AdminApiUtil.findClientByClientId(adminClient.realm("test"), CLIENT_ID);
        ClientRepresentation client = clientResource.toRepresentation();
        OIDCAdvancedConfigWrapper config = OIDCAdvancedConfigWrapper.fromClientRepresentation(client);
        config.setAuthorizationSignedResponseAlg(Algorithm.RS256);
        config.setAuthorizationEncryptedResponseAlg(JWEConstants.RSA_OAEP);
        config.setAuthorizationEncryptedResponseEnc(JWEConstants.A256GCM);
        config.setUseJwksUrl(true);
        config.setJwksUrl(TestApplicationResourceUrls.clientJwksUri());
        clientResource.update(client);

        try {
            String state = "oidc4ac-encrypted-error-state";
            String claims = JsonSerialization.writeValueAsString(Map.of(
                    "id_token", Map.of("amr_details", Map.of(
                            "essential", true,
                            "amr_identifier", Map.of("value", "face"),
                            "amr_metadata", Map.of("time", Map.of("essential", true))))));

            oauth.responseMode("jwt");
            AuthorizationEndpointResponse response = oauth.loginForm()
                    .param(OIDCLoginProtocol.CLAIMS_PARAM, URLEncoder.encode(claims, StandardCharsets.UTF_8))
                    .state(state)
                    .doLogin("test-user@localhost", "password");

            String encryptedResponse = response.getResponse();
            String[] parts = encryptedResponse.split("\\.");
            assertEquals(5, parts.length);
            byte[] plaintext = TokenUtil.jweKeyEncryptionVerifyAndDecode(
                    PemUtils.decodePrivateKey(oidcClientEndpointsResource.getKeysAsPem().get("privateKey")),
                    encryptedResponse,
                    new RsaCekManagementProvider(null, JWEConstants.RSA_OAEP).jweAlgorithmProvider(),
                    new AesGcmContentEncryptionProvider(null, JWEConstants.A256GCM).jweEncryptionProvider());

            AuthorizationResponseToken token = oauth.verifyAuthorizationResponseToken(
                    new String(plaintext, StandardCharsets.UTF_8));
            assertEquals("unmet_authentication_requirements", token.getOtherClaims().get("error"));
            assertEquals(state, token.getOtherClaims().get("state"));
            assertTrue(((String) token.getOtherClaims().get("error_description")).length() > 0);
        } finally {
            ClientRepresentation restored = clientResource.toRepresentation();
            OIDCAdvancedConfigWrapper restoredConfig = OIDCAdvancedConfigWrapper.fromClientRepresentation(restored);
            restoredConfig.setAuthorizationSignedResponseAlg(Algorithm.RS256);
            restoredConfig.setAuthorizationEncryptedResponseAlg(null);
            restoredConfig.setAuthorizationEncryptedResponseEnc(null);
            restoredConfig.setUseJwksUrl(false);
            restoredConfig.setJwksUrl(null);
            clientResource.update(restored);
        }
    }

    private AccessTokenResponse login(Map<String, Object> claims) throws IOException {
        return login(claims, "openid");
    }

    private AccessTokenResponse login(Map<String, Object> claims, String scope) throws IOException {
        oauth.scope(scope);
        String claimsJson = JsonSerialization.writeValueAsString(claims);
        oauth.loginForm().param(OIDCLoginProtocol.CLAIMS_PARAM, URLEncoder.encode(claimsJson, StandardCharsets.UTF_8)).open();
        loginPage.assertCurrent();
        loginPage.login("test-user@localhost", "password");
        assertEquals(AppPage.RequestType.AUTH_RESPONSE, appPage.getRequestType());

        AuthorizationEndpointResponse authorizationResponse = oauth.parseLoginResponse();
        assertTrue(authorizationResponse.isSuccess());
        AccessTokenResponse response = oauth.client(CLIENT_ID, CLIENT_SECRET).doAccessTokenRequest(authorizationResponse.getCode());
        assertEquals(200, response.getStatusCode());
        return response;
    }

    private Map<String, Object> passwordClaimsRequest() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("pwd_derivation_algorithm", null);

        Map<String, Object> idTokenMethod = new LinkedHashMap<>();
        idTokenMethod.put("amr_identifier", Map.of("value", "pwd"));
        idTokenMethod.put("amr_metadata", Map.of("time", Map.of("essential", true)));
        idTokenMethod.put("amr_properties", properties);

        // Every method expression is subject to the same structural grammar,
        // including when it is requested only in UserInfo.  In particular,
        // amr_metadata.time is mandatory for each method expression.
        Map<String, Object> userInfoMethod = Map.of(
                "amr_identifier", Map.of("value", "pwd"),
                "amr_metadata", Map.of("time", Map.of("essential", true)));
        return Map.of(
                "id_token", Map.of("amr_details", Map.of("essential", true, "amr_identifier", idTokenMethod.get("amr_identifier"),
                        "amr_metadata", idTokenMethod.get("amr_metadata"), "amr_properties", idTokenMethod.get("amr_properties"))),
                "userinfo", Map.of("amr_details", userInfoMethod));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> onlyAuthenticationDetail(IDToken token) {
        return onlyAuthenticationDetail(token.getOtherClaims());
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> onlyAuthenticationDetail(UserInfo token) {
        return onlyAuthenticationDetail(token.getOtherClaims());
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> onlyAuthenticationDetail(Map<String, Object> claims) {
        Object details = claims.get("amr_details");
        assertTrue(details instanceof List<?>);
        List<?> values = (List<?>) details;
        assertEquals(1, values.size());
        assertTrue(values.get(0) instanceof Map<?, ?>);
        return (Map<String, Object>) values.get(0);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> object(Map<String, Object> parent, String name) {
        Object value = parent.get(name);
        assertTrue(value instanceof Map<?, ?>);
        return (Map<String, Object>) value;
    }
}
