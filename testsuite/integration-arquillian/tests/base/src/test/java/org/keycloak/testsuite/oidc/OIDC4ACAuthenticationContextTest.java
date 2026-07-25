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
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.UserInfo;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.testsuite.arquillian.annotation.EnableFeature;
import org.keycloak.testsuite.pages.AppPage;
import org.keycloak.testsuite.util.oauth.AccessTokenResponse;
import org.keycloak.testsuite.util.oauth.AuthorizationEndpointResponse;
import org.keycloak.util.JsonSerialization;

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

    private AccessTokenResponse login(Map<String, Object> claims) throws IOException {
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

        Map<String, Object> userInfoMethod = Map.of("amr_identifier", Map.of("value", "pwd"));
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
