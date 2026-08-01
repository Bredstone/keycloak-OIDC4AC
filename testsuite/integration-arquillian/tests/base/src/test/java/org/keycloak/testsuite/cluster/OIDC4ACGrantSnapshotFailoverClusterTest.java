/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package org.keycloak.testsuite.cluster;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import org.keycloak.common.Profile;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.UserInfo;
import org.keycloak.testsuite.arquillian.annotation.EnableFeature;
import org.keycloak.testsuite.util.oauth.AccessTokenResponse;
import org.keycloak.util.JsonSerialization;

import org.junit.Test;
import org.openqa.selenium.Cookie;

import static org.keycloak.testsuite.util.WaitUtils.pause;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that an OIDC4AC grant snapshot remains available after the backend
 * node that issued the authorization is stopped. Run with the clustered
 * Quarkus profile, a shared non-H2 database, and two session-cache owners.
 */
@EnableFeature(value = Profile.Feature.OIDC4AC, skipRestart = true)
public class OIDC4ACGrantSnapshotFailoverClusterTest extends AbstractFailoverClusterTest {

    @Test
    public void grantSnapshotSurvivesBackendFailover() throws IOException {
        oauth.client("test-app", "password");
        oauth.scope("openid offline_access");

        AccessTokenResponse initial = loginWithAmrDetails();
        IDToken initialIdToken = oauth.verifyIDToken(initial.getIdToken());
        Map<String, Object> initialDetail = onlyAuthenticationDetail(initialIdToken);
        assertEquals("pwd", initialDetail.get("amr_identifier"));
        assertNotNull(object(initialDetail, "amr_metadata").get("time"));
        assertFalse(oauth.verifyToken(initial.getAccessToken()).getOtherClaims().containsKey("amr_details"));

        UserInfo initialUserInfo = oauth.doUserInfoRequest(initial.getAccessToken()).getUserInfo();
        assertEquals(initialDetail, onlyAuthenticationDetail(initialUserInfo));

        Cookie sessionCookie = driver.manage().getCookieNamed(KEYCLOAK_SESSION_COOKIE);
        assertNotNull(sessionCookie);
        setCurrentFailNodeForRoute(sessionCookie.getValue());
        failure();
        pause(REBALANCE_WAIT);

        AccessTokenResponse refreshed = oauth.client("test-app", "password")
                .doRefreshTokenRequest(initial.getRefreshToken());
        assertEquals(200, refreshed.getStatusCode());
        assertEquals(initialDetail, onlyAuthenticationDetail(oauth.verifyIDToken(refreshed.getIdToken())));
        assertFalse(oauth.verifyToken(refreshed.getAccessToken()).getOtherClaims().containsKey("amr_details"));
        assertEquals(initialDetail, onlyAuthenticationDetail(
                oauth.doUserInfoRequest(refreshed.getAccessToken()).getUserInfo()));
    }

    private AccessTokenResponse loginWithAmrDetails() throws IOException {
        Map<String, Object> method = new LinkedHashMap<>();
        method.put("amr_identifier", Map.of("value", "pwd"));
        method.put("amr_metadata", Map.of("time", Map.of("essential", true)));
        Map<String, Object> claim = Map.of("essential", true, "amr_identifier", method.get("amr_identifier"),
                "amr_metadata", method.get("amr_metadata"));
        Map<String, Object> claims = Map.of(
                "id_token", Map.of("amr_details", claim),
                "userinfo", Map.of("amr_details", claim));

        String encoded = URLEncoder.encode(JsonSerialization.writeValueAsString(claims), StandardCharsets.UTF_8);
        oauth.loginForm().param(OIDCLoginProtocol.CLAIMS_PARAM, encoded).open();
        loginPage.assertCurrent();
        loginPage.login("test-user@localhost", "password");
        assertTrue(appPage.isCurrent());
        var authorizationResponse = oauth.parseLoginResponse();
        assertTrue(authorizationResponse.isSuccess());
        AccessTokenResponse response = oauth.client("test-app", "password")
                .doAccessTokenRequest(authorizationResponse.getCode());
        assertEquals(200, response.getStatusCode());
        return response;
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
        assertTrue(details instanceof java.util.List<?>);
        java.util.List<?> values = (java.util.List<?>) details;
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
