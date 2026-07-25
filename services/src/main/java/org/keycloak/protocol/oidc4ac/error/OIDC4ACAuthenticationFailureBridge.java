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
package org.keycloak.protocol.oidc4ac.error;

import java.util.List;
import java.util.Optional;

import jakarta.ws.rs.core.Response;

import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.common.Profile;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsClaimRequest;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsClaimsRequest;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsRequestException;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsRequestParser;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Converts only terminal method-requirement failures into the author-approved
 * OIDC response. It deliberately leaves an End-User cancellation as Keycloak's
 * ordinary {@code access_denied} response.
 */
public final class OIDC4ACAuthenticationFailureBridge {

    private OIDC4ACAuthenticationFailureBridge() {
    }

    public static Optional<Response> responseFor(KeycloakSession session, AuthenticationSessionModel authenticationSession,
            AuthenticationFlowException failure) {
        if (!isApplicable(authenticationSession, failure)) {
            return Optional.empty();
        }
        LoginProtocol protocol = session.getProvider(LoginProtocol.class, OIDCLoginProtocol.LOGIN_PROTOCOL);
        if (protocol instanceof OIDCLoginProtocol oidc) {
            return Optional.of(oidc.sendUnmetAuthenticationRequirements(authenticationSession));
        }
        return Optional.empty();
    }

    static boolean isApplicable(AuthenticationSessionModel authenticationSession, AuthenticationFlowException failure) {
        if (!Profile.isFeatureEnabled(Profile.Feature.OIDC4AC)
                || !OIDCLoginProtocol.LOGIN_PROTOCOL.equals(authenticationSession.getProtocol())) {
            return false;
        }
        List<AuthenticationFlowException> failures = failure.getAfeList() == null ? List.of(failure) : failure.getAfeList();
        if (failures.stream().anyMatch(item -> item.getError() == AuthenticationFlowError.ACCESS_DENIED)
                || failures.stream().noneMatch(item -> isMethodRequirementFailure(item.getError()))) {
            return false;
        }
        try {
            AmrDetailsClaimsRequest requests = AmrDetailsRequestParser.parseClaimsParameter(
                    authenticationSession.getClientNote(OIDCLoginProtocol.CLAIMS_PARAM));
            return isEssential(requests.idToken()) || isEssential(requests.userInfo());
        } catch (AmrDetailsRequestException e) {
            // Malformed claims are handled before the browser flow starts.
            return false;
        }
    }

    private static boolean isEssential(Optional<AmrDetailsClaimRequest> request) {
        return request.map(AmrDetailsClaimRequest::essential).orElse(false);
    }

    private static boolean isMethodRequirementFailure(AuthenticationFlowError error) {
        return error == AuthenticationFlowError.CREDENTIAL_SETUP_REQUIRED
                || error == AuthenticationFlowError.INVALID_CREDENTIALS
                || error == AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR;
    }
}
