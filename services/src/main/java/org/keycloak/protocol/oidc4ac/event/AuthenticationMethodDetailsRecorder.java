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
package org.keycloak.protocol.oidc4ac.event;

import java.time.Instant;
import java.util.List;

import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.common.Profile;
import org.keycloak.common.util.Time;
import org.keycloak.events.Details;
import org.keycloak.protocol.oidc4ac.OIDC4ACRealmSettings;
import org.keycloak.protocol.oidc4ac.spi.AuthenticationMethodDetails;
import org.keycloak.protocol.oidc4ac.spi.AuthenticationMethodDetailsContext;
import org.keycloak.protocol.oidc4ac.spi.AuthenticationMethodDetailsProvider;

import org.jboss.logging.Logger;

/** Captures safe details only for a successful current-flow execution. */
public final class AuthenticationMethodDetailsRecorder {

    private static final Logger LOG = Logger.getLogger(AuthenticationMethodDetailsRecorder.class);

    private AuthenticationMethodDetailsRecorder() {
    }

    public static void record(AuthenticationProcessor processor, AuthenticationProcessor.Result result) {
        if (!Profile.isFeatureEnabled(Profile.Feature.OIDC4AC)
                || !OIDC4ACRealmSettings.isEnabled(processor.getRealm())
                || processor.getAuthenticationSession().getAuthenticatedUser() == null) {
            return;
        }

        AuthenticationMethodDetailsContext context = new AuthenticationMethodDetailsContext(processor.getSession(), processor.getRealm(),
                processor.getAuthenticationSession().getAuthenticatedUser(), processor.getAuthenticationSession(), processor.getUserSession(),
                result.getExecution().getAuthenticator(), result.getExecution().getId(), result.getCredentialType(),
                selectedCredentialId(processor), Instant.ofEpochSecond(Time.currentTime()));
        List<AuthenticationMethodDetails> details = new java.util.ArrayList<>();
        for (AuthenticationMethodDetailsProvider provider : processor.getSession().getAllProviders(AuthenticationMethodDetailsProvider.class)) {
            try {
                if (provider.supports(context)) {
                    provider.describeSuccessfulExecution(context).ifPresent(details::add);
                }
            } catch (RuntimeException e) {
                // Method-detail adapters are optional observability providers. They must not affect login.
                LOG.warn("An OIDC4AC authentication-method-details provider failed; omitting its details");
            }
        }
        if (details.size() == 1) {
            AuthenticationEventSnapshotStore.append(processor.getAuthenticationSession(), AuthenticationEventSnapshotCodec.fromDetails(details.get(0)));
        }
    }

    /**
     * The browser OTP authenticator writes this event detail before validating
     * the selected credential. This recorder runs only after that authenticator
     * has succeeded, so the identifier identifies the credential just verified.
     * It is passed to private adapters only and never serialized into an event
     * snapshot or a token.
     */
    private static String selectedCredentialId(AuthenticationProcessor processor) {
        java.util.Map<String, String> details = processor.getEvent().getEvent().getDetails();
        return details == null ? null : details.get(Details.SELECTED_CREDENTIAL_ID);
    }
}
