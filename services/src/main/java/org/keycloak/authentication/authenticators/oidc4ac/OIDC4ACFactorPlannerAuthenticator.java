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
package org.keycloak.authentication.authenticators.oidc4ac;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.Profile;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc4ac.error.OIDC4ACAuthenticationFailureBridge;
import org.keycloak.protocol.oidc4ac.flow.AuthenticationFactorBinding;
import org.keycloak.protocol.oidc4ac.flow.AuthenticationFactorPlan;
import org.keycloak.protocol.oidc4ac.flow.AuthenticationFactorPlanPlanner;
import org.keycloak.protocol.oidc4ac.flow.AuthenticationFactorPlanResult;
import org.keycloak.protocol.oidc4ac.flow.AuthenticationFactorPlanStore;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsClaimsRequest;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsRequestException;
import org.keycloak.protocol.oidc4ac.request.AmrDetailsRequestParser;
import org.keycloak.protocol.oidc4ac.spi.AuthenticationMethodCapability;
import org.keycloak.protocol.oidc4ac.spi.AuthenticationMethodDetailsProvider;

/**
 * Builds one opaque, request-scoped factor plan for a configured sibling
 * subflow. The target container exposes only administrator-configured child
 * subflows named {@code oidc4ac:<amr_identifier>}; no RP input is ever used as
 * a Keycloak provider or flow identifier.
 */
public final class OIDC4ACFactorPlannerAuthenticator implements Authenticator {

    static final OIDC4ACFactorPlannerAuthenticator SINGLETON = new OIDC4ACFactorPlannerAuthenticator();
    static final String FACTOR_FLOW_ALIAS = "factor_flow_alias";
    static final String FACTOR_ALIAS_PREFIX = "oidc4ac:";

    private OIDC4ACFactorPlannerAuthenticator() {
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        Optional<String> factorFlowAlias = configuredFactorFlowAlias(context);
        if (factorFlowAlias.isEmpty()) {
            context.success();
            return;
        }
        try {
            AuthenticationFlowModel factorFlow = configuredSiblingFactorFlow(context, factorFlowAlias.orElseThrow());
            Optional<AuthenticationFactorPlan> existingPlan = AuthenticationFactorPlanStore.read(context.getAuthenticationSession());
            if (existingPlan.isPresent() && !factorFlow.getId().equals(existingPlan.orElseThrow().factorFlowId())) {
                throw new IllegalArgumentException("Only one OIDC4AC factor container may be planned per authorization");
            }
            if (existingPlan.isPresent()) {
                context.success();
                return;
            }
            if (!Profile.isFeatureEnabled(Profile.Feature.OIDC4AC)
                    || !OIDCLoginProtocol.LOGIN_PROTOCOL.equals(context.getAuthenticationSession().getProtocol())) {
                context.success();
                return;
            }
            var requests = AmrDetailsRequestParser.parseClaimsParameter(
                    context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.CLAIMS_PARAM));
            if (!hasRequestedAmrDetails(requests)) {
                // Do not turn the configured factor container into a no-op for
                // an ordinary browser/account login. Without an OIDC4AC
                // request, its normal ALTERNATIVE policy remains in charge.
                context.success();
                return;
            }
            List<AuthenticationFactorBinding> bindings = bindings(context, factorFlow);
            AuthenticationFactorPlanResult result = new AuthenticationFactorPlanPlanner().plan(requests,
                    factorFlow.getId(), bindings);
            if (result.essentialRequirementsUnplannable()) {
                OIDC4ACAuthenticationFailureBridge.markUnmetAuthenticationRequirement(context.getAuthenticationSession());
                context.failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR);
                return;
            }
            if (result.plan().steps().isEmpty()) {
                // A non-essential request may name only unavailable methods or
                // constraints. It remains a best-effort preference and must
                // not activate an empty request-scoped container that would
                // otherwise prevent ordinary authentication from completing.
                context.success();
                return;
            }
            AuthenticationFactorPlanStore.storeIfAbsent(context.getAuthenticationSession(), result.plan());
            context.success();
        } catch (AmrDetailsRequestException | IllegalArgumentException e) {
            // The authorization endpoint validator handles malformed claims.
            // A malformed administrator binding is indistinguishable from an
            // unavailable method to an RP with an essential requirement.
            context.failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR);
        }
    }

    static boolean hasRequestedAmrDetails(AmrDetailsClaimsRequest requests) {
        return !requests.isEmpty();
    }

    private Optional<String> configuredFactorFlowAlias(AuthenticationFlowContext context) {
        AuthenticatorConfigModel configuration = context.getAuthenticatorConfig();
        String alias = configuration == null || configuration.getConfig() == null ? null
                : configuration.getConfig().get(FACTOR_FLOW_ALIAS);
        if (alias == null || alias.isBlank()) {
            return Optional.empty();
        }
        return Optional.of(alias);
    }

    private AuthenticationFlowModel configuredSiblingFactorFlow(AuthenticationFlowContext context, String alias) {
        RealmModel realm = context.getRealm();
        AuthenticationFlowModel factorFlow = realm.getFlowByAlias(alias);
        if (factorFlow == null) {
            throw new IllegalArgumentException("Configured OIDC4AC factor flow does not exist");
        }
        Optional<AuthenticationExecutionModel> target = realm.getAuthenticationExecutionsStream(context.getExecution().getParentFlow())
                .filter(execution -> execution.isAuthenticatorFlow() && factorFlow.getId().equals(execution.getFlowId()))
                .findFirst();
        if (target.isEmpty() || !target.orElseThrow().isRequired()
                || target.orElseThrow().getPriority() <= context.getExecution().getPriority()) {
            throw new IllegalArgumentException("Configured OIDC4AC factor flow is not a later required sibling");
        }
        return factorFlow;
    }

    private List<AuthenticationFactorBinding> bindings(AuthenticationFlowContext context, AuthenticationFlowModel factorFlow) {
        Map<String, Set<String>> propertiesByIdentifier = supportedProperties(context.getSession());
        List<AuthenticationFactorBinding> bindings = new ArrayList<>();
        context.getRealm().getAuthenticationExecutionsStream(factorFlow.getId()).forEachOrdered(execution -> {
            if (!execution.isAuthenticatorFlow() || !execution.isAlternative()) {
                return;
            }
            AuthenticationFlowModel factor = context.getRealm().getAuthenticationFlowById(execution.getFlowId());
            String identifier = identifierFor(factor);
            if (identifier != null && propertiesByIdentifier.containsKey(identifier)) {
                bindings.add(new AuthenticationFactorBinding(execution.getId(), identifier, execution.getPriority(),
                        propertiesByIdentifier.get(identifier)));
            }
        });
        return List.copyOf(bindings);
    }

    private Map<String, Set<String>> supportedProperties(KeycloakSession session) {
        Map<String, Set<String>> propertiesByIdentifier = new LinkedHashMap<>();
        for (AuthenticationMethodDetailsProvider provider : session.getAllProviders(AuthenticationMethodDetailsProvider.class)) {
            try {
                for (AuthenticationMethodCapability capability : provider.getCapabilities()) {
                    propertiesByIdentifier.computeIfAbsent(capability.amrIdentifier(), ignored -> new LinkedHashSet<>())
                            .addAll(capability.propertyNames());
                }
            } catch (RuntimeException e) {
                // A broken optional adapter must neither select a flow nor
                // change ordinary browser authentication behavior.
            }
        }
        return propertiesByIdentifier.entrySet().stream().collect(java.util.stream.Collectors.toUnmodifiableMap(
                Map.Entry::getKey, entry -> Set.copyOf(entry.getValue())));
    }

    private String identifierFor(AuthenticationFlowModel factor) {
        if (factor == null || factor.getAlias() == null || !factor.getAlias().startsWith(FACTOR_ALIAS_PREFIX)) {
            return null;
        }
        String identifier = factor.getAlias().substring(FACTOR_ALIAS_PREFIX.length());
        return identifier.isBlank() ? null : identifier;
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // This authenticator never challenges the End-User.
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // No required action is associated with routing.
    }

    @Override
    public void close() {
        // Singleton has no resources.
    }
}
