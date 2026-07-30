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
package org.keycloak.protocol.oidc4ac;

import org.keycloak.models.RealmModel;

/** Realm-scoped switches for the experimental OIDC4AC feature. */
public final class OIDC4ACRealmSettings {

    /** Realm attribute used by the Admin Console and realm import/export. */
    public static final String ENABLED_ATTRIBUTE = "oidc4ac.enabled";

    private OIDC4ACRealmSettings() {
    }

    /**
     * Existing realms remain enabled unless an administrator explicitly turns
     * OIDC4AC off. This preserves the feature's previous profile-gated
     * behavior while making the per-realm switch opt-out.
     */
    public static boolean isEnabled(RealmModel realm) {
        if (realm == null) {
            return true;
        }
        String value = realm.getAttribute(ENABLED_ATTRIBUTE);
        return value == null || Boolean.parseBoolean(value);
    }
}
