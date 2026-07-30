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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Proxy;

import org.junit.Test;
import org.keycloak.models.RealmModel;

public class OIDC4ACRealmSettingsTest {

    @Test
    public void defaultsToEnabledForExistingRealms() {
        RealmModel realm = realmWithAttribute(null);

        assertTrue(OIDC4ACRealmSettings.isEnabled(realm));
    }

    @Test
    public void honorsExplicitRealmSwitch() {
        assertFalse(OIDC4ACRealmSettings.isEnabled(realmWithAttribute("false")));
        assertTrue(OIDC4ACRealmSettings.isEnabled(realmWithAttribute("true")));
    }

    private static RealmModel realmWithAttribute(String value) {
        return (RealmModel) Proxy.newProxyInstance(RealmModel.class.getClassLoader(), new Class<?>[] { RealmModel.class },
                (proxy, method, args) -> {
                    if ("getAttribute".equals(method.getName()) && OIDC4ACRealmSettings.ENABLED_ATTRIBUTE.equals(args[0])) {
                        return value;
                    }
                    if ("toString".equals(method.getName())) {
                        return "realm";
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }
}
