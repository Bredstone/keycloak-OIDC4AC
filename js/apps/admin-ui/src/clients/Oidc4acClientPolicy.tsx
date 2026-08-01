import type ClientRepresentation from "@keycloak/keycloak-admin-client/lib/defs/clientRepresentation";
import { fetchWithError } from "@keycloak/keycloak-admin-client";
import {
  Alert,
  Card,
  CardBody,
  CardTitle,
  PageSection,
  Switch,
  Title,
} from "@patternfly/react-core";
import { useAlerts, useEnvironment } from "@keycloak/keycloak-ui-shared";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAdminClient } from "../admin-client";
import { FixedButtonsGroup } from "../components/form/FixedButtonGroup";
import { FormAccess } from "../components/form/FormAccess";
import { useRealm } from "../context/realm-context/RealmContext";
import type { Environment } from "../environment-types";
import { addTrailingSlash } from "../util";
import { getAuthorizationHeaders } from "../utils/getAuthorizationHeaders";
import {
  capabilitiesFromDiscovery,
  DEFAULT_DISCLOSURE_MODE,
  disclosureModesFromCapabilities,
  DisclosureFields,
  type Capability,
  type DisclosureMode as FieldDisclosureMode,
} from "../authentication/policies/Oidc4acDisclosureFields";
import style from "../authentication/policies/oidc4ac-policy.module.css";

type Configuration = {
  clientDisclosureModes?: Record<string, FieldDisclosureMode>;
};

export function Oidc4acClientPolicy({
  client,
}: {
  client: ClientRepresentation;
}) {
  const { t } = useTranslation();
  const { realm } = useRealm();
  const { adminClient } = useAdminClient();
  const { environment } = useEnvironment<Environment>();
  const { addAlert, addError } = useAlerts();
  const [capabilities, setCapabilities] = useState<Capability[]>([]);
  const [overrideRealmPolicy, setOverrideRealmPolicy] = useState(false);
  const [fieldModes, setFieldModes] = useState<
    Record<string, FieldDisclosureMode>
  >({});
  const [initial, setInitial] = useState({
    overrideRealmPolicy: false,
    fieldModes: {} as Record<string, FieldDisclosureMode>,
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string>();

  const endpoint = `${addTrailingSlash(adminClient.baseUrl)}admin/realms/${realm}/ui-ext/oidc4ac?clientId=${encodeURIComponent(client.clientId || "")}`;

  useEffect(() => {
    void (async () => {
      try {
        const [configResponse, discoveryResponse] = await Promise.all([
          fetchWithError(endpoint, {
            headers: getAuthorizationHeaders(
              await adminClient.getAccessToken(),
            ),
          }).then((response) => response.json() as Promise<Configuration>),
          fetchWithError(
            `${addTrailingSlash(environment.serverBaseUrl)}realms/${realm}/.well-known/openid-configuration`,
          ).then(
            (response) => response.json() as Promise<Record<string, unknown>>,
          ),
        ]);
        const discoveredCapabilities =
          capabilitiesFromDiscovery(discoveryResponse);
        const configuredModes = configResponse.clientDisclosureModes || {};
        const initialModes = {
          ...disclosureModesFromCapabilities(discoveredCapabilities),
          ...configuredModes,
        };
        const hasOverride = Object.keys(configuredModes).length > 0;
        setCapabilities(discoveredCapabilities);
        setOverrideRealmPolicy(hasOverride);
        setFieldModes(initialModes);
        setInitial({
          overrideRealmPolicy: hasOverride,
          fieldModes: initialModes,
        });
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : String(cause));
      } finally {
        setLoading(false);
      }
    })();
  }, [adminClient, endpoint, environment.serverBaseUrl, realm]);

  const changeFieldMode = (path: string, fieldMode: FieldDisclosureMode) =>
    setFieldModes((current) => ({ ...current, [path]: fieldMode }));

  const setOverride = (override: boolean) => {
    setOverrideRealmPolicy(override);
    if (override && Object.keys(fieldModes).length === 0) {
      setFieldModes(disclosureModesFromCapabilities(capabilities));
    }
  };

  const save = async () => {
    setSaving(true);
    setError(undefined);
    try {
      await fetchWithError(
        `${addTrailingSlash(adminClient.baseUrl)}admin/realms/${realm}/ui-ext/oidc4ac`,
        {
          method: "PUT",
          headers: {
            ...getAuthorizationHeaders(await adminClient.getAccessToken()),
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            clientId: client.clientId,
            clientIds: [client.clientId],
            clientDisclosureModes: overrideRealmPolicy ? fieldModes : {},
            realmPolicyUpdate: false,
            clientPolicyUpdate: true,
          }),
        },
      );
      setInitial({ overrideRealmPolicy, fieldModes });
      addAlert(t("itemSaveSuccessful"));
    } catch (cause) {
      addError("itemSaveError", cause);
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setSaving(false);
    }
  };

  const reset = () => {
    setOverrideRealmPolicy(initial.overrideRealmPolicy);
    setFieldModes(initial.fieldModes);
    setError(undefined);
  };

  return (
    <PageSection>
      <Title headingLevel="h2" size="xl" className="pf-v5-u-mb-lg">
        OIDC4AC disclosure policy
      </Title>
      {error && (
        <Alert
          variant="danger"
          title={t("error")}
          isInline
          className="pf-v5-u-mb-lg"
        >
          {error}
        </Alert>
      )}
      <FormAccess
        isHorizontal
        className={style.fullWidthForm}
        fineGrainedAccess={client.access?.configure}
        role="manage-clients"
        onSubmit={(event) => {
          event.preventDefault();
          void save();
        }}
      >
        <Card>
          <CardTitle>Client disclosure policy</CardTitle>
          <CardBody>
            <p className="pf-v5-u-mb-lg">
              Control which optional authentication-method metadata and
              properties this client may receive. Mandatory identifiers and
              execution times are always preserved.
            </p>
            <Switch
              id="oidc4ac-client-override-realm-policy"
              label="Override realm disclosure settings for this client"
              labelOff="Use realm disclosure settings"
              isChecked={overrideRealmPolicy}
              onChange={(_, checked) => setOverride(checked)}
              isDisabled={loading}
            />
          </CardBody>
        </Card>
        <div className="pf-v5-u-mt-md">
          <DisclosureFields
            capabilities={capabilities}
            modes={fieldModes}
            fallbackMode={DEFAULT_DISCLOSURE_MODE}
            onModeChange={changeFieldMode}
            disabled={loading || !overrideRealmPolicy}
            idPrefix="oidc4ac-client-field"
          />
        </div>
        <FixedButtonsGroup
          name="oidc4ac-client-policy"
          reset={reset}
          isSubmit
          isDisabled={loading || saving}
        />
      </FormAccess>
    </PageSection>
  );
}
