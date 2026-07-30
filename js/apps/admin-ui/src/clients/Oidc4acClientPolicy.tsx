import type ClientRepresentation from "@keycloak/keycloak-admin-client/lib/defs/clientRepresentation";
import { fetchWithError } from "@keycloak/keycloak-admin-client";
import {
  Alert,
  Card,
  CardBody,
  CardTitle,
  Divider,
  Form,
  FormGroup,
  PageSection,
  Radio,
  Title,
} from "@patternfly/react-core";
import { useEnvironment } from "@keycloak/keycloak-ui-shared";
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
  DisclosureFields,
  type Capability,
} from "../authentication/policies/Oidc4acDisclosureFields";

type ClientDisclosureMode = "inherit" | "selected" | "none";

type Configuration = {
  clientDisclosureMode?: ClientDisclosureMode;
  clientAllowedFields?: string[];
};

const modeOptions: Array<{
  value: ClientDisclosureMode;
  label: string;
  description: string;
}> = [
  {
    value: "inherit",
    label: "Use the realm default",
    description: "This client follows the realm disclosure policy.",
  },
  {
    value: "selected",
    label: "Allow only selected fields",
    description:
      "Only the fields selected below may be disclosed to this client.",
  },
  {
    value: "none",
    label: "Block optional fields",
    description:
      "This client receives only mandatory authentication-event fields.",
  },
];

export function Oidc4acClientPolicy({
  client,
}: {
  client: ClientRepresentation;
}) {
  const { t } = useTranslation();
  const { realm } = useRealm();
  const { adminClient } = useAdminClient();
  const { environment } = useEnvironment<Environment>();
  const [capabilities, setCapabilities] = useState<Capability[]>([]);
  const [mode, setMode] = useState<ClientDisclosureMode>("inherit");
  const [fields, setFields] = useState<Set<string>>(new Set());
  const [initial, setInitial] = useState({
    mode: "inherit" as ClientDisclosureMode,
    fields: [] as string[],
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
        const configuredMode = configResponse.clientDisclosureMode || "inherit";
        const configuredFields = configResponse.clientAllowedFields || [];
        setCapabilities(capabilitiesFromDiscovery(discoveryResponse));
        setMode(configuredMode);
        setFields(new Set(configuredFields));
        setInitial({ mode: configuredMode, fields: configuredFields });
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : String(cause));
      } finally {
        setLoading(false);
      }
    })();
  }, [adminClient, endpoint, environment.serverBaseUrl, realm]);

  const toggleField = (path: string) =>
    setFields((current) => {
      const next = new Set(current);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });

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
            clientDisclosureMode: mode,
            clientAllowedFields: Array.from(fields),
            realmPolicyUpdate: false,
            clientPolicyUpdate: true,
          }),
        },
      );
      setInitial({ mode, fields: Array.from(fields) });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setSaving(false);
    }
  };

  const reset = () => {
    setMode(initial.mode);
    setFields(new Set(initial.fields));
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
        fineGrainedAccess={client.access?.configure}
        role="manage-clients"
      >
        <Form
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
              <FormGroup label="Client policy" fieldId="oidc4ac-client-mode">
                {modeOptions.map((option) => (
                  <Radio
                    key={option.value}
                    id={`oidc4ac-client-mode-${option.value}`}
                    name="oidc4ac-client-mode"
                    label={option.label}
                    description={option.description}
                    isChecked={mode === option.value}
                    onChange={() => setMode(option.value)}
                    isDisabled={loading}
                  />
                ))}
              </FormGroup>
              <Divider className="pf-v5-u-my-lg" />
              <DisclosureFields
                capabilities={capabilities}
                selected={fields}
                onToggle={toggleField}
                disabled={loading || mode !== "selected"}
                idPrefix="oidc4ac-client-field"
              />
            </CardBody>
          </Card>
          <FixedButtonsGroup
            name="oidc4ac-client-policy"
            save={save}
            reset={reset}
            isDisabled={loading || saving}
          />
        </Form>
      </FormAccess>
    </PageSection>
  );
}
