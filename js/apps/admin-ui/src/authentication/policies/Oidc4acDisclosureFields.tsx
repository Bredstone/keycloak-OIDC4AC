import {
  Checkbox,
  Divider,
  EmptyState,
  EmptyStateBody,
  Grid,
  GridItem,
  HelperText,
  HelperTextItem,
  Label,
  Tab,
  Tabs,
  TabTitleText,
  Title,
} from "@patternfly/react-core";
import { useEffect, useState } from "react";

export type Discovery = Record<string, unknown>;
export type Capability = {
  identifier: string;
  properties: string[];
  metadata: string[];
  values: Record<string, string[]>;
};

export type DisclosureField = {
  path: string;
  name: string;
  values: string[];
};

const asStrings = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];

export const capabilitiesFromDiscovery = (discovery: Discovery): Capability[] =>
  asStrings(discovery.amr_identifiers_supported).map((identifier) => {
    const properties = asStrings(
      discovery[`${identifier}_properties_supported`],
    );
    const metadata = asStrings(discovery[`${identifier}_metadata_supported`]);
    const values = Object.fromEntries(
      properties.map((property) => [
        property,
        asStrings(discovery[`${property}_values_supported`]),
      ]),
    );
    return { identifier, properties, metadata, values };
  });

const metadataFieldsFor = (capabilities: Capability[]): DisclosureField[] => {
  const names = new Set(
    capabilities.flatMap((capability) => capability.metadata),
  );
  return [...names]
    .filter((name) => name !== "time")
    .map((name) => ({
      path: `amr_metadata.${name}`,
      name,
      values: [],
    }));
};

const propertyFieldsFor = (capability: Capability): DisclosureField[] =>
  capability.properties.map((name) => ({
    path: `amr_properties.${name}`,
    name,
    values: capability.values[name],
  }));

const FieldGrid = ({
  fields,
  selected,
  onToggle,
  disabled,
  idPrefix,
  capability,
}: {
  fields: DisclosureField[];
  selected: Set<string>;
  onToggle: (path: string) => void;
  disabled: boolean;
  idPrefix: string;
  capability: string;
}) => (
  <Grid hasGutter className="pf-v5-u-mt-md">
    {fields.map((field) => (
      <GridItem key={field.path} span={6}>
        <Checkbox
          id={`${idPrefix}-${capability}-${field.name}`}
          label={
            <>
              <code>{field.path}</code>
              {field.values.length > 0 && (
                <span className="pf-v5-u-ml-sm">
                  {field.values.map((value) => (
                    <Label
                      key={value}
                      isCompact
                      color="blue"
                      className="pf-v5-u-mr-xs"
                    >
                      {value}
                    </Label>
                  ))}
                </span>
              )}
            </>
          }
          isChecked={selected.has(field.path)}
          isDisabled={disabled}
          onChange={() => onToggle(field.path)}
        />
      </GridItem>
    ))}
  </Grid>
);

export function DisclosureFields({
  capabilities,
  selected,
  onToggle,
  disabled,
  idPrefix,
}: {
  capabilities: Capability[];
  selected: Set<string>;
  onToggle: (path: string) => void;
  disabled: boolean;
  idPrefix: string;
}) {
  const [active, setActive] = useState(capabilities[0]?.identifier || "");

  useEffect(() => {
    if (!capabilities.some((capability) => capability.identifier === active)) {
      setActive(capabilities[0]?.identifier || "");
    }
  }, [active, capabilities]);

  if (capabilities.length === 0) {
    return (
      <EmptyState variant="xs">
        <EmptyStateBody>
          No authentication-method capabilities were advertised by this Keycloak
          instance.
        </EmptyStateBody>
      </EmptyState>
    );
  }

  const metadataFields = metadataFieldsFor(capabilities);

  return (
    <>
      <Title headingLevel="h3" size="lg" className="pf-v5-u-mb-sm">
        Optional metadata
      </Title>
      <p className="pf-v5-u-mb-md">
        Metadata describes the authentication event and applies to every
        authentication method. The mandatory <code>amr_metadata.time</code>{" "}
        value is always retained.
      </p>
      <HelperText>
        <HelperTextItem>
          <strong>amr_identifier</strong> and <strong>amr_metadata.time</strong>{" "}
          are always preserved and are not configurable here.
        </HelperTextItem>
      </HelperText>
      {metadataFields.length > 0 ? (
        <FieldGrid
          fields={metadataFields}
          selected={selected}
          onToggle={onToggle}
          disabled={disabled}
          idPrefix={idPrefix}
          capability="metadata"
        />
      ) : (
        <p className="pf-v5-u-mt-md">No optional metadata was advertised.</p>
      )}
      <Divider className="pf-v5-u-my-lg" />
      <Title headingLevel="h3" size="lg" className="pf-v5-u-mb-sm">
        Authentication method properties
      </Title>
      <p className="pf-v5-u-mb-md">
        Properties describe the method or credential used for each execution.
        Select a method to configure its optional properties.
      </p>
      <Tabs
        activeKey={active}
        onSelect={(_, key) => setActive(key as string)}
        mountOnEnter
        unmountOnExit
      >
        {capabilities.map((capability) => {
          const propertyFields = propertyFieldsFor(capability);
          return (
            <Tab
              key={capability.identifier}
              eventKey={capability.identifier}
              id={`${idPrefix}-${capability.identifier}`}
              title={<TabTitleText>{capability.identifier}</TabTitleText>}
            >
              <div className="pf-v5-u-pt-md">
                <p className="pf-v5-u-mb-md">
                  Select optional properties that may be disclosed for{" "}
                  <strong>{capability.identifier}</strong>. Enumerated values
                  are shown beside each property.
                </p>
                {propertyFields.length > 0 ? (
                  <FieldGrid
                    fields={propertyFields}
                    selected={selected}
                    onToggle={onToggle}
                    disabled={disabled}
                    idPrefix={idPrefix}
                    capability={capability.identifier}
                  />
                ) : (
                  <p>This method has no optional properties advertised.</p>
                )}
              </div>
            </Tab>
          );
        })}
      </Tabs>
    </>
  );
}
