/*
 * Copyright (C) 2015 Dell, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.quest.keycloak.broker.wsfed.mappers;

import com.quest.keycloak.broker.wsfed.WSFedEndpoint;
import com.quest.keycloak.broker.wsfed.WSFedIdentityProviderFactory;
import com.quest.keycloak.common.wsfed.utils.AttributeUtils;

import org.apache.commons.lang3.StringUtils;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.ConfigConstants;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.Arrays;
import java.util.List;

public class AttributeToRoleMapper extends AbstractIdentityProviderMapper {
    protected static final Logger logger = Logger.getLogger(AttributeToRoleMapper.class);

    private static final List<String> COMPATIBLE_PROVIDERS = Arrays.asList(WSFedIdentityProviderFactory.PROVIDER_ID);

    private static final List<ProviderConfigProperty> configProperties;

    public static final String ATTRIBUTE_NAME = "attribute.name";
    public static final String ATTRIBUTE_FRIENDLY_NAME = "attribute.friendly.name";
    public static final String ATTRIBUTE_VALUE = "attribute.value";

    static {
        configProperties = ProviderConfigurationBuilder.create()
            .property(ATTRIBUTE_NAME, "Attribute Name", "Name of attribute to search for in assertion. You can leave this blank and specify a friendly name instead.", ProviderConfigProperty.STRING_TYPE, null, null)
            .property(ATTRIBUTE_FRIENDLY_NAME, "Friendly Name", "Friendly name of attribute to search for in assertion. You can leave this blank and specify a name instead.", ProviderConfigProperty.STRING_TYPE, null, null)
            .property(ATTRIBUTE_VALUE, "Attribute Value", "Value the attribute must have. If the attribute is a list, then the value must be contained in the list.", ProviderConfigProperty.STRING_TYPE, null, null)
            .property(ConfigConstants.ROLE, "Role", "Role to grant to user. To reference an application role the syntax is appname.approle, i.e. myapp.myrole", ProviderConfigProperty.STRING_TYPE, null, null)
            .build();
    }

    public static final String PROVIDER_ID = "wsfed-role-idp-mapper";

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS.toArray(new String[COMPATIBLE_PROVIDERS.size()]);
    }

    @Override
    public String getDisplayCategory() {
        return "Role Mapper";
    }

    @Override
    public String getDisplayType() {
        return "WS-Fed Attribute to Role";
    }

    @Override
    public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String roleName = mapperModel.getConfig().get(ConfigConstants.ROLE);
        if (isAttributePresent(mapperModel, context)) {
            RoleModel role = KeycloakModelUtils.getRoleFromString(realm, roleName);
            if (role == null) throw new IdentityBrokerException("Unable to find role: " + roleName);
            user.grantRole(role);
        }
    }

    protected boolean isAttributePresent(IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String name = StringUtils.defaultIfBlank(mapperModel.getConfig().get(ATTRIBUTE_NAME), null);
        String friendly = StringUtils.defaultIfBlank(mapperModel.getConfig().get(ATTRIBUTE_FRIENDLY_NAME), null);
        String desiredValue = mapperModel.getConfig().get(ATTRIBUTE_VALUE);

        try {
            Object token = context.getContextData().get(WSFedEndpoint.WSFED_REQUESTED_TOKEN);

            if (token instanceof AssertionType) {
                return isAttributePresent((AssertionType) token, name, friendly, desiredValue);
            } else {
                //TODO: else if token type == JWSInput
                logger.warn("WS-Fed attribute role mapper doesn't currently support this token type.");
            }
        } catch (Exception ex) {
            logger.warn("Unable to parse token response", ex);
        }

        return false;
    }

    protected boolean isAttributePresent(AssertionType assertion, String name, String friendly, String desiredValue) {
        return AttributeUtils.findAttributeValue(assertion, name, friendly, a -> a.getAttributeValue().stream().anyMatch(o -> o.equals(desiredValue))) != null;
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String roleName = mapperModel.getConfig().get(ConfigConstants.ROLE);
        RoleModel role = KeycloakModelUtils.getRoleFromString(realm, roleName);
        if (role == null) throw new IdentityBrokerException("Unable to find role: " + roleName);

        if (isAttributePresent(mapperModel, context)) {
            user.grantRole(role);
        } else {
            user.deleteRoleMapping(role);
        }
    }

    @Override
    public String getHelpText() {
        return "If a claim exists, grant the user the specified realm or application role.";
    }
}
