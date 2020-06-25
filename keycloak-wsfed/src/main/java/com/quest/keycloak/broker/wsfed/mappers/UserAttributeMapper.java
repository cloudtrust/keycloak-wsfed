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
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.Arrays;
import java.util.List;

public class UserAttributeMapper extends AbstractIdentityProviderMapper {
    private static final Logger logger = Logger.getLogger(UserAttributeMapper.class);

    private static final List<String> COMPATIBLE_PROVIDERS = Arrays.asList(WSFedIdentityProviderFactory.PROVIDER_ID);

    private static final List<ProviderConfigProperty> configProperties;

    public static final String ATTRIBUTE_NAME = "attribute.name";
    public static final String ATTRIBUTE_FRIENDLY_NAME = "attribute.friendly.name";
    public static final String USER_ATTRIBUTE = "user.attribute";

    static {
        configProperties = ProviderConfigurationBuilder.create()
            .property(ATTRIBUTE_NAME, "Attribute Name", "Name of attribute to search for in assertion. You can leave this blank and specify a friendly name instead.", ProviderConfigProperty.STRING_TYPE, null, null)
            .property(ATTRIBUTE_FRIENDLY_NAME, "Friendly Name", "Friendly name of attribute to search for in assertion. You can leave this blank and specify a name instead.", ProviderConfigProperty.STRING_TYPE, null, null)
            .property(USER_ATTRIBUTE, "User Attribute Name", "User attribute name to store saml attribute.", ProviderConfigProperty.STRING_TYPE, null, null)
            .build();
    }

    public static final String PROVIDER_ID = "wsfed-user-attribute-idp-mapper";

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
        return "Attribute Importer";
    }

    @Override
    public String getDisplayType() {
        return "WS-Fed Attribute Importer";
    }

    @Override
    public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String attribute = mapperModel.getConfig().get(USER_ATTRIBUTE);
        Object value = getAttribute(mapperModel, context);
        if (value != null) {
            user.setSingleAttribute(attribute, value.toString());
        }
    }

    protected String getAttribute(IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String name = StringUtils.defaultIfBlank(mapperModel.getConfig().get(ATTRIBUTE_NAME), null);
        String friendly = StringUtils.defaultIfBlank(mapperModel.getConfig().get(ATTRIBUTE_FRIENDLY_NAME), null);

        try {
            Object token = context.getContextData().get(WSFedEndpoint.WSFED_REQUESTED_TOKEN);

            if (token instanceof AssertionType) {
                return getAttribute((AssertionType) token, name, friendly);
            } else {
                //TODO: else if token type == JWSInput
                logger.warn("WS-Fed user attribute mapper doesn't currently support this token type.");
            }
        } catch (Exception ex) {
            logger.warn("Unable to parse token response", ex);
        }

        return null;
    }

    protected String getAttribute(AssertionType assertion, String name, String friendly) {
        List<Object> attrValue = AttributeUtils.findAttributeValue(assertion, name, friendly, a -> a.getAttributeValue() != null && !a.getAttributeValue().isEmpty());
        if (attrValue == null) {
            return null;
        }
        return attrValue.get(0).toString();
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String attribute = mapperModel.getConfig().get(USER_ATTRIBUTE);
        Object value = getAttribute(mapperModel, context);
        if (value == null) {
            user.removeAttribute(attribute);
        } else {
            String current = user.getFirstAttribute(attribute);
            if (!value.equals(current)) {
                user.setSingleAttribute(attribute, value.toString());
            }
        }
    }

    @Override
    public String getHelpText() {
        return "Import declared wsfed attribute if it exists in assertion into the specified user attribute.";
    }
}
