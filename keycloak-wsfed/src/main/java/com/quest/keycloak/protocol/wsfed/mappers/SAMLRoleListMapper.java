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

package com.quest.keycloak.protocol.wsfed.mappers;

import com.quest.keycloak.protocol.wsfed.WSFedLoginProtocol;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.saml.mappers.RoleListMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.util.DefaultClientSessionContext;

import java.util.ArrayList;
import java.util.List;

/**
 * This class handles the mapping of roles to attributes for the WSFed protocol. This is handled by calling the
 * existing keycloak SAML 2.0 role mapper.
 */
public class SAMLRoleListMapper extends AbstractWsfedProtocolMapper implements WSFedSAMLRoleListMapper {
    public static final String PROVIDER_ID = "wsfed-saml-role-list-mapper";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    static {
        RoleListMapper mapper = new RoleListMapper();
        configProperties.addAll(mapper.getConfigProperties());
        addNamespaceToFriendlyProperty(configProperties);
    }

    @Override
    public String getDisplayCategory() {
        return SAML_ROLE_MAPPER;
    }

    @Override
    public String getDisplayType() {
        return "SAML Role list";
    }

    @Override
    public String getHelpText() {
        return "Role names are stored in an attribute value.  There is either one attribute with multiple attribute values, or an attribute per role name depending on how you configure it.  You can also specify the attribute name i.e. 'Role' or 'memberOf' being examples.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    /**
     * Calls keycloak's role mapper to perform the mapping from the sessions' attributes using the parameters
     * defined in the mapping model.
     *
     * @param roleAttributeStatement The attribute statement to enrich with the roles
     * @param mappingModel the mapping model with the information on how to map
     * @param session The keycloak session
     * @param userSession The user's session. Not actually used, astonishingly
     * @param clientSession The client session. The role information is gathered from here as all roles for the user-client session is actually attached to this object during authentication
     */
    @Override
    public void mapRoles(AttributeStatementType roleAttributeStatement, ProtocolMapperModel mappingModel, KeycloakSession session, UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
        RoleListMapper samlMapper = new RoleListMapper();
        samlMapper.mapRoles(roleAttributeStatement, mappingModel, session, userSession, DefaultClientSessionContext.fromClientSessionScopeParameter(clientSession));
    }

    /**
     * Creates a protocol mapper object. Mainly used for testing, but can also be used to add default mappers to a client.
     * @param name The name of the mapper
     * @param samlAttributeName The name of the attribute in the saml assertion
     * @param nameFormat can be "basic", "URI reference" or "unspecified"
     * @param friendlyName The friendly name of the attribute. Unused in saml 1.1
     * @param singleAttribute If true, all roles will be stored under one attribute with multiple attribute values
     * @return a protocol mapper for a role mapping
     */
    public static ProtocolMapperModel create(String name, String samlAttributeName, String nameFormat, String friendlyName, boolean singleAttribute) {
        ProtocolMapperModel mapper = RoleListMapper.create(name, samlAttributeName, nameFormat, friendlyName, singleAttribute);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol(WSFedLoginProtocol.LOGIN_PROTOCOL);
        return mapper;
    }

}
