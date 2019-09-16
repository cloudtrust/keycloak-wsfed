/*
 * Copyright 2016 Analytical Graphics, Inc. and/or its affiliates
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
 *
 */

package com.quest.keycloak.protocol.wsfed.mappers;

import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.saml.mappers.UserAttributeStatementMapper;
import com.quest.keycloak.protocol.wsfed.WSFedLoginProtocol;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @since 11/15/2016
 */

public class SAMLUserAttributeStatementMapper extends AbstractWsfedProtocolMapper implements WSFedSAMLAttributeStatementMapper {

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();
    public static final String PROVIDER_ID = "wsfed-saml-user-attribute-mapper";

    static {
        UserAttributeStatementMapper mapper = new UserAttributeStatementMapper();
        configProperties.addAll(mapper.getConfigProperties());
        addNamespaceToFriendlyProperty(configProperties);
    }

    @Override
    public String getHelpText() {
        return "Map a user attribute to a SAML attribute type.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public void transformAttributeStatement(AttributeStatementType attributeStatement, ProtocolMapperModel mappingModel, KeycloakSession session, UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
        UserAttributeStatementMapper mapper = new UserAttributeStatementMapper();
        mapper.transformAttributeStatement(attributeStatement, mappingModel, session, userSession, clientSession);
    }

    public static ProtocolMapperModel createAttributeMapper(String name, String userAttribute,
                                                            String samlAttributeName, String nameFormat, String friendlyName,
                                                            boolean consentRequired, String consentText) {
        ProtocolMapperModel mapper = UserAttributeStatementMapper.createAttributeMapper(name, userAttribute, samlAttributeName, nameFormat, friendlyName);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol(WSFedLoginProtocol.LOGIN_PROTOCOL);
        return mapper;
    }

    @Override
    public String getDisplayCategory() {
        return ATTRIBUTE_STATEMENT_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "SAML User Attribute";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
