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
import io.cloudtrust.keycloak.exceptions.CtRuntimeException;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.saml.mappers.AttributeStatementHelper;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Iterator;
import java.util.List;

public abstract class AbstractWsfedProtocolMapper implements ProtocolMapper {
    public static final String TOKEN_MAPPER_CATEGORY = "OIDC Token mapper";
    public static final String ATTRIBUTE_STATEMENT_CATEGORY = "SAML AttributeStatement Mapper";
    public static final String SAML_ROLE_MAPPER = "SAML Role Mapper";
    public static final String FRIENDLY_NAMESPACE_HELP_TEXT = "SAML 2.0 Token: This field is used for the friendly name SAML 1.1 Token: This field is used for the attribute namespace";

    @Override
    public String getProtocol() {
        return WSFedLoginProtocol.LOGIN_PROTOCOL;
    }

    @Override
    public void close() {

    }

    @Override
    public final ProtocolMapper create(KeycloakSession session) {
        throw new CtRuntimeException("UNSUPPORTED METHOD");
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    /**
     * This method is used to add details to the FriendlyName property used in WsFed SAML Mappers. It is mainly used
     * when a Keycloak provided Mapper is used to configure the properties of a custom mapper so as to avoid duplicating
     * code provided by Keycloak.
     *
     * The details that are added are " / Namespace" to the label as well as replacing the help text detailing
     * that in SAML 2.0 Tokens FriendlyName is still used normally and in SAML 1.1 Tokens it is used to define the attribute
     * namespace to be used.
     *
     * @param properties The list of ProviderConfigProperty objects already configured by a Keycloak provided Mapper
     */
    static void addNamespaceToFriendlyProperty(List<ProviderConfigProperty> properties) {
        ProviderConfigProperty property = null;
        Iterator<ProviderConfigProperty> iter = properties.iterator();
        // Iterate until we find the property with the FriendlyName, could break if Keycloak Mappers stop using
        // AttributeStatementHelper.FriendlyName
        while (iter.hasNext()) {
            property = iter.next();
            if (property.getName().equals(AttributeStatementHelper.FRIENDLY_NAME)) {
                property.setLabel(AttributeStatementHelper.FRIENDLY_NAME_LABEL + "/ Namespace");
                property.setHelpText(FRIENDLY_NAMESPACE_HELP_TEXT);
                break;
            }
        }
    }
}
