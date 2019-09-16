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

package com.quest.keycloak.protocol.wsfed.builders;

import com.quest.keycloak.protocol.wsfed.mappers.WSFedSAMLAttributeStatementMapper;
import com.quest.keycloak.protocol.wsfed.mappers.WSFedSAMLRoleListMapper;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.models.*;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.saml.common.constants.GeneralConstants;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;

import javax.xml.datatype.DatatypeConfigurationException;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

public class WSFedSAML2AssertionTypeBuilder extends WsFedSAMLAssertionTypeAbstractBuilder<WSFedSAML2AssertionTypeBuilder> {

    public AssertionType build() throws DatatypeConfigurationException {
        String responseIssuer = getResponseIssuer(realm);
        String nameIdFormat = getNameIdFormat(clientSession);
        String nameId = getNameId(nameIdFormat, clientSession, userSession);

        // save NAME_ID and format in clientSession as they may be persistent or transient or email and not username
        // we'll need to send this back on a logout
        clientSession.setNote(WSFED_NAME_ID, nameId);
        clientSession.setNote(WSFED_NAME_ID_FORMAT, nameIdFormat);

        SAML2AssertionTypeBuilder builder = new SAML2AssertionTypeBuilder();
        builder.issuer(responseIssuer)
                .assertionExpiration(realm.getAccessCodeLifespan())
                .subjectExpiration(realm.getAccessTokenLifespan())
                .nameIdentifier(nameIdFormat, nameId)
                .requestIssuer(clientSession.getClient().getClientId());

        AssertionType assertion = builder.buildModel();

        List<SamlProtocol.ProtocolMapperProcessor<WSFedSAMLAttributeStatementMapper>> attributeStatementMappers = new LinkedList<>();
        SamlProtocol.ProtocolMapperProcessor<WSFedSAMLRoleListMapper> roleListMapper = null;

        Set<ProtocolMapperModel> mappings = clientSession.getClient().getProtocolMappers();
        for (ProtocolMapperModel mapping : mappings) {

            ProtocolMapper mapper = (ProtocolMapper)session.getKeycloakSessionFactory().getProviderFactory(ProtocolMapper.class, mapping.getProtocolMapper());
            if (mapper == null) continue;
            if (mapper instanceof WSFedSAMLAttributeStatementMapper) {
                attributeStatementMappers.add(new SamlProtocol.ProtocolMapperProcessor<>((WSFedSAMLAttributeStatementMapper)mapper, mapping));
            }
            if (mapper instanceof WSFedSAMLRoleListMapper) {
                roleListMapper = new SamlProtocol.ProtocolMapperProcessor<>((WSFedSAMLRoleListMapper)mapper, mapping);
            }
        }

        transformAttributeStatement(attributeStatementMappers, assertion, session, userSession, clientSession);
        populateRoles(roleListMapper, assertion, session, userSession, clientSession);

        return assertion;
    }

    protected void populateRoles(SamlProtocol.ProtocolMapperProcessor<WSFedSAMLRoleListMapper> roleListMapper,
                              AssertionType assertion,
                              KeycloakSession session,
                              UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
        if (roleListMapper == null) return;
        AttributeStatementType attributeStatement = new AttributeStatementType();
        roleListMapper.mapper.mapRoles(attributeStatement, roleListMapper.model, session, userSession, clientSession);

        //SAML Spec 2.7.3 AttributeStatement much contain one or more Attribute or EncryptedAttribute
        if(attributeStatement.getAttributes().size() > 0) {
            assertion.addStatement(attributeStatement);
        }
    }

    public void transformAttributeStatement(List<SamlProtocol.ProtocolMapperProcessor<WSFedSAMLAttributeStatementMapper>> attributeStatementMappers,
                                            AssertionType assertion,
                                            KeycloakSession session,
                                            UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
        AttributeStatementType attributeStatement = new AttributeStatementType();
        for (SamlProtocol.ProtocolMapperProcessor<WSFedSAMLAttributeStatementMapper> processor : attributeStatementMappers) {
            processor.mapper.transformAttributeStatement(attributeStatement, processor.model, session, userSession, clientSession);
        }

        //SAML Spec 2.7.3 AttributeStatement much contain one or more Attribute or EncryptedAttribute
        if(attributeStatement.getAttributes().size() > 0) {
            assertion.addStatement(attributeStatement);
        }
    }

    protected String getNameIdFormat(AuthenticatedClientSessionModel clientSession) {
        String nameIdFormat = clientSession.getNote(GeneralConstants.NAMEID_FORMAT);
        ClientModel client = clientSession.getClient();
        boolean forceFormat = forceNameIdFormat(client);
        String configuredNameIdFormat = client.getAttribute(SAML_NAME_ID_FORMAT_ATTRIBUTE);
        if ((nameIdFormat == null || forceFormat) && configuredNameIdFormat != null) {
            if (configuredNameIdFormat.equals("email")) {
                nameIdFormat = JBossSAMLURIConstants.NAMEID_FORMAT_EMAIL.get();
            } else if (configuredNameIdFormat.equals("persistent")) {
                nameIdFormat = JBossSAMLURIConstants.NAMEID_FORMAT_PERSISTENT.get();
            } else if (configuredNameIdFormat.equals("transient")) {
                nameIdFormat = JBossSAMLURIConstants.NAMEID_FORMAT_TRANSIENT.get();
            } else if (configuredNameIdFormat.equals("username")) {
                nameIdFormat = JBossSAMLURIConstants.NAMEID_FORMAT_UNSPECIFIED.get();
            } else {
                nameIdFormat = JBossSAMLURIConstants.NAMEID_FORMAT_UNSPECIFIED.get();
            }
        }
        if(nameIdFormat == null) return SAML_DEFAULT_NAMEID_FORMAT;
        return nameIdFormat;
    }

    protected static boolean forceNameIdFormat(ClientModel client) {
        return "true".equals(client.getAttribute(SAML_FORCE_NAME_ID_FORMAT_ATTRIBUTE));
    }

    protected String getNameId(String nameIdFormat, AuthenticatedClientSessionModel clientSession, UserSessionModel userSession) {
        if (nameIdFormat.equals(JBossSAMLURIConstants.NAMEID_FORMAT_EMAIL.get())) {
            return userSession.getUser().getEmail();
        } else if(nameIdFormat.equals(JBossSAMLURIConstants.NAMEID_FORMAT_TRANSIENT.get())) {
            // "G-" stands for "generated" Add this for the slight possibility of collisions.
            return "G-" + UUID.randomUUID().toString();
        } else if(nameIdFormat.equals(JBossSAMLURIConstants.NAMEID_FORMAT_PERSISTENT.get())) {
            // generate a persistent user id specifically for each client.
            UserModel user = userSession.getUser();
            String name = SAML_PERSISTENT_NAME_ID_FOR + "." + clientSession.getClient().getClientId();
            String samlPersistentId = user.getFirstAttribute(name);
            if (samlPersistentId != null) return samlPersistentId;
            // "G-" stands for "generated"
            samlPersistentId = "G-" + UUID.randomUUID().toString();
            user.setSingleAttribute(name, samlPersistentId);
            return samlPersistentId;
        } else if(nameIdFormat.equals(JBossSAMLURIConstants.NAMEID_FORMAT_UNSPECIFIED.get())){
            // TODO: Support for persistent NameID (pseudo-random identifier persisted in user object)
            return userSession.getUser().getUsername();
        } else {
            return userSession.getUser().getUsername();
        }
    }

    @Override
    protected WSFedSAML2AssertionTypeBuilder getThis() {
        return this;
    }
}
