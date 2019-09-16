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

package com.quest.keycloak.protocol.wsfed.builders;

import org.jboss.logging.Logger;
import org.keycloak.dom.saml.v1.assertion.SAML11AssertionType;
import org.keycloak.dom.saml.v1.assertion.SAML11AttributeStatementType;
import org.keycloak.dom.saml.v1.assertion.SAML11AttributeType;
import org.keycloak.dom.saml.v1.assertion.SAML11StatementAbstractType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.dom.saml.v2.assertion.EncryptedElementType;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.saml.SamlProtocol;
import com.quest.keycloak.protocol.wsfed.mappers.WSFedSAMLAttributeStatementMapper;
import com.quest.keycloak.protocol.wsfed.mappers.WSFedSAMLRoleListMapper;
import org.keycloak.protocol.saml.mappers.AttributeStatementHelper;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.exceptions.ConfigurationException;

import java.net.URI;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

/**
 * This class handles the creation of a complete SAML 1.1 assertion. By default, all previous processing is done in keycloak's
 * SAML 2.0 classes, an therefore the translation to SAML 1.1 structures is done in this class. However, the SAML
 * 1.1 classes are already a part of keycloak, so all this class needs to do is the translation from one set of
 * classes to another.
 *
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @since 10/4/2016
 */

public class WsFedSAML11AssertionTypeBuilder extends WsFedSAMLAssertionTypeAbstractBuilder<WsFedSAML11AssertionTypeBuilder> {

    // TODO eventually make the attribute namespace configurable to support multiple dialects.
    private static final String ATTRIBUTE_NAMESPACE = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims";

    private static final Logger logger = Logger.getLogger(WsFedSAML11AssertionTypeBuilder.class);

    @Override
    protected WsFedSAML11AssertionTypeBuilder getThis() {
        return this;
    }

    private final class SAML11AttributeArrayMapper {
        SAML11AttributeStatementType attributeStatement;
        SAML11AttributeArrayMapper(SAML11AttributeStatementType attributeStatement) {
            this.attributeStatement = attributeStatement;
        }
        void mapAttributes(AttributeStatementType saml2AttributeStatement,
                       Function<AttributeType, SAML11AttributeType> mapper) {

            if (mapper == null)
                throw new NullPointerException("Mapper cannot be null");

            for (AttributeStatementType.ASTChoiceType astChoice : saml2AttributeStatement.getAttributes()) {
                AttributeType attribute = astChoice.getAttribute();
                EncryptedElementType encryptedElement = astChoice.getEncryptedAssertion();

                if (attribute != null) {
                    SAML11AttributeType samlAttribute = mapper.apply(attribute);
                    attributeStatement.add(samlAttribute);
                }

                if (encryptedElement != null) {
                    logger.warn("Encrypted assertion attributes are not supported.");
                }
            }
        }
    }

    public SAML11AssertionType build() throws ConfigurationException {
        String responseIssuer = getResponseIssuer(realm);
        String nameIdFormat = JBossSAMLURIConstants.NAMEID_FORMAT_UNSPECIFIED.get();
//        String nameId = getNameId(nameIdFormat, clientSession, userSession);
        String nameId = userSession.getUser().getUsername();

        // save NAME_ID and format in clientSession as they may be persistent or transient or email and not username
        // we'll need to send this back on a logout
        clientSession.setNote(WSFED_NAME_ID, nameId);
        clientSession.setNote(WSFED_NAME_ID_FORMAT, nameIdFormat);

        SAML11AssertionTypeBuilder builder = new SAML11AssertionTypeBuilder();
        builder.issuer(responseIssuer)
                .assertionExpiration(realm.getAccessTokenLifespanForImplicitFlow())
                .nameIdentifier(nameIdFormat, nameId)
                .requestIssuer(clientSession.getClient().getClientId());

        SAML11AssertionType assertion = builder.buildModel();

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

    private void populateRoles(SamlProtocol.ProtocolMapperProcessor<WSFedSAMLRoleListMapper> roleListMapper,
                               SAML11AssertionType assertion,
                               KeycloakSession session,
                               UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
        if (roleListMapper == null) return;

        AttributeStatementType tempAttributeStatement = new AttributeStatementType();

        // TODO should there be different mappers to support SAML1.0 and SAML2.0 formats? --> only if SAML 2.0 mapper explicitly doesn't support values removed in SAML2.0
        // For instance, SAML1.0 may need "AttributeNamespace" explicitly specified,
        // wherease SAML2.0 needs a format specifier which does not map to anything in SAML1.0. Or does it?
        roleListMapper.mapper.mapRoles(tempAttributeStatement, roleListMapper.model, session, userSession, clientSession);

        SAML11AttributeStatementType attributeStatement = getAttributeStatement(assertion);

        SAML11AttributeArrayMapper samlAttributeMapper = new SAML11AttributeArrayMapper(attributeStatement);
        samlAttributeMapper.mapAttributes(tempAttributeStatement, attribute -> {
            // TODO what is there to do with SAML2 attribute name format? Should be set to attributeNameSpace, but value to use is unclear

            // Change the role attribute name to lowercase, i.e. "Role" becomes "role"
            SAML11AttributeType samlAttribute = null;
            String namespace = ATTRIBUTE_NAMESPACE;
            if (attribute.getFriendlyName() != null && !attribute.getFriendlyName().isEmpty()) {
                namespace = attribute.getFriendlyName();
            }
            samlAttribute = new SAML11AttributeType(attribute.getName().toLowerCase(), URI.create(namespace));

            if (!attribute.getAttributeValue().isEmpty()) {
                for (Object attributeValue : attribute.getAttributeValue()) {
                    samlAttribute.add(attributeValue.toString());
                }
            } else {
                logger.warnf("The attribute '%s' does not have a value", attribute.getName());
            }
            return samlAttribute;
        });

        if(!attributeStatement.get().isEmpty() && assertion.getStatements().isEmpty()) {
            assertion.add(attributeStatement);
        }
    }

    /**
     * Retrieves the SAML11AttributeStatementType from the passed assertion, or returns a new one if
     * none exists. Note: does NOT attach the newly created attribute statement to the the assertion
     * @param assertion a SAML11 Assertion (an SAML 1.1 assertion is in fact the token)
     * @return a SAML 1.1. Attribute statement type
     */
    private SAML11AttributeStatementType getAttributeStatement(SAML11AssertionType assertion) {
        SAML11AttributeStatementType attributeStatement = null;
        List<SAML11StatementAbstractType> statements = assertion.getStatements();
        if (statements != null) {
            for (SAML11StatementAbstractType st : statements) {
                if (st instanceof SAML11AttributeStatementType) {
                    attributeStatement = (SAML11AttributeStatementType)st;
                    break;
                }
            }
        }
        if (attributeStatement == null) {
            attributeStatement = new SAML11AttributeStatementType();
        }
        return attributeStatement;
    }

    /**
     * This method adds attributes to the passed SAML assertion. The values to append are taken from the state of the
     * sessions (keycloak session, user session and client session), and processed via the mappers to get the
     * actual attributes to add to the assertion.
     * This method will then take the values from the resulting SAML 2.0 classes and set them in SAML 1.1 classes.
     *
     * @param attributeStatementMappers The list of SAML attribute statement mappers to consider for this transformation.
     * @param assertion The SAML 1.1 assertion to build
     * @param session The current keycloak session
     * @param userSession The current user session
     * @param clientSession The current client session
     */
    private void transformAttributeStatement(List<SamlProtocol.ProtocolMapperProcessor<WSFedSAMLAttributeStatementMapper>> attributeStatementMappers,
                                            SAML11AssertionType assertion,
                                            KeycloakSession session,
                                            UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
        //This group is still SAML 2.0
        AttributeStatementType tempAttributeStatement = new AttributeStatementType();
        for (SamlProtocol.ProtocolMapperProcessor<WSFedSAMLAttributeStatementMapper> processor : attributeStatementMappers) {
            processor.mapper.transformAttributeStatement(tempAttributeStatement, processor.model, session, userSession, clientSession);
        }
        //From here we transform to SAML 1.1
        SAML11AttributeStatementType attributeStatement = getAttributeStatement(assertion);

        SAML11AttributeArrayMapper samlAttributeMapper = new SAML11AttributeArrayMapper(attributeStatement);
        samlAttributeMapper.mapAttributes(tempAttributeStatement, attribute -> {
            // TODO what is there to do with SAML2 attribute name format? Should be set to attributeNameSpace, but value to use is unclear
            SAML11AttributeType samlAttribute = null;
            String namespace = ATTRIBUTE_NAMESPACE;
            if (attribute.getFriendlyName() != null && !attribute.getFriendlyName().isEmpty()) {
                namespace = attribute.getFriendlyName();
            }
            samlAttribute = new SAML11AttributeType(attribute.getName(), URI.create(namespace));

            if (!attribute.getAttributeValue().isEmpty()) {
                for (Object attributeValue : attribute.getAttributeValue()) {
                    samlAttribute.add(attributeValue.toString());
                }
            } else {
                logger.warnf("The attribute '%s' does not have a value", attribute.getName());
            }
            return samlAttribute;
        });

        if(!attributeStatement.get().isEmpty() && assertion.getStatements().isEmpty()) {
            assertion.add(attributeStatement);
        }
    }

}
