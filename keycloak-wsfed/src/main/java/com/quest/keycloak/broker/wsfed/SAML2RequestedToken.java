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

package com.quest.keycloak.broker.wsfed;

import org.jboss.logging.Logger;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.dom.saml.v2.assertion.AudienceRestrictionType;
import org.keycloak.dom.saml.v2.assertion.ConditionAbstractType;
import org.keycloak.dom.saml.v2.assertion.EncryptedAssertionType;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.assertion.SubjectType;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.saml.common.constants.JBossSAMLConstants;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.saml.common.util.StaxParserUtil;
import org.keycloak.saml.processing.api.saml.v2.response.SAML2Response;
import org.keycloak.saml.processing.core.parsers.saml.SAMLParser;
import org.keycloak.saml.processing.core.saml.v2.constants.X500SAMLProfileConstants;
import org.keycloak.saml.processing.core.saml.v2.util.AssertionUtil;
import org.keycloak.saml.processing.core.util.JAXPValidationUtil;
import org.keycloak.saml.processing.core.util.XMLEncryptionUtil;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.ws.rs.core.Response;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

/**
 * Created on 5/15/15.
 */
public class SAML2RequestedToken implements RequestedToken {
    private NameIDType subjectNameID;
    protected static final Logger logger = Logger.getLogger(SAML2RequestedToken.class);
    private AssertionType saml2Assertion;
    private String wsfedResponse;
    private KeycloakSession session;

    public SAML2RequestedToken(KeycloakSession session, String wsfedResponse, Object token, RealmModel realm) throws IOException, ParsingException, ProcessingException, ConfigurationException {
        this.wsfedResponse = wsfedResponse;
        this.session = session;
        this.saml2Assertion = getAssertionType(token, realm);
    }

    @Override
    public Response validate(PublicKey key, WSFedIdentityProviderConfig config, EventBuilder event, KeycloakSession session) {
        try {
            //We have to use the wsfedResponse and pull the document from it. The reason is the WSTrustParser sometimes re-organizes some attributes within the RequestedSecurityToken which breaks validation.
            Document doc = createXmlDocument(wsfedResponse);
            logger.tracef("wsfedResponse [%s].", wsfedResponse);

            if(!AssertionUtil.isSignatureValid(extractSamlDocument(doc).getDocumentElement(), key)) {
                event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
                event.error(Errors.INVALID_SIGNATURE);
                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_FEDERATED_IDENTITY_ACTION);
            }

            XMLGregorianCalendar notBefore = saml2Assertion.getConditions().getNotBefore();
            //Add in a tiny bit of slop for small clock differences
            notBefore.add(DatatypeFactory.newInstance().newDuration(false, 0, 0, 0, 0, 0, 10));

            if(AssertionUtil.hasExpired(saml2Assertion)) {
                event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
                event.error(Errors.EXPIRED_CODE);
                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_FEDERATED_IDENTITY_ACTION);
            }

            if(!isValidAudienceRestriction(URI.create(config.getWsFedRealm()))) {
                event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
                event.error(Errors.INVALID_SAML_RESPONSE);
                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_FEDERATED_IDENTITY_ACTION);
            }

        } catch (Exception e) {
            logger.error("Unable to validate signature", e);
            event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
            event.error(Errors.INVALID_SAML_RESPONSE);
            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_FEDERATED_IDENTITY_ACTION);
        }

        return null;
    }

    public boolean isValidAudienceRestriction(URI...uris) {
        List<URI> audienceRestriction = getAudienceRestrictions();

        if(audienceRestriction == null) {
            return true;
        }

        for (URI uri : uris) {
            if (audienceRestriction.contains(uri)) {
                return true;
            }
        }

        return false;
    }

    public List<URI> getAudienceRestrictions() {
        List<ConditionAbstractType> conditions = saml2Assertion.getConditions().getConditions();
        for(ConditionAbstractType condition : conditions) {
            if(condition instanceof AudienceRestrictionType) {
                return ((AudienceRestrictionType) condition).getAudience();
            }
        }

        return null;
    }

    protected NameIDType getSubjectNameID() {
        if (subjectNameID == null) {
            SubjectType subject = saml2Assertion.getSubject();
            SubjectType.STSubType subType = subject.getSubType();

            if (subType != null && subType.getBaseID() instanceof NameIDType) {
                subjectNameID = (NameIDType) subType.getBaseID();
            }
        }
        return subjectNameID;
    }

    @Override
    public String getUsername() {
        return getId();
    }

    @Override
    public String getLastName() {
        // TODO: implement getLastName
        return null;
    }

    @Override
    public String getFirstName() {
        // TODO: implement getFirstName
        return null;
    }

    @Override
    public String getEmail() {
        if (getSubjectNameID()!=null && getSubjectNameID().getFormat()!=null && getSubjectNameID().getFormat().toString().equals(JBossSAMLURIConstants.NAMEID_FORMAT_EMAIL.get())) {
            return subjectNameID.getValue();
        }

        if (saml2Assertion.getAttributeStatements() == null ) {
            return null;
        }
        for (AttributeStatementType attrStatement : saml2Assertion.getAttributeStatements()) {
            for (AttributeStatementType.ASTChoiceType choice : attrStatement.getAttributes()) {
                AttributeType attribute = choice.getAttribute();
                if (X500SAMLProfileConstants.EMAIL.getFriendlyName().equals(attribute.getFriendlyName())
                        || X500SAMLProfileConstants.EMAIL.get().equals(attribute.getName())
                        || "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress".equals(attribute.getName())) {
                    if (!attribute.getAttributeValue().isEmpty()) {
                        return attribute.getAttributeValue().get(0).toString();
                    }
                }
            }
        }

        return null;
    }

    @Override
    public String getId() {
        return getSubjectNameID().getValue();
    }

    @Override
    public String getSessionIndex() {
        //TODO: getSessionIndex still needs to be implemented
        return null;
    }

    public AssertionType getAssertionType(Object token, RealmModel realm) throws IOException, ParsingException, ProcessingException, ConfigurationException {
        AssertionType assertionType =  null;
        SAMLParser parser = SAMLParser.getInstance();
        String assertionXml = DocumentUtil.asString(((Element) token).getOwnerDocument());

        try (ByteArrayInputStream bis = new ByteArrayInputStream(assertionXml.getBytes())) {
            Object assertion = parser.parse(bis);

            if (assertion instanceof EncryptedAssertionType) {
                PrivateKey privateKey = (PrivateKey)session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.RS256).getPrivateKey();
                assertionType = decryptAssertion((EncryptedAssertionType) assertion, privateKey);
            } else {
                assertionType = (AssertionType) assertion;
            }

            return assertionType;
        }
    }

    protected AssertionType decryptAssertion(EncryptedAssertionType encryptedAssertion, PrivateKey privateKey) throws ParsingException, ProcessingException, ConfigurationException {
        SAML2Response saml2Response = new SAML2Response();
        Document doc = saml2Response.convert(encryptedAssertion);
        Element enc = DocumentUtil.getElement(doc, new QName(JBossSAMLConstants.ENCRYPTED_ASSERTION.get()));

        if (enc == null) {
            return null;
        }

        Document newDoc = DocumentUtil.createDocument();
        Node importedNode = newDoc.importNode(enc, true);
        newDoc.appendChild(importedNode);

        Element decryptedDocumentElement = XMLEncryptionUtil.decryptElementInDocument(newDoc, privateKey);
        SAMLParser parser = SAMLParser.getInstance();

        JAXPValidationUtil.checkSchemaValidation(decryptedDocumentElement);
        return (AssertionType) parser.parse(StaxParserUtil.getXMLEventReader(DocumentUtil.getNodeAsStream(decryptedDocumentElement)));
    }

    public AssertionType getAssertionType() {
        return saml2Assertion;
    }

    @Override
    public Object getToken() { return saml2Assertion; }
}
