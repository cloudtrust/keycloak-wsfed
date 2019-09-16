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
import org.keycloak.dom.saml.v1.assertion.*;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.common.exceptions.fed.IssueInstantMissingException;
import org.keycloak.saml.processing.core.saml.v2.common.IDGenerator;
import org.keycloak.saml.processing.core.saml.v2.util.AssertionUtil;
import org.keycloak.saml.processing.core.saml.v2.util.XMLTimeUtil;

import io.cloudtrust.keycloak.exceptions.CtRuntimeException;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import java.net.URI;
import java.util.GregorianCalendar;

/**
 * The purpose of this class is to create an inital SAML 1.1 assertion (essentially, a saml 1.1 token).
 * This assertion can then serve as the basis to create a complete SAML 1.1 assertion
 *
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 10/4/2016
 */

public class SAML11AssertionTypeBuilder {
    protected static final Logger logger = Logger.getLogger(SAML11AssertionTypeBuilder.class);

    private static final String ATTRIBUTE_NAMESPACE = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims";

    public final static long CLOCK_SKEW = 2000; // in milliseconds

    protected String requestID;
    protected String issuer;
    protected String requestIssuer;
    protected int assertionExpiration;
    protected String nameId;
    protected String nameIdFormat;

    public SAML11AssertionTypeBuilder issuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    /**
     * Length of time in seconds the assertion is valid for
     * See SAML core specification 2.5.1.2 NotOnOrAfter
     *
     * @param assertionExpiration Number of seconds the assertion should be valid
     * @return
     */
    public SAML11AssertionTypeBuilder assertionExpiration(int assertionExpiration) {
        this.assertionExpiration = assertionExpiration;
        return this;
    }

    public SAML11AssertionTypeBuilder requestID(String requestID) {
        this.requestID =requestID;
        return this;
    }

    public SAML11AssertionTypeBuilder requestIssuer(String requestIssuer) {
        this.requestIssuer =requestIssuer;
        return this;
    }

    public SAML11AssertionTypeBuilder nameIdentifier(String nameIdFormat, String nameId) {
        this.nameIdFormat = nameIdFormat;
        this.nameId = nameId;
        return this;
    }

    protected SAML11SubjectType getSubjectType(String nameID, String nameIDFormat) {
        SAML11SubjectConfirmationType subjectConfirmationType = new SAML11SubjectConfirmationType();
        subjectConfirmationType.addConfirmationMethod(URI.create("urn:oasis:names:tc:SAML:1.0:cm:bearer"));

        SAML11SubjectType subject = new SAML11SubjectType();
        subject.setSubjectConfirmation(subjectConfirmationType);

        SAML11NameIdentifierType nameIdentifierType = new SAML11NameIdentifierType(nameID);
        nameIdentifierType.setFormat(URI.create(nameIDFormat));

        SAML11SubjectType.SAML11SubjectTypeChoice subjectTypeChoice = new SAML11SubjectType.SAML11SubjectTypeChoice(nameIdentifierType);
        subject.setChoice(subjectTypeChoice);

        return subject;
    }

    /**
     * Creates a bare-bones SAML 1.1 assertion.
     * @return the SAML 1.1 assertion
     * @throws ConfigurationException
     */
    public SAML11AssertionType buildModel() throws ConfigurationException {
        String id = IDGenerator.create("ID_");

        XMLGregorianCalendar issuerInstant = XMLTimeUtil.getIssueInstant();
        SAML11AssertionType assertion = AssertionUtil.createSAML11Assertion(id, issuerInstant, issuer);

        //Add request issuer as the audience restriction
        SAML11AudienceRestrictionCondition audience = new SAML11AudienceRestrictionCondition();
        audience.add(URI.create(requestIssuer));

        SAML11ConditionsType conditions;
        if (assertionExpiration <= 0) {
            conditions = new SAML11ConditionsType();

            XMLGregorianCalendar beforeInstant = XMLTimeUtil.subtract(issuerInstant, CLOCK_SKEW);
            conditions.setNotBefore(beforeInstant);

            XMLGregorianCalendar assertionValidityLength = XMLTimeUtil.add(issuerInstant, CLOCK_SKEW);
            conditions.setNotOnOrAfter(assertionValidityLength);
        } else {
            try {
                AssertionUtil.createSAML11TimedConditions(assertion, assertionExpiration * 1000L, CLOCK_SKEW);
                conditions = assertion.getConditions();
            }
            catch(IssueInstantMissingException ex) {
                throw new CtRuntimeException(ex);
            }
        }
        if (conditions == null) {
            throw new CtRuntimeException("Failed to create timed conditions");
        }
        conditions.add(audience);
        assertion.setConditions(conditions);

        SAML11SubjectType subject = getSubjectType(nameId, nameIdFormat);

        SAML11AttributeStatementType attributeStatement = new SAML11AttributeStatementType();
        attributeStatement.setSubject(subject);
//        attributeStatement.add(getNameAttribute(nameId));
        assertion.add(attributeStatement);

        SAML11AuthenticationStatementType authnStatement = getAuthenticationStatement(subject, assertion.getIssueInstant());
        assertion.add(authnStatement);

        return assertion;
    }

    protected XMLGregorianCalendar getXMLGregorianCalendarNow() throws DatatypeConfigurationException {
        GregorianCalendar gregorianCalendar = new GregorianCalendar();
        DatatypeFactory datatypeFactory = DatatypeFactory.newInstance();
        return datatypeFactory.newXMLGregorianCalendar(gregorianCalendar);
    }

    protected SAML11AuthenticationStatementType getAuthenticationStatement(SAML11SubjectType subject, XMLGregorianCalendar authenticationInstant) {
        SAML11AuthenticationStatementType authnStatement = new SAML11AuthenticationStatementType(URI.create(JBossSAMLURIConstants.AC_PASSWORD_PROTECTED_TRANSPORT.get()), authenticationInstant);
        authnStatement.setSubject(subject);
        return authnStatement;
    }
}
