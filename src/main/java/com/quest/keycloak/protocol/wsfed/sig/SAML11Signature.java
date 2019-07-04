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

package com.quest.keycloak.protocol.wsfed.sig;

import org.keycloak.rotation.HardcodedKeyLocator;
import org.keycloak.rotation.KeyLocator;
import org.keycloak.saml.common.PicketLinkLogger;
import org.keycloak.saml.common.PicketLinkLoggerFactory;
import org.keycloak.saml.common.constants.JBossSAMLConstants;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.processing.core.saml.v1.SAML11Constants;
import org.keycloak.saml.processing.core.util.SignatureUtilTransferObject;
import org.keycloak.saml.processing.core.util.XMLSignatureUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.ParserConfigurationException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 10/4/2016
 */

public class SAML11Signature implements SAMLAbstractSignature {

    private static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();

    private static final String CONDITIONS = "Conditions";

    private String signatureMethod = SignatureMethod.RSA_SHA1;

    private String digestMethod = DigestMethod.SHA1;

    private Node sibling;

    /**
     * Set the X509Certificate if X509Data is needed in signed info
     */
    private X509Certificate x509Certificate;

    public String getSignatureMethod() {
        return signatureMethod;
    }

    @Override
    public void setSignatureMethod(String signatureMethod) {
        this.signatureMethod = signatureMethod;
    }

    public String getDigestMethod() {
        return digestMethod;
    }

    @Override
    public void setDigestMethod(String digestMethod) {
        this.digestMethod = digestMethod;
    }

    @Override
    public void setNextSibling(Node sibling) {
        this.sibling = sibling;
    }

    /**
     * Set to false, if you do not want to include keyinfo in the signature
     *
     * @param val
     * @since v2.0.1
     */
    public void setSignatureIncludeKeyInfo(boolean val) {
        if (!val) {
            XMLSignatureUtil.setIncludeKeyInfoInSignature(false);
        }
    }

    /**
     * Set the {@link X509Certificate} if you desire
     * to have the SignedInfo have X509 Data
     * <p>
     * This method needs to be called before any of the sign methods.
     *
     * @param x509Certificate
     * @since v2.5.0
     */
    @Override
    public void setX509Certificate(X509Certificate x509Certificate) {
        this.x509Certificate = x509Certificate;
    }

    /**
     * Sign an Document at the root
     *
     * @param keyPair Key Pair
     * @return
     * @throws ParserConfigurationException
     * @throws XMLSignatureException
     * @throws MarshalException
     * @throws GeneralSecurityException
     */
    public Document sign(Document doc, String keyName, String referenceID, KeyPair keyPair, String canonicalizationMethodType) throws ParserConfigurationException,
            GeneralSecurityException, MarshalException, XMLSignatureException {
        String referenceURI = "#" + referenceID;

        configureIdAttribute(doc);

        if (sibling != null) {
            SignatureUtilTransferObject dto = new SignatureUtilTransferObject();
            dto.setDocumentToBeSigned(doc);
            dto.setKeyPair(keyPair);
            dto.setDigestMethod(digestMethod);
            dto.setSignatureMethod(signatureMethod);
            dto.setReferenceURI(referenceURI);
            dto.setNextSibling(sibling);

            if (x509Certificate != null) {
                dto.setX509Certificate(x509Certificate);
            }

            return XMLSignatureUtil.sign(dto, canonicalizationMethodType);
        }
        return XMLSignatureUtil.sign(doc, keyName, keyPair, digestMethod, signatureMethod, referenceURI, canonicalizationMethodType);
    }

    /**
     * Sign a SAML Document
     *
     * @param samlDocument
     * @param keypair
     * @param keyName
     * @throws org.keycloak.saml.common.exceptions.ProcessingException
     */
    @Override
    public void signSAMLDocument(Document samlDocument, String keyName, KeyPair keypair, String canonicalizationMethodType) throws ProcessingException {
        // Get the ID from the root
        String id = samlDocument.getDocumentElement().getAttribute(SAML11Constants.ASSERTIONID);
        try {
            sign(samlDocument, keyName, id, keypair, canonicalizationMethodType);
        } catch (Exception e) {
            throw new ProcessingException(logger.signatureError(e));
        }
    }

    /**
     * Validate the SAML11 Document
     *
     * @param signedDocument
     * @param publicKey
     * @return
     * @throws ProcessingException
     */
    public boolean validate(Document signedDocument, PublicKey publicKey) throws ProcessingException {
        try {
            configureIdAttribute(signedDocument);
            KeyLocator keyLocator = new HardcodedKeyLocator(publicKey);
            return XMLSignatureUtil.validate(signedDocument, keyLocator);
        } catch (MarshalException | XMLSignatureException me) {
            throw new ProcessingException(logger.signatureError(me));
        }
    }

    @Override
    public Node getNextSiblingOfIssuer(Document doc) {
        return getNextSiblingOfConditions(doc);
    }

    /**
     * Given a {@link Document}, find the {@link Node} which is the sibling of the Issuer element
     *
     * @param doc
     * @return
     */
    public Node getNextSiblingOfConditions(Document doc) {
        // Find the sibling of Conditions
        NodeList nl = doc.getElementsByTagNameNS(SAML11Constants.ASSERTION_11_NSURI, CONDITIONS);
        if (nl.getLength() > 0) {
            Node authenticationStatement = nl.item(0);

            return authenticationStatement.getNextSibling();
        }
        return null;
    }

    /**
     * <p>
     * Sets the IDness of the ID attribute. Santuario 1.5.1 does not assumes IDness based on attribute names anymore.
     * This
     * method should be called before signing/validating a saml document.
     * </p>
     *
     * @param document SAML document to have its ID attribute configured.
     */
    private void configureIdAttribute(Document document) {
        // Estabilish the IDness of the ID attribute.
        document.getDocumentElement().setIdAttribute(SAML11Constants.ASSERTIONID, true);

        NodeList nodes = document.getElementsByTagNameNS(SAML11Constants.ASSERTION_11_NSURI,
                JBossSAMLConstants.ASSERTION.get());

        for (int i = 0; i < nodes.getLength(); i++) {
            Node n = nodes.item(i);
            if (n instanceof Element) {
                ((Element) n).setIdAttribute(SAML11Constants.ASSERTIONID, true);
            }
        }
    }
}
