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

import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.processing.core.util.JAXPValidationUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.ws.rs.core.Response;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.IOException;
import java.io.StringReader;
import java.security.PublicKey;

public interface RequestedToken {
    Response validate(PublicKey key, WSFedIdentityProviderConfig config, EventBuilder event, KeycloakSession session);

    String getUsername();

    String getEmail();

    String getId();

    String getSessionIndex();

    Object getToken();

    String getFirstName();

    String getLastName();

    default Document createXmlDocument(String response) throws ProcessingException, ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();

        InputSource source = new InputSource();
        source.setCharacterStream(new StringReader(response));
        try {
            Document document = builder.parse(source);
            JAXPValidationUtil.checkSchemaValidation(document);
            return document;
        } catch (SAXException | IOException e) {
            throw new ProcessingException("Error while extracting SAML from WSFed response.");
        }
    }

    default Document extractSamlDocument(Document document) throws ProcessingException, XPathExpressionException {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression xPathExpression = xpath.compile("//*[local-name() = 'Assertion']");

            NodeList samlNodes = (NodeList) xPathExpression.evaluate(document, XPathConstants.NODESET);
            Document samlDoc = factory.newDocumentBuilder().newDocument();
            for (int i = 0; i < samlNodes.getLength(); i++) {
                Node node = samlNodes.item(i);
                Node copyNode = samlDoc.importNode(node, true);
                samlDoc.appendChild(copyNode);
            }
            return samlDoc;
        } catch (XPathExpressionException | ParserConfigurationException e) {
            throw new ProcessingException("Error while extracting SAML Assertion from WSFed XML document.");
        }
    }


}
