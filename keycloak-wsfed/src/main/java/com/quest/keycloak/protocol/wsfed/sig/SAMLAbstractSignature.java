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

import org.keycloak.saml.common.exceptions.ProcessingException;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

/**
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 10/4/2016
 */

public interface SAMLAbstractSignature {

    void setSignatureMethod(String signatureMethod);
    void setDigestMethod(String digestMethod);
    Node getNextSiblingOfIssuer(Document doc);
    void setNextSibling(Node sibling);
    void setX509Certificate(X509Certificate x509Certificate);
    void signSAMLDocument(Document samlDocument, String keyName, KeyPair keypair, String canonicalizationMethodType) throws ProcessingException;
}
