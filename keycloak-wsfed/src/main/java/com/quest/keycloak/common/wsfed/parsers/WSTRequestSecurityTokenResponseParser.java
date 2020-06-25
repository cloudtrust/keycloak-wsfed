/*
 * JBoss, Home of Professional Open Source. Copyright 2008, Red Hat Middleware LLC, and individual contributors as
 * indicated by the @author tags. See the copyright.txt file in the distribution for a full listing of individual
 * contributors.
 *
 * This is free software; you can redistribute it and/or modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either version 2.1 of the License, or (at your option) any
 * later version.
 *
 * This software is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with this software; if not, write to
 * the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA, or see the FSF site:
 * http://www.fsf.org.
 */
package com.quest.keycloak.common.wsfed.parsers;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;

import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;
import org.picketlink.common.constants.WSTrustConstants;
import org.picketlink.common.exceptions.ParsingException;
import org.picketlink.common.parsers.ParserNamespaceSupport;
import org.picketlink.common.util.StaxParserUtil;
import org.picketlink.identity.federation.core.parsers.ParserController;
import org.picketlink.identity.federation.core.parsers.wsse.WSSecurityParser;
import org.picketlink.identity.federation.core.parsers.wst.WSTrustOnBehalfOfParser;
import org.picketlink.identity.federation.core.wstrust.WSTrustUtil;
import org.picketlink.identity.federation.core.wstrust.wrappers.Lifetime;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityTokenResponse;
import org.picketlink.identity.federation.ws.policy.AppliesTo;
import org.picketlink.identity.federation.ws.trust.BinarySecretType;
import org.picketlink.identity.federation.ws.trust.ComputedKeyType;
import org.picketlink.identity.federation.ws.trust.EntropyType;
import org.picketlink.identity.federation.ws.trust.LifetimeType;
import org.picketlink.identity.federation.ws.trust.OnBehalfOfType;
import org.picketlink.identity.federation.ws.trust.RequestedProofTokenType;
import org.picketlink.identity.federation.ws.trust.RequestedReferenceType;
import org.picketlink.identity.federation.ws.trust.RequestedSecurityTokenType;
import org.picketlink.identity.federation.ws.trust.RequestedTokenCancelledType;
import org.picketlink.identity.federation.ws.trust.StatusType;
import org.picketlink.identity.federation.ws.trust.UseKeyType;
import org.picketlink.identity.federation.ws.wss.secext.SecurityTokenReferenceType;
import org.picketlink.identity.federation.ws.wss.utility.AttributedDateTime;
import org.w3c.dom.Element;

/**
 * Parse the WS-Trust RequestSecurityTokenResponse
 *
 * @author Anil.Saldhana@redhat.com
 * @since Oct 11, 2010
 */
public class WSTRequestSecurityTokenResponseParser implements ParserNamespaceSupport {

    private static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();

    public static final String X509CERTIFICATE = "X509Certificate";

    public static final String KEYVALUE = "KeyValue";

    public static final String JDK_TRANSFORMER_PROPERTY = "picketlink.jdk.transformer";

    public interface TagParser<T> {
        void parse(XMLEventReader xmlEventReader, T response) throws ParsingException;
    }

    private static Map<String, TagParser<RequestSecurityTokenResponse>> tagParsers = new HashMap<>();
    private static Map<String, TagParser<StatusType>> statusTypeTagProcessors = new HashMap<>();

    static {
        /**
         * Initialize RequestSecurityToken parser
         */

        // REQUEST_TYPE parsing
        tagParsers.put(WSTrustConstants.REQUEST_TYPE, (xmlEventReader, responseToken) -> responseToken.setRequestType(parseURI(xmlEventReader, "request type")));
        // TOKEN_TYPE parsing
        tagParsers.put(WSTrustConstants.TOKEN_TYPE, (xmlEventReader, responseToken) -> responseToken.setTokenType(parseURI(xmlEventReader, "token type")));
        // KEY_TYPE parsing
        tagParsers.put(WSTrustConstants.KEY_TYPE, (xmlEventReader, responseToken) -> responseToken.setKeyType(parseURI(xmlEventReader, "key type")));
        // LIFETIME parsing
        tagParsers.put(WSTrustConstants.LIFETIME, (xmlEventReader, responseToken) -> {
            StartElement subEvent = StaxParserUtil.getNextStartElement(xmlEventReader);
            StaxParserUtil.validate(subEvent, WSTrustConstants.LIFETIME);

            LifetimeType lifeTime = new LifetimeType();
            // Get the Created
            subEvent = StaxParserUtil.getNextStartElement(xmlEventReader);
            String subTag = StaxParserUtil.getStartElementName(subEvent);
            if (subTag.equals(WSTrustConstants.CREATED)) {
                AttributedDateTime created = new AttributedDateTime();
                created.setValue(StaxParserUtil.getElementText(xmlEventReader));
                lifeTime.setCreated(created);
            }
            subEvent = StaxParserUtil.getNextStartElement(xmlEventReader);
            subTag = StaxParserUtil.getStartElementName(subEvent);

            if (!subTag.equals(WSTrustConstants.EXPIRES)) {
                throw logger.parserUnknownTag(subTag, subEvent.getLocation());
            }

            AttributedDateTime expires = new AttributedDateTime();
            expires.setValue(StaxParserUtil.getElementText(xmlEventReader));
            lifeTime.setExpires(expires);

            responseToken.setLifetime(new Lifetime(lifeTime));
            EndElement lifeTimeElement = StaxParserUtil.getNextEndElement(xmlEventReader);
            StaxParserUtil.validate(lifeTimeElement, WSTrustConstants.LIFETIME);
        });
        // ON_BEHALF_OF parsing
        tagParsers.put(WSTrustConstants.ON_BEHALF_OF, (xmlEventReader, responseToken) -> {
            StaxParserUtil.getNextStartElement(xmlEventReader);

            WSTrustOnBehalfOfParser wstOnBehalfOfParser = new WSTrustOnBehalfOfParser();
            OnBehalfOfType onBehalfOf = (OnBehalfOfType) wstOnBehalfOfParser.parse(xmlEventReader);
            responseToken.setOnBehalfOf(onBehalfOf);
            EndElement onBehalfOfEndElement = StaxParserUtil.getNextEndElement(xmlEventReader);
            StaxParserUtil.validate(onBehalfOfEndElement, WSTrustConstants.ON_BEHALF_OF);
        });
        // KEY_SIZE parsing
        tagParsers.put(WSTrustConstants.KEY_SIZE, (xmlEventReader, responseToken) -> {
            StaxParserUtil.getNextStartElement(xmlEventReader);

            if (!StaxParserUtil.hasTextAhead(xmlEventReader))
                throw logger.parserExpectedTextValue("key size");

            String keySize = StaxParserUtil.getElementText(xmlEventReader);
            try {
                responseToken.setKeySize(Long.parseLong(keySize));
            } catch (NumberFormatException e) {
                throw logger.parserException(e);
            }
        });
        // ENTROPY parsing
        tagParsers.put(WSTrustConstants.ENTROPY, (xmlEventReader, responseToken) -> {
            StaxParserUtil.getNextStartElement(xmlEventReader);
            EntropyType entropy = new EntropyType();
            StartElement subEvent = StaxParserUtil.getNextStartElement(xmlEventReader);
            if (StaxParserUtil.matches(subEvent, WSTrustConstants.BINARY_SECRET)) {
                BinarySecretType binarySecret = new BinarySecretType();
                Attribute typeAttribute = subEvent.getAttributeByName(new QName("", "Type"));
                if (typeAttribute != null) {
                    binarySecret.setType(StaxParserUtil.getAttributeValue(typeAttribute));
                }

                if (!StaxParserUtil.hasTextAhead(xmlEventReader)) {
                    throw logger.parserExpectedTextValue("binary secret value");
                }

                binarySecret.setValue(StaxParserUtil.getElementText(xmlEventReader).getBytes());
                entropy.addAny(binarySecret);
            }
            responseToken.setEntropy(entropy);
            EndElement endElement = StaxParserUtil.getNextEndElement(xmlEventReader);
            StaxParserUtil.validate(endElement, WSTrustConstants.ENTROPY);
        });
        // USE_KEY parsing
        tagParsers.put(WSTrustConstants.USE_KEY, (xmlEventReader, responseToken) -> {
            StartElement subEvent = StaxParserUtil.getNextStartElement(xmlEventReader);
            UseKeyType useKeyType = new UseKeyType();
            StaxParserUtil.validate(subEvent, WSTrustConstants.USE_KEY);

            // We peek at the next start element as the stax source has to be in the START_ELEMENT mode
            subEvent = StaxParserUtil.peekNextStartElement(xmlEventReader);
            if (!StaxParserUtil.matches(subEvent, X509CERTIFICATE) && !StaxParserUtil.matches(subEvent, KEYVALUE)) {
                throw logger.parserUnknownStartElement(StaxParserUtil.getStartElementName(subEvent), subEvent.getLocation());
            }
            Element domElement = StaxParserUtil.getDOMElement(xmlEventReader);
            useKeyType.add(domElement);
            responseToken.setUseKey(useKeyType);
        });
        // REQUESTED_TOKEN_CANCELLED parsing
        tagParsers.put(WSTrustConstants.REQUESTED_TOKEN_CANCELLED, (xmlEventReader, responseToken) -> {
            StaxParserUtil.getNextEndElement(xmlEventReader);
            responseToken.setRequestedTokenCancelled(new RequestedTokenCancelledType());
        });
        // REQUESTED_PROOF_TOKEN parsing
        tagParsers.put(WSTrustConstants.REQUESTED_PROOF_TOKEN, (xmlEventReader, responseToken) -> {
            StaxParserUtil.getNextStartElement(xmlEventReader);
            RequestedProofTokenType requestedProofToken = new RequestedProofTokenType();
            StartElement subEvent = StaxParserUtil.getNextStartElement(xmlEventReader);
            if (StaxParserUtil.matches(subEvent, WSTrustConstants.BINARY_SECRET)) {
                BinarySecretType binarySecret = new BinarySecretType();
                Attribute typeAttribute = subEvent.getAttributeByName(new QName("", "Type"));
                binarySecret.setType(StaxParserUtil.getAttributeValue(typeAttribute));

                if (!StaxParserUtil.hasTextAhead(xmlEventReader)) {
                    throw logger.parserExpectedTextValue("binary secret value");
                }

                binarySecret.setValue(StaxParserUtil.getElementText(xmlEventReader).getBytes());
                requestedProofToken.add(binarySecret);
            } else if (StaxParserUtil.matches(subEvent, WSTrustConstants.COMPUTED_KEY)) {
                ComputedKeyType computedKey = new ComputedKeyType();
                if (!StaxParserUtil.hasTextAhead(xmlEventReader)) {
                    throw logger.parserExpectedTextValue("computed key algorithm");
                }
                computedKey.setAlgorithm(StaxParserUtil.getElementText(xmlEventReader));
                requestedProofToken.add(computedKey);
            }
            responseToken.setRequestedProofToken(requestedProofToken);
            EndElement endElement = StaxParserUtil.getNextEndElement(xmlEventReader);
            StaxParserUtil.validate(endElement, WSTrustConstants.REQUESTED_PROOF_TOKEN);
        });
        // REQUESTED_TOKEN parsing
        tagParsers.put(WSTrustConstants.REQUESTED_TOKEN,
                (xmlEventReader, responseToken) -> responseToken.setRequestedSecurityToken(parseRequestedSecurityTokenType(xmlEventReader)));
        // REQUESTED_ATTACHED_REFERENCE parsing
        tagParsers.put(WSTrustConstants.REQUESTED_ATTACHED_REFERENCE,
                (xmlEventReader, responseToken) -> responseToken.setRequestedAttachedReference(parseRequestedReference(xmlEventReader, WSTrustConstants.REQUESTED_ATTACHED_REFERENCE)));
        // REQUESTED_UNATTACHED_REFERENCE parsing
        tagParsers.put(WSTrustConstants.REQUESTED_UNATTACHED_REFERENCE,
                (xmlEventReader, responseToken) -> responseToken.setRequestedUnattachedReference(parseRequestedReference(xmlEventReader, WSTrustConstants.REQUESTED_UNATTACHED_REFERENCE)));
        // STATUS parsing
        tagParsers.put(WSTrustConstants.STATUS,
                (xmlEventReader, responseToken) -> responseToken.setStatus(parseStatusType(xmlEventReader)));
        // RENEWING parsing
        tagParsers.put(WSTrustConstants.RENEWING,
                (xmlEventReader, responseToken) -> responseToken.setRenewing(WSTrustUtil.parseRenewingType(xmlEventReader)));

        /**
         * Initialize StatusType parser
         */
        statusTypeTagProcessors.put(WSTrustConstants.CODE, (xmlEventReader, status) -> {
            StartElement startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
            StaxParserUtil.validate(startElement, WSTrustConstants.CODE);

            if (!StaxParserUtil.hasTextAhead(xmlEventReader)) {
                throw logger.parserExpectedTextValue("Validation code");
            }
            status.setCode(StaxParserUtil.getElementText(xmlEventReader));
        });
        statusTypeTagProcessors.put(WSTrustConstants.REASON, (xmlEventReader, status) -> {
            StartElement startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
            StaxParserUtil.validate(startElement, WSTrustConstants.REASON);

            if (!StaxParserUtil.hasTextAhead(xmlEventReader)) {
                throw logger.parserExpectedTextValue("Validation reason");
            }
            status.setReason(StaxParserUtil.getElementText(xmlEventReader));
        });
    }

    /**
     * @see ParserNamespaceSupport#parse(XMLEventReader)
     */
    public Object parse(XMLEventReader xmlEventReader) throws ParsingException {
        StartElement startElement = StaxParserUtil.getNextStartElement(xmlEventReader);

        RequestSecurityTokenResponse responseToken = new RequestSecurityTokenResponse();
        responseToken.setContext(getContext(startElement));

        while (xmlEventReader.hasNext()) {
            XMLEvent xmlEvent = StaxParserUtil.peek(xmlEventReader);
            if (xmlEvent == null) {
                return responseToken;
            }
            if (xmlEvent instanceof EndElement) {
                xmlEvent = StaxParserUtil.getNextEvent(xmlEventReader);
                EndElement endElement = (EndElement) xmlEvent;
                String endElementTag = StaxParserUtil.getEndElementName(endElement);
                if (!endElementTag.equals(WSTrustConstants.RSTR)) {
                    throw logger.parserUnknownEndElement(endElementTag);
                }
                break;
            }

            StartElement subEvent = StaxParserUtil.peekNextStartElement(xmlEventReader);
            if (subEvent == null) {
                return responseToken;
            }

            String tag = StaxParserUtil.getStartElementName(subEvent);
            tagParsers.getOrDefault(tag, (xer, respToken) -> parseDynamicTag(xmlEventReader, responseToken, subEvent)).parse(xmlEventReader, responseToken);
        }

        return responseToken;
    }

    private void parseDynamicTag(XMLEventReader xmlEventReader, RequestSecurityTokenResponse responseToken, StartElement subEvent) throws ParsingException {
        QName qname = subEvent.getName();

        logger.trace("Looking for parser for element: " + qname);

        ParserNamespaceSupport parser = ParserController.get(qname);
        if (parser == null) {
            throw logger.parserUnknownTag(qname.getLocalPart(), subEvent.getLocation());
        }

        Object parsedObject = parser.parse(xmlEventReader);
        if (parsedObject instanceof AppliesTo) {
            responseToken.setAppliesTo((AppliesTo) parsedObject);
        }
    }

    private String getContext(StartElement startElement) {
        QName contextQName = new QName("", WSTrustConstants.RST_CONTEXT);
        Attribute contextAttribute = startElement.getAttributeByName(contextQName);
        //Context is optional and may be null if no RST was sent
        if (contextAttribute != null) {
            return StaxParserUtil.getAttributeValue(contextAttribute);
        }
        return "";
    }

    /**
     * @see ParserNamespaceSupport#supports(QName)
     */
    public boolean supports(QName qname) {
        String nsURI = qname.getNamespaceURI();
        String localPart = qname.getLocalPart();

        return WSTrustConstants.BASE_NAMESPACE.equals(nsURI) && WSTrustConstants.RST.equals(localPart);
    }

    private static URI parseURI(XMLEventReader xmlEventReader, String type) throws ParsingException {
        StaxParserUtil.getNextStartElement(xmlEventReader);

        if (!StaxParserUtil.hasTextAhead(xmlEventReader)) {
            throw logger.parserExpectedTextValue(type);
        }

        String value = StaxParserUtil.getElementText(xmlEventReader);
        try {
            return new URI(value);
        } catch (URISyntaxException e) {
            throw logger.parserException(e);
        }
    }

    private static StatusType parseStatusType(XMLEventReader xmlEventReader) throws ParsingException {
        StatusType status = new StatusType();
        StaxParserUtil.validate(StaxParserUtil.getNextStartElement(xmlEventReader), WSTrustConstants.STATUS);

        XMLEvent xmlEvent = null;
        while (xmlEventReader.hasNext()) {
            // Implemented this way, does not support new lines, indentation, ...
            xmlEvent = StaxParserUtil.peek(xmlEventReader);
            if (xmlEvent instanceof EndElement) {
                String endElementTag = StaxParserUtil.getEndElementName((EndElement) xmlEvent);
                if (!endElementTag.equals(WSTrustConstants.STATUS)) {
                    throw logger.parserUnknownEndElement(endElementTag);
                }
                StaxParserUtil.getNextEndElement(xmlEventReader);
                break;
            }
            final StartElement startElement = (StartElement) xmlEvent;
            final String tag = StaxParserUtil.getStartElementName(startElement);
            statusTypeTagProcessors.getOrDefault(tag, (xer, respToken) -> {
                throw logger.parserUnknownTag(tag, startElement.getLocation());
            }).parse(xmlEventReader, status);
        }

        return status;
    }

    private static RequestedSecurityTokenType parseRequestedSecurityTokenType(XMLEventReader xmlEventReader) throws ParsingException {
        RequestedSecurityTokenType requestedSecurityTokenType = new RequestedSecurityTokenType();

        StartElement startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
        StaxParserUtil.validate(startElement, WSTrustConstants.REQUESTED_TOKEN);

        XMLEvent xmlEvent = null;
        while (xmlEventReader.hasNext()) {
            xmlEvent = StaxParserUtil.peek(xmlEventReader);
            if (xmlEvent instanceof EndElement) {
                String endElementTag = StaxParserUtil.getEndElementName((EndElement) xmlEvent);
                if (endElementTag.equals(WSTrustConstants.REQUESTED_TOKEN)) {
                    StaxParserUtil.getNextEndElement(xmlEventReader);
                    break;
                }
                throw logger.parserUnknownEndElement(endElementTag);
            }
            Element tokenElement = StaxParserUtil.getDOMElement(xmlEventReader);
            requestedSecurityTokenType.add(tokenElement);
        }

        return requestedSecurityTokenType;
    }

    private static RequestedReferenceType parseRequestedReference(XMLEventReader xmlEventReader, String requestedReferenceTag) throws ParsingException {
        StartElement startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
        StaxParserUtil.validate(startElement, requestedReferenceTag);

        RequestedReferenceType ref = new RequestedReferenceType();

        WSSecurityParser wsseParser = new WSSecurityParser();
        SecurityTokenReferenceType secref = (SecurityTokenReferenceType) wsseParser.parse(xmlEventReader);

        ref.setSecurityTokenReference(secref);

        EndElement endElement = StaxParserUtil.getNextEndElement(xmlEventReader);
        StaxParserUtil.validate(endElement, requestedReferenceTag);

        return ref;
    }

}