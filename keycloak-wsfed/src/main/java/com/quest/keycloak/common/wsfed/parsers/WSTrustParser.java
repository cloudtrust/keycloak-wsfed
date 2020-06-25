/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.quest.keycloak.common.wsfed.parsers;

import org.picketlink.common.constants.WSTrustConstants;
import org.picketlink.common.exceptions.ParsingException;
import org.picketlink.common.parsers.AbstractParser;
import org.picketlink.common.parsers.ParserNamespaceSupport;
import org.picketlink.common.util.StaxParserUtil;
import org.picketlink.identity.federation.core.parsers.wst.WSTRequestSecurityTokenCollectionParser;
import org.picketlink.identity.federation.core.parsers.wst.WSTRequestSecurityTokenParser;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;


/**
 * Parser for WS-Trust payload
 *
 * @author Anil.Saldhana@redhat.com
 * @since Oct 11, 2010
 */
public class WSTrustParser extends AbstractParser {
    interface TagParser {
        Object parse(XMLEventReader reader) throws ParsingException;
    }

    private static Map<String, Supplier<ParserNamespaceSupport>> tagParsers = new HashMap<>();

    static {
        tagParsers.put(WSTrustConstants.RST_COLLECTION.toUpperCase(), WSTRequestSecurityTokenCollectionParser::new);
        tagParsers.put(WSTrustConstants.RST.toUpperCase(), WSTRequestSecurityTokenParser::new);
        tagParsers.put(WSTrustConstants.RSTR_COLLECTION.toUpperCase(), WSTRequestSecurityTokenResponseCollectionParser::new);
        tagParsers.put(WSTrustConstants.RSTR.toUpperCase(), WSTRequestSecurityTokenResponseParser::new);
    }

    /**
     * @see AbstractParser#parse(XMLEventReader)
     */
    public Object parse(XMLEventReader xmlEventReader) throws ParsingException {
        while (xmlEventReader.hasNext()) {
            XMLEvent xmlEvent = StaxParserUtil.peek(xmlEventReader);

            if (xmlEvent instanceof StartElement) {
                StartElement startElement = (StartElement) xmlEvent;

                String elementName = StaxParserUtil.getStartElementName(startElement);
                Supplier<ParserNamespaceSupport> parser = tagParsers.get(elementName.toUpperCase());
                if (parser==null) {
                    throw logger.parserFailed(elementName);
                }
                return parser.get().parse(xmlEventReader);
            } else {
                StaxParserUtil.getNextEvent(xmlEventReader);
            }
        }
        throw logger.parserFailed(WSTrustConstants.BASE_NAMESPACE);
    }

    /**
     * @see AbstractParser#supports(QName)
     */
    public boolean supports(QName qname) {
        return WSTrustConstants.BASE_NAMESPACE.equals(qname.getNamespaceURI());
    }
}