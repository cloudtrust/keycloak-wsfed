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

import org.keycloak.broker.provider.DefaultDataMarshaller;
import org.keycloak.dom.saml.v1.assertion.SAML11AssertionType;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.StaxUtil;
import org.keycloak.saml.processing.core.parsers.saml.SAMLParser;
import org.keycloak.saml.processing.core.saml.v1.writers.SAML11AssertionWriter;
import org.keycloak.saml.processing.core.saml.v2.writers.SAMLAssertionWriter;

import io.cloudtrust.keycloak.exceptions.CtRuntimeException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

public class WSFedDataMarshaller extends DefaultDataMarshaller {
    @Override
    public String serialize(Object obj) {
        if (obj instanceof AssertionType) {
            try {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                AssertionType assertion = (AssertionType) obj;
                SAMLAssertionWriter samlWriter = new SAMLAssertionWriter(StaxUtil.getXMLStreamWriter(bos));
                samlWriter.write(assertion);

                return new String(bos.toByteArray());
            } catch (ProcessingException pe) {
                throw new CtRuntimeException(pe);
            }
        }
        else if (obj instanceof SAML11AssertionType) {
            try {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                SAML11AssertionType assertion = (SAML11AssertionType) obj;
                SAML11AssertionWriter samlWriter = new SAML11AssertionWriter(StaxUtil.getXMLStreamWriter(bos));
                samlWriter.write(assertion);

                return new String(bos.toByteArray());
            } catch (ProcessingException pe) {
                throw new CtRuntimeException(pe);
            }
        } else {
            return super.serialize(obj);
        }
    }

    @Override
    public <T> T deserialize(String serialized, Class<T> clazz) {
        if (clazz.equals(AssertionType.class)) {
            try {
                byte[] bytes = serialized.getBytes();
                InputStream is = new ByteArrayInputStream(bytes);
                Object respType = SAMLParser.getInstance().parse(is);

                return clazz.cast(respType);
            } catch (ParsingException pe) {
                throw new CtRuntimeException(pe);
            }
        }
        else if (clazz.equals(SAML11AssertionType.class)) {
            try {
                byte[] bytes = serialized.getBytes();
                InputStream is = new ByteArrayInputStream(bytes);
                Object respType = SAMLParser.getInstance().parse(is);

                return clazz.cast(respType);
            } catch (ParsingException pe) {
                throw new CtRuntimeException(pe);
            }
        } else {
            return super.deserialize(serialized, clazz);
        }
    }
}

