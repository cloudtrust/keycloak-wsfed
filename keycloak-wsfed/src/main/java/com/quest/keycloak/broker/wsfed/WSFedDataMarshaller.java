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

import io.cloudtrust.exception.CloudtrustRuntimeException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.function.Function;
import java.util.function.Predicate;

public class WSFedDataMarshaller extends DefaultDataMarshaller {
    private static final Map<Predicate<Object>, Function<Object, String>> serializers;
    private static final Map<Class<?>, Function<String, Object>> deserializers;

    static {
        serializers = new HashMap<>();
        serializers.put(o -> o instanceof AssertionType, obj -> {
            try {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                AssertionType assertion = (AssertionType) obj;
                SAMLAssertionWriter samlWriter = new SAMLAssertionWriter(StaxUtil.getXMLStreamWriter(bos));
                samlWriter.write(assertion);

                return new String(bos.toByteArray(), StandardCharsets.UTF_8);
            } catch (ProcessingException pe) {
                throw new CloudtrustRuntimeException(pe);
            }
        });
        serializers.put(o -> o instanceof SAML11AssertionType, obj -> {
            try {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                SAML11AssertionType assertion = (SAML11AssertionType) obj;
                SAML11AssertionWriter samlWriter = new SAML11AssertionWriter(StaxUtil.getXMLStreamWriter(bos));
                samlWriter.write(assertion);

                return new String(bos.toByteArray(), StandardCharsets.UTF_8);
            } catch (ProcessingException pe) {
                throw new CloudtrustRuntimeException(pe);
            }
        });

        deserializers = new HashMap<>();
        deserializers.put(AssertionType.class, s -> {
            try {
                byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
                InputStream is = new ByteArrayInputStream(bytes);
                return SAMLParser.getInstance().parse(is);
            } catch (ParsingException pe) {
                throw new CloudtrustRuntimeException(pe);
            }
        });
        deserializers.put(SAML11AssertionType.class, s -> {
            try {
                byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
                InputStream is = new ByteArrayInputStream(bytes);
                return SAMLParser.getInstance().parse(is);
            } catch (ParsingException pe) {
                throw new CloudtrustRuntimeException(pe);
            }
        });
    }

    @Override
    public String serialize(Object obj) {
        return serializers.entrySet().stream()
            .filter(e -> e.getKey().test(obj)).map(Entry::getValue).findFirst()
            .orElse(super::serialize)
            .apply(obj);
    }

    @Override
    public <T> T deserialize(String serialized, Class<T> clazz) {
        Function<String, Object> deserializer = deserializers.get(clazz);
        if (deserializer==null) {
            return super.deserialize(serialized, clazz);
        }
        return clazz.cast(deserializer.apply(serialized));
    }
}

