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

package com.quest.keycloak.protocol.wsfed;

import io.cloudtrust.keycloak.exceptions.CtRuntimeException;

/**
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 10/4/2016
 */

public enum WsFedSAMLAssertionTokenFormat {

    SAML11_ASSERTION_TOKEN_FORMAT("SAML 1.1"),
    SAML20_ASSERTION_TOKEN_FORMAT("SAML 2.0");

    private String formatValue = null;
    WsFedSAMLAssertionTokenFormat(String format) {
        formatValue = format;
    }

    public String get() {
        return formatValue;
    }

    public static WsFedSAMLAssertionTokenFormat parse(String format) {
        for (WsFedSAMLAssertionTokenFormat value : WsFedSAMLAssertionTokenFormat.values()) {
            if (value.get().equalsIgnoreCase(format)) {
                return value;
            }
        }
        throw new CtRuntimeException("Invalid saml assertion token format enumeration");
    }
}
