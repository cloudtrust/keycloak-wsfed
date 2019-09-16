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

package com.quest.keycloak.protocol.wsfed;

import com.quest.keycloak.protocol.wsfed.mappers.OIDCFullNameMapper;
import com.quest.keycloak.protocol.wsfed.mappers.OIDCUserPropertyMapper;
import com.quest.keycloak.protocol.wsfed.mappers.SAMLUserPropertyAttributeStatementMapper;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.AbstractLoginProtocolFactory;
import org.keycloak.protocol.oidc.mappers.AddressMapper;
import org.keycloak.protocol.saml.mappers.AttributeStatementHelper;
import org.keycloak.protocol.saml.mappers.RoleListMapper;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.processing.core.saml.v2.constants.X500SAMLProfileConstants;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created on 5/19/15.
 */
public abstract class AbstractWSFedLoginProtocolFactory extends AbstractLoginProtocolFactory {
    public static final String USERNAME = "username";
    public static final String UPN = "upn";
    public static final String EMAIL = "email";
    public static final String EMAIL_VERIFIED = "email verified";
    public static final String GIVEN_NAME = "given name";
    public static final String FAMILY_NAME = "family name";
    public static final String FULL_NAME = "full name";
    public static final String USERNAME_CONSENT_TEXT = "${username}";
    public static final String UPN_CONSENT_TEXT = "${upn}";
    public static final String EMAIL_CONSENT_TEXT = "${email}";
    public static final String EMAIL_VERIFIED_CONSENT_TEXT = "${emailVerified}";
    public static final String GIVEN_NAME_CONSENT_TEXT = "${givenName}";
    public static final String FAMILY_NAME_CONSENT_TEXT = "${familyName}";
    public static final String FULL_NAME_CONSENT_TEXT = "${fullName}";

    private static final String T_STRING = "String";
    private static final String T_BOOL = "boolean";

    static Map<String, ProtocolMapperModel> builtins = new HashMap<>();
    static List<ProtocolMapperModel> defaultBuiltins = new ArrayList<>();

    @Override
    public Map<String, ProtocolMapperModel> getBuiltinMappers() {
        return builtins;
    }

    @Override
    public Object createProtocolEndpoint(RealmModel realm, EventBuilder event) {
        return new WSFedService(realm, event);
    }

    @Override
    public void setupClientDefaults(ClientRepresentation rep, ClientModel newClient) {
        // Does nothing
    }

    @Override
    public String getId() {
        return "wsfed";
    }

    static {
        Arrays.asList(
            //OIDC
            OIDCUserPropertyMapper.createClaimMapper(UPN, USERNAME, "upn", T_STRING, true, UPN_CONSENT_TEXT, true, true),
            OIDCUserPropertyMapper.createClaimMapper(USERNAME, USERNAME, "preferred_username", T_STRING, true, USERNAME_CONSENT_TEXT, true, true),
            OIDCUserPropertyMapper.createClaimMapper(EMAIL, EMAIL, EMAIL, T_STRING, true, EMAIL_CONSENT_TEXT, true, true),
            OIDCUserPropertyMapper.createClaimMapper(GIVEN_NAME, "firstName", "given_name", T_STRING, true, GIVEN_NAME_CONSENT_TEXT, true, true),
            OIDCUserPropertyMapper.createClaimMapper(FAMILY_NAME, "lastName", "family_name", T_STRING, true, FAMILY_NAME_CONSENT_TEXT, true, true),
            OIDCUserPropertyMapper.createClaimMapper(EMAIL_VERIFIED, "emailVerified", "email_verified", T_BOOL, false, EMAIL_VERIFIED_CONSENT_TEXT, true, true),
            OIDCFullNameMapper.create(FULL_NAME, true, true, true),
            AddressMapper.createAddressMapper(),
            //SAML
            SAMLUserPropertyAttributeStatementMapper.createAttributeMapper("X500 email", EMAIL, X500SAMLProfileConstants.EMAIL.get(),
                JBossSAMLURIConstants.ATTRIBUTE_FORMAT_URI.get(), X500SAMLProfileConstants.EMAIL.getFriendlyName(), true, EMAIL_CONSENT_TEXT),
            SAMLUserPropertyAttributeStatementMapper.createAttributeMapper("X500 givenName", "firstName", X500SAMLProfileConstants.GIVEN_NAME.get(),
                JBossSAMLURIConstants.ATTRIBUTE_FORMAT_URI.get(), X500SAMLProfileConstants.GIVEN_NAME.getFriendlyName(), true, GIVEN_NAME_CONSENT_TEXT),
            SAMLUserPropertyAttributeStatementMapper.createAttributeMapper("X500 surname", "lastName", X500SAMLProfileConstants.SURNAME.get(),
                JBossSAMLURIConstants.ATTRIBUTE_FORMAT_URI.get(), X500SAMLProfileConstants.SURNAME.getFriendlyName(), true, FAMILY_NAME_CONSENT_TEXT),
            RoleListMapper.create("saml role list", "Role", AttributeStatementHelper.BASIC, null, false)
        ).forEach(m -> builtins.put(m.getName(), m));
    }

    @Override
    protected void createDefaultClientScopesImpl(RealmModel newRealm) {
        // Does nothing
    }

    @Override
    protected void addDefaults(ClientModel client) {
        for (ProtocolMapperModel model : defaultBuiltins) client.addProtocolMapper(model);
    }
}
