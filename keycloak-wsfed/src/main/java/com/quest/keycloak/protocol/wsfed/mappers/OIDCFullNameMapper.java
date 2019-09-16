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

package com.quest.keycloak.protocol.wsfed.mappers;

import com.quest.keycloak.protocol.wsfed.WSFedLoginProtocol;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.FullNameMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.util.DefaultClientSessionContext;

import java.util.ArrayList;
import java.util.List;

public class OIDCFullNameMapper extends AbstractWsfedProtocolMapper implements WSFedOIDCAccessTokenMapper {
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    static {
        FullNameMapper mapper = new FullNameMapper();
        configProperties.addAll(mapper.getConfigProperties());
    }

    public static final String PROVIDER_ID = "wsfed-oidc-full-name-mapper";

    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "OIDC User's full name";
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Maps the user's first and last name to the OpenID Connect 'name' claim. Format is <first> + ' ' + <last>";
    }

    @Override
    public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession session,
                                            UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
        FullNameMapper mapper = new FullNameMapper();
        return mapper.transformAccessToken(token, mappingModel, session, userSession, DefaultClientSessionContext.fromClientSessionScopeParameter(clientSession));
    }

    public static ProtocolMapperModel create(String name,
                                             boolean consentRequired,
                                             boolean accessToken, boolean idToken) {

        ProtocolMapperModel mapper = FullNameMapper.create(name, accessToken, idToken, consentRequired);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol(WSFedLoginProtocol.LOGIN_PROTOCOL);
        return mapper;
    }

}
