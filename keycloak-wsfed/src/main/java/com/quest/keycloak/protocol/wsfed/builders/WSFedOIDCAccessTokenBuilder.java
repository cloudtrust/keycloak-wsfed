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

package com.quest.keycloak.protocol.wsfed.builders;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Set;

import com.quest.keycloak.protocol.wsfed.mappers.WSFedOIDCAccessTokenMapper;

import org.keycloak.common.util.Base64Url;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.*;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.services.util.DefaultClientSessionContext;

public class WSFedOIDCAccessTokenBuilder {
    private KeycloakSession session;
    private UserSessionModel userSession;
    private AuthenticatedClientSessionModel clientSession;
    private ClientSessionCode<?> accessCode;
    private RealmModel realm;
    private ClientModel client;
    private boolean x5tIncluded;

    public KeycloakSession getSession() {
        return session;
    }

    public WSFedOIDCAccessTokenBuilder setSession(KeycloakSession session) {
        this.session = session;
        return this;
    }

    public UserSessionModel getUserSession() {
        return userSession;
    }

    public WSFedOIDCAccessTokenBuilder setUserSession(UserSessionModel userSession) {
        this.userSession = userSession;
        return this;
    }

    public AuthenticatedClientSessionModel getClientSession() {
        return clientSession;
    }

    public WSFedOIDCAccessTokenBuilder setClientSession(AuthenticatedClientSessionModel clientSession) {
        this.clientSession = clientSession;
        return this;
    }

    public ClientSessionCode getAccessCode() {
        return accessCode;
    }

    public WSFedOIDCAccessTokenBuilder setAccessCode(ClientSessionCode accessCode) {
        this.accessCode = accessCode;
        return this;
    }

    public RealmModel getRealm() {
        return realm;
    }

    public WSFedOIDCAccessTokenBuilder setRealm(RealmModel realm) {
        this.realm = realm;
        return this;
    }

    public ClientModel getClient() {
        return client;
    }

    public WSFedOIDCAccessTokenBuilder setClient(ClientModel client) {
        this.client = client;
        return this;
    }

    public String build() throws NoSuchAlgorithmException, CertificateEncodingException {
        TokenManager tokenManager = new TokenManager();
        UserModel user = session.users().getUserById(userSession.getUser().getId(), realm);
        AccessToken accessToken = tokenManager.createClientAccessToken(session, realm, client, user, userSession, DefaultClientSessionContext.fromClientSessionScopeParameter(clientSession));
        accessToken = transformAccessToken(session, accessToken, userSession, clientSession);
        return encodeToken(realm, accessToken);
    }

    public String encodeToken(RealmModel realm, Object token) throws NoSuchAlgorithmException, CertificateEncodingException {
        JWSBuilderExtended builder = new JWSBuilderExtended().type("JWT");

        KeyManager keyManager = session.keys();
        KeyWrapper activeKey = keyManager.getActiveKey(realm, KeyUse.SIG, Algorithm.RS256);
        if(isX5tIncluded()) {
            builder.x5t(activeKey.getCertificate());
        }

        return builder.jsonContent(token).sign(new AsymmetricSignatureSignerContext(activeKey));
    }

    public boolean isX5tIncluded() {
        return x5tIncluded;
    }

    public WSFedOIDCAccessTokenBuilder setX5tIncluded(boolean x5tIncluded) {
        this.x5tIncluded = x5tIncluded;
        return this;
    }

    protected class JWSBuilderExtended extends JWSBuilder {
        String type;
        String contentType;
        String x5t;

        @Override
        public JWSBuilderExtended type(String type) {
            super.type(type);
            this.type = type;
            return this;
        }

        @Override
        public JWSBuilderExtended contentType(String type) {
            super.contentType(type);
            this.contentType = type;
            return this;
        }

        public JWSBuilderExtended x5t(X509Certificate certificate) throws NoSuchAlgorithmException, CertificateEncodingException {
            this.x5t = getThumbPrint(certificate);
            return this;
        }

        public String getThumbPrint(X509Certificate cert) throws NoSuchAlgorithmException, CertificateEncodingException {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] der = cert.getEncoded();
            md.update(der);
            byte[] digest = md.digest();
            return Base64Url.encode(digest);
        }

        @Override
        protected String encodeHeader(String algo) {
            StringBuilder builder = new StringBuilder("{");
            if (type != null) builder.append("\"typ\":\"").append(type).append("\",");
            builder.append("\"alg\":\"").append(algo).append("\"");

            if (contentType != null) builder.append(",\"cty\":\"").append(contentType).append("\"");
            if (x5t != null) builder.append(",\"x5t\":\"").append(x5t).append("\"");
            builder.append("}");
            return Base64Url.encode(builder.toString().getBytes(StandardCharsets.UTF_8));
        }
    }

    public AccessToken transformAccessToken(KeycloakSession session, AccessToken token, UserSessionModel userSession,
                                            AuthenticatedClientSessionModel clientSession) {
        Set<ProtocolMapperModel> mappings = clientSession.getClient().getProtocolMappers();
        KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();
        for (ProtocolMapperModel mapping : mappings) {

            ProtocolMapper mapper = (ProtocolMapper)sessionFactory.getProviderFactory(ProtocolMapper.class, mapping.getProtocolMapper());
            if (!(mapper instanceof WSFedOIDCAccessTokenMapper)) continue;
            token = ((WSFedOIDCAccessTokenMapper)mapper).transformAccessToken(token, mapping, session, userSession, clientSession);

        }
        return token;
    }
}
