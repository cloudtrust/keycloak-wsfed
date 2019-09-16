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

package com.quest.keycloak.common.wsfed;

import org.keycloak.OAuth2Constants;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.enums.SslRequired;
import org.keycloak.common.util.CertificateUtils;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.scripting.DefaultScriptingProviderFactory;
import org.keycloak.scripting.ScriptingProvider;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.sessions.StickySessionEncoderProvider;
import org.keycloak.storage.UserStorageManager;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import io.cloudtrust.keycloak.exceptions.CtRuntimeException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;

public class MockHelper {
    private String baseUri = null;

    private String clientId = null;
    private Map<String, String> clientAttributes = new HashMap<>();
    private Map<String, String> clientSessionNotes = new HashMap<>();

    private String userName = null;
    private String email = null;

    private String realmName = null;
    private int accessCodeLifespan = 0;
    private int accessTokenLifespan = 0;
    private int accessTokenLifespanForImplicitFlow = 0;

    private Map<ProtocolMapperModel, ProtocolMapper> protocolMappers = new HashMap<>();

    @Mock
    private KeycloakUriInfo uriInfo;
    @Mock
    private RealmModel realm;
    @Mock
    private ClientModel client;
    @Mock
    private UserModel user;
    @Mock
    private KeyManager keyManager;
    @Mock
    private KeyManager.ActiveRsaKey activeKey;

    @Mock
    private LoginFormsProvider loginFormsProvider;
    @Mock
    private KeycloakSession session;
    @Mock
    private KeycloakSessionFactory sessionFactory;
    @Mock
    private AuthenticatedClientSessionModel clientSession;
    @Mock
    private AuthenticationSessionModel authSession;
    @Mock
    private ClientSessionCode accessCode;
    @Mock
    private UserSessionModel userSessionModel;

    public MockHelper() {
        resetMocks();
    }

    public void resetMocks() {
        MockitoAnnotations.initMocks(this);
    }

    /**
     * Initialize the defaults based on field values. If you don't like the defaults they can be changed by using reset(mockClass) and then configure it however you want
     */
    public MockHelper initializeMockValues() {
        initializeSessionMock();
        initializeUriInfo();
        initializeRealmMock();
        initializeClientModelMock();
        initializeUserModelMock();
        initializeLoginFormsProviderMock();
        initializeKeycloakSessionFactoryMock();
        initializeKeycloakSessionMock();
        initializeClientSessionModelMock();
        initializeAuthSessionModelMock();
        initializeClientSessionCodeMock();
        initializeUserSessionModelMock();
        protocolMappers = new HashMap<>();
        return this;
    }

    protected void initializeSessionMock() {
        when(session.keys()).thenReturn(keyManager);

    }

    protected void initializeUriInfo() {
        //We have to use thenAnswer so that the UriBuilder gets created on each call vs at mock time.
        when(getUriInfo().getBaseUriBuilder()).
                thenAnswer(new Answer<UriBuilder>() {
                    public UriBuilder answer(InvocationOnMock invocation) {
                        return UriBuilder.fromUri(getBaseUri());
                    }
                });

        URI baseUri = getUriInfo().getBaseUriBuilder().build();
        when(getUriInfo().getBaseUri()).thenReturn(baseUri);
    }

    protected void initializeRealmMock() {
        when(getRealm().getName()).thenReturn(getRealmName());
        when(getRealm().isEnabled()).thenReturn(true);
        when(getRealm().getAccessCodeLifespan()).thenReturn(getAccessCodeLifespan());
        when(getRealm().getAccessTokenLifespan()).thenReturn(getAccessTokenLifespan());
        when(getRealm().getSslRequired()).thenReturn(SslRequired.ALL);
        generateActiveRealmKeys(keyManager, activeKey, realm);
    }

    public static void generateActiveRealmKeys(KeyManager keyManager, KeyManager.ActiveRsaKey activeKey, RealmModel realm) {
        if (keyManager.getActiveKey(realm, KeyUse.SIG, Algorithm.RS256) != null) {
            return;
        }
        KeyPair keyPair = null;
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            keyPair = generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new CtRuntimeException(e);
        }
        X509Certificate certificate = null;
        try {
            certificate = CertificateUtils.generateV1SelfSignedCertificate(keyPair, realm.getName());
        } catch (Exception e) {
            throw new CtRuntimeException(e);
        }

        KeyWrapper activeKeyWrapper = new KeyWrapper();
        activeKeyWrapper.setPublicKey(keyPair.getPublic());
        activeKeyWrapper.setAlgorithm("RS256");
        activeKeyWrapper.setCertificate(certificate);
        activeKeyWrapper.setKid(UUID.randomUUID().toString());
        activeKeyWrapper.setPrivateKey(keyPair.getPrivate());
        activeKeyWrapper.setStatus(KeyStatus.ACTIVE);
        when(keyManager.getActiveKey(eq(realm), any(), eq(Algorithm.RS256))).thenReturn(activeKeyWrapper);

        when(activeKey.getPublicKey()).thenReturn(keyPair.getPublic());
        when(activeKey.getPrivateKey()).thenReturn(keyPair.getPrivate());
        when(activeKey.getCertificate()).thenReturn(certificate);
        when(activeKey.getKid()).thenReturn(UUID.randomUUID().toString());

        SecretKey secret = new SecretKeySpec("junit".getBytes(), "HmacSHA256");
        KeyWrapper activeHmacKeyWrapper = new KeyWrapper();
        activeHmacKeyWrapper.setAlgorithm("HS256");
        activeHmacKeyWrapper.setKid(UUID.randomUUID().toString());
        activeHmacKeyWrapper.setSecretKey(secret);
        activeHmacKeyWrapper.setStatus(KeyStatus.ACTIVE);
        when(keyManager.getActiveKey(eq(realm), any(), eq(Algorithm.HS256))).thenReturn(activeHmacKeyWrapper);
    }

    protected void initializeClientModelMock() {
        when(getClient().getId()).thenReturn(UUID.randomUUID().toString());
        when(getClient().getClientId()).thenReturn(getClientId());
        when(getClient().isEnabled()).thenReturn(true);

        for (Map.Entry<String, String> entry : getClientAttributes().entrySet()) {
            when(getClient().getAttribute(entry.getKey())).thenReturn(entry.getValue());
        }

        when(getClient().getProtocolMapperById(anyString())).thenReturn(null);
        for (ProtocolMapperModel mapperModel : protocolMappers.keySet()) {
            when(getClient().getProtocolMapperById(mapperModel.getId())).thenReturn(mapperModel);
        }

        when(realm.getClientByClientId(getClientId())).thenReturn(getClient());
    }

    protected void initializeUserModelMock() {
        when(getUser().getId()).thenReturn(UUID.randomUUID().toString());
        when(getUser().getUsername()).thenReturn(getUserName());
        when(getUser().getEmail()).thenReturn(getEmail());

        Set<GroupModel> userGroups = new HashSet<>();
        GroupModel group1 = mock(GroupModel.class);
        GroupModel group2 = mock(GroupModel.class);
        GroupModel group3 = mock(GroupModel.class);
        userGroups.addAll(Arrays.asList(group1, group2, group3));
        when(group1.getName()).thenReturn("group1");
        when(group2.getName()).thenReturn("group2");
        when(group3.getName()).thenReturn("group3");

        when(user.getGroups()).thenReturn(userGroups);
        when(user.isMemberOf(any())).thenReturn(false);
        when(user.isMemberOf(group1)).thenReturn(true);
        when(user.isMemberOf(group2)).thenReturn(true);
        when(user.isMemberOf(group3)).thenReturn(true);
    }

    protected void initializeLoginFormsProviderMock() {
        when(getLoginFormsProvider().setError(anyString())).thenReturn(getLoginFormsProvider());
        when(getLoginFormsProvider().createErrorPage(Matchers.any(Response.Status.class))).thenAnswer(new Answer<Response>() {
            @Override
            public Response answer(final InvocationOnMock invocation) throws Throwable {
                if (invocation.getArguments()[0] instanceof Response.Status) {
                    return Response.status((Response.Status) invocation.getArguments()[0]).build();
                }
                return Response.serverError().build();
            }
        });
    }

    protected void initializeKeycloakSessionMock() {
        when(getSession().getProvider(LoginFormsProvider.class)).thenReturn(getLoginFormsProvider());
        when(getSession().getProvider(LoginFormsProvider.class).setAuthenticationSession(any())).thenReturn(getLoginFormsProvider());
        when(getSession().getKeycloakSessionFactory()).thenReturn(getSessionFactory());
        when(getSession().users()).thenReturn(mock(UserStorageManager.class));
        when(getSession().users().getUserById(user.getId(), realm)).thenReturn(user);
        when(getSession().getProvider(StickySessionEncoderProvider.class)).thenReturn(mock(StickySessionEncoderProvider.class));

        when(getSession().sessions()).thenReturn(mock(UserSessionProvider.class));
        when(getSession().sessions().getUserSessionByBrokerSessionId(realm, userSessionModel.getBrokerSessionId())).thenReturn(userSessionModel);
        when(getSession().sessions().getUserSessionByBrokerUserId(realm, getUser().getId())).thenReturn(Arrays.asList(userSessionModel));

        AuthenticationSessionProvider authProvider = mock(AuthenticationSessionProvider.class);
        RootAuthenticationSessionModel rootAuthenticationSessionModel = mock(RootAuthenticationSessionModel.class);
        when(rootAuthenticationSessionModel.getId()).thenReturn(UUID.randomUUID().toString());
        when(rootAuthenticationSessionModel.createAuthenticationSession(client)).thenReturn(authSession);
        when(authSession.getParentSession()).thenReturn(rootAuthenticationSessionModel);
        when(authSession.getRealm()).thenReturn(realm);
        when(authProvider.createRootAuthenticationSession(realm)).thenReturn(rootAuthenticationSessionModel);
        when(getSession().authenticationSessions()).thenReturn(authProvider);

        KeycloakContext context = mock(KeycloakContext.class);
        when(getSession().getContext()).thenReturn(context);
        when(context.getUri()).thenReturn(uriInfo);
        ClientConnection clientConnection = mock(ClientConnection.class);
        when(context.getConnection()).thenReturn(clientConnection);

        when(getSession().getProvider(ScriptingProvider.class)).thenReturn(new DefaultScriptingProviderFactory().create(getSession()));
    }

    protected void initializeKeycloakSessionFactoryMock() {
        for (Map.Entry<ProtocolMapperModel, ProtocolMapper> mapper : getProtocolMappers().entrySet()) {
            when(getSessionFactory().getProviderFactory(ProtocolMapper.class, mapper.getKey().getProtocolMapper())).thenReturn(mapper.getValue());
        }
    }

    protected void initializeClientSessionModelMock() {
        when(getClientSessionModel().getId()).thenReturn(UUID.randomUUID().toString());
        when(getClientSessionModel().getClient()).thenReturn(getClient());
        when(getClientSessionModel().getRedirectUri()).thenReturn(getClientId());
        when(clientSession.getRealm()).thenReturn(realm);
        when(clientSession.getNote(OAuth2Constants.SCOPE)).thenReturn("openid");
        when(clientSession.getUserSession()).thenReturn(getUserSessionModel());
        when(client.getRealm()).thenReturn(realm);
        when(client.isFullScopeAllowed()).thenReturn(true);

        for (Map.Entry<String, String> entry : getClientSessionNotes().entrySet()) {
            when(getClientSessionModel().getNote(entry.getKey())).thenReturn(entry.getValue());
        }

        when(getClientSessionModel().getClient().getProtocolMappers()).thenReturn(getProtocolMappers().keySet());
        RoleModel role1 = mock(RoleModel.class);
        RoleModel role2 = mock(RoleModel.class);
        RoleModel role3 = mock(RoleModel.class);
        RoleModel role4 = mock(RoleModel.class);
        when(role1.getName()).thenReturn("role1");
        when(role2.getName()).thenReturn("role2");
        when(role3.getName()).thenReturn("role3");
        when(role4.getName()).thenReturn("role4");

        List<RoleModel> roles = Arrays.asList(role1, role2, role3, role4);
        when(user.getRoleMappings()).thenReturn(new HashSet<RoleModel>(roles));
        when(realm.getRoleById(anyString())).thenReturn(null);
        for (RoleModel role : roles) {
            when(role.getContainer()).thenReturn(client);
            when(role.isComposite()).thenReturn(false);
            when(realm.getRoleById(role.getName())).thenReturn(role);
        }
    }

    protected void initializeAuthSessionModelMock() {
        when(getAuthSessionModel().getClient()).thenReturn(getClient());
        when(getAuthSessionModel().getRedirectUri()).thenReturn(getClientId());
    }

    protected void initializeClientSessionCodeMock() {
        when(getAccessCode().getClientSession()).thenReturn(getClientSessionModel());
        when(getClientSessionModel().getClient().getProtocolMappers()).thenReturn(getProtocolMappers().keySet());
    }

    protected void initializeUserSessionModelMock() {
        when(getUserSessionModel().getId()).thenReturn(UUID.randomUUID().toString());
        when(getUserSessionModel().getBrokerSessionId()).thenReturn(UUID.randomUUID().toString());
        when(getUserSessionModel().getUser()).thenReturn(getUser());
        Map<String, AuthenticatedClientSessionModel> map = Collections.singletonMap(getClient().getId(), getClientSessionModel());
        when(getUserSessionModel().getAuthenticatedClientSessions()).thenReturn(map);
        doReturn(getUser().getId()).when(getUserSessionModel()).getBrokerUserId();
        when(getUserSessionModel().getRealm()).thenReturn(getRealm());
    }

    public String getBaseUri() {
        return baseUri;
    }

    public MockHelper setBaseUri(String baseUri) {
        this.baseUri = baseUri;
        return this;
    }

    public String getClientId() {
        return clientId;
    }

    public MockHelper setClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public Map<String, String> getClientAttributes() {
        return clientAttributes;
    }

    public MockHelper setClientAttributes(Map<String, String> clientAttributes) {
        this.clientAttributes = clientAttributes;
        return this;
    }

    public Map<String, String> getClientSessionNotes() {
        return clientSessionNotes;
    }

    public MockHelper setClientSessionNotes(Map<String, String> clientSessionNotes) {
        this.clientSessionNotes = clientSessionNotes;
        return this;
    }

    public String getUserName() {
        return userName;
    }

    public MockHelper setUserName(String userName) {
        this.userName = userName;
        return this;
    }

    public String getEmail() {
        return email;
    }

    public MockHelper setEmail(String email) {
        this.email = email;
        return this;
    }

    public String getRealmName() {
        return realmName;
    }

    public MockHelper setRealmName(String realmName) {
        this.realmName = realmName;
        return this;
    }

    public int getAccessCodeLifespan() {
        return accessCodeLifespan;
    }

    public MockHelper setAccessCodeLifespan(int accessCodeLifespan) {
        this.accessCodeLifespan = accessCodeLifespan;
        return this;
    }

    public int getAccessTokenLifespan() {
        return accessTokenLifespan;
    }

    public MockHelper setAccessTokenLifespan(int accessTokenLifespan) {
        this.accessTokenLifespan = accessTokenLifespan;
        return this;
    }

    public int getAccessTokenLifespanForImplicitFlow() {
        return accessTokenLifespanForImplicitFlow;
    }

    public MockHelper setAccessTokenLifespanForExplicitFlow(int accessTokenLifespanForExplicitFlow) {
        this.accessTokenLifespanForImplicitFlow = accessTokenLifespanForExplicitFlow;
        return this;
    }

    public UriInfo getUriInfo() {
        return uriInfo;
    }

    public MockHelper setUriInfo(KeycloakUriInfo uriInfo) {
        this.uriInfo = uriInfo;
        return this;
    }

    public RealmModel getRealm() {
        return realm;
    }

    public MockHelper setRealm(RealmModel realm) {
        this.realm = realm;
        return this;
    }

    public ClientModel getClient() {
        return client;
    }

    public MockHelper setClient(ClientModel client) {
        this.client = client;
        return this;
    }

    public UserModel getUser() {
        return user;
    }

    public MockHelper setUser(UserModel user) {
        this.user = user;
        return this;
    }

    public LoginFormsProvider getLoginFormsProvider() {
        return loginFormsProvider;
    }

    public MockHelper setLoginFormsProvider(LoginFormsProvider loginFormsProvider) {
        this.loginFormsProvider = loginFormsProvider;
        return this;
    }

    public KeycloakSession getSession() {
        return session;
    }

    public MockHelper setSessionFactory(KeycloakSessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
        return this;
    }

    public KeycloakSessionFactory getSessionFactory() {
        return sessionFactory;
    }

    public MockHelper setSession(KeycloakSession session) {
        this.session = session;
        return this;
    }

    public AuthenticatedClientSessionModel getClientSessionModel() {
        return clientSession;
    }

    public MockHelper setClientSessionModel(AuthenticatedClientSessionModel clientSession) {
        this.clientSession = clientSession;
        return this;
    }

    public AuthenticationSessionModel getAuthSessionModel() {
        return authSession;
    }

    public void setAuthSessionModel(AuthenticationSessionModel authSession) {
        this.authSession = authSession;
    }

    public ClientSessionCode getAccessCode() {
        return accessCode;
    }

    public MockHelper setAccessCode(ClientSessionCode accessCode) {
        this.accessCode = accessCode;
        return this;
    }

    public UserSessionModel getUserSessionModel() {
        return userSessionModel;
    }

    public MockHelper setUserSessionModel(UserSessionModel userSessionModel) {
        this.userSessionModel = userSessionModel;
        return this;
    }

    public Map<ProtocolMapperModel, ProtocolMapper> getProtocolMappers() {
        return protocolMappers;
    }

    public void setProtocolMappers(Map<ProtocolMapperModel, ProtocolMapper> protocolMappers) {
        this.protocolMappers = protocolMappers;
    }

    public KeyManager.ActiveRsaKey getActiveKey() {
        return activeKey;
    }

    public KeyManager getKeyManager() {
        return keyManager;
    }
}
