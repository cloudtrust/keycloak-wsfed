package com.quest.keycloak.broker.wsfed;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import com.quest.keycloak.common.wsfed.MockHelper;
import com.quest.keycloak.common.wsfed.TestHelpers;
import com.quest.keycloak.common.wsfed.WSFedConstants;
import com.quest.keycloak.protocol.wsfed.builders.RequestSecurityTokenResponseBuilder;
import com.quest.keycloak.protocol.wsfed.builders.WsFedSAML11AssertionTypeBuilder;
import com.quest.keycloak.protocol.wsfed.mappers.SAMLUserPropertyAttributeStatementMapper;
import com.quest.keycloak.protocol.wsfed.mappers.WSFedSAMLAttributeStatementMapper;
import org.junit.Test;
import org.keycloak.dom.saml.v1.assertion.SAML11AssertionType;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.saml.common.constants.GeneralConstants;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityTokenResponse;

import javax.ws.rs.core.Response;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.UUID;

/**
 * Test class for the SAML11RequestedToken class
 */
public class SAML11RequestedTokenTest {

    MockHelper mockHelper = TestHelpers.getMockHelper();

    private RequestSecurityTokenResponseBuilder generateRequestSecurityTokenResponseBuilder() throws ConfigurationException {
        mockHelper.getClientAttributes().put(WsFedSAML11AssertionTypeBuilder.SAML_FORCE_NAME_ID_FORMAT_ATTRIBUTE, "false");
        mockHelper.getClientSessionNotes().put(GeneralConstants.NAMEID_FORMAT, JBossSAMLURIConstants.NAMEID_FORMAT_EMAIL.get());
        mockHelper.initializeMockValues();
        RequestSecurityTokenResponseBuilder builder = new RequestSecurityTokenResponseBuilder();

        builder.setRealm(mockHelper.getClientId())
                .setAction(WSFedConstants.WSFED_SIGNIN_ACTION)
                .setDestination("https://localhost:8443")
                .setContext("context")
                .setTokenExpiration(mockHelper.getAccessTokenLifespan())
                .setRequestIssuer("https://issuer")
                .setSigningKeyPair(new KeyPair(mockHelper.getActiveKey().getPublicKey(), mockHelper.getActiveKey().getPrivateKey()))
                .setSigningCertificate(mockHelper.getActiveKey().getCertificate())
                .setSigningKeyPairId(mockHelper.getActiveKey().getKid());

        WsFedSAML11AssertionTypeBuilder samlBuilder = new WsFedSAML11AssertionTypeBuilder();
        samlBuilder.setRealm(mockHelper.getRealm())
                .setUriInfo(mockHelper.getUriInfo())
                .setAccessCode(mockHelper.getAccessCode())
                .setClientSession(mockHelper.getClientSessionModel())
                .setUserSession(mockHelper.getUserSessionModel())
                .setSession(mockHelper.getSession());

        SAML11AssertionType token = samlBuilder.build();
        builder.setSaml11Token(token);

        return builder;
    }

    private SAML11RequestedToken getSAML11RequestedToken() throws Exception {
        RequestSecurityTokenResponseBuilder builder = generateRequestSecurityTokenResponseBuilder();
        String wsfedResponse = builder.getStringValue();

        WSFedEndpoint endpoint = new WSFedEndpoint(null, null, null, null);
        RequestSecurityTokenResponse rstr = endpoint.getWsfedToken(wsfedResponse);

        return new SAML11RequestedToken(wsfedResponse, rstr.getRequestedSecurityToken().getAny().get(0));
    }


    @Test
    public void testGetId() throws Exception {
        SAML11RequestedToken token = getSAML11RequestedToken();
        assertEquals(mockHelper.getUserName(), token.getId());
    }

    @Test
    public void testGetUsernameNoMapper() throws Exception {
        SAML11RequestedToken token = getSAML11RequestedToken();
        assertEquals(mockHelper.getUserName(), token.getUsername());
    }

    @Test
    public void testGetUsernameWithMapper() throws Exception {
        WSFedSAMLAttributeStatementMapper userMapper = new SAMLUserPropertyAttributeStatementMapper();
        ProtocolMapperModel attributeUsername = SAMLUserPropertyAttributeStatementMapper.createAttributeMapper("SamlUsername", "email", "name", "basic", null, false, null);
        attributeUsername.setId(UUID.randomUUID().toString());
        mockHelper.getProtocolMappers().put(attributeUsername, userMapper);

        SAML11RequestedToken token = getSAML11RequestedToken();
        assertEquals(mockHelper.getEmail(), token.getUsername());
    }

    @Test
    public void testGetUsernameWithBadMapper() throws Exception {
        WSFedSAMLAttributeStatementMapper userMapper = new SAMLUserPropertyAttributeStatementMapper();
        ProtocolMapperModel attributeUsername = SAMLUserPropertyAttributeStatementMapper.createAttributeMapper("SamlUsername", "email", "username", "basic", null, false, null);
        attributeUsername.setId(UUID.randomUUID().toString());
        mockHelper.getProtocolMappers().put(attributeUsername, userMapper);

        SAML11RequestedToken token = getSAML11RequestedToken();
        assertEquals(mockHelper.getUserName(), token.getUsername());
    }

    @Test
    public void testGetEmail() throws Exception {
        WSFedSAMLAttributeStatementMapper userMapper = new SAMLUserPropertyAttributeStatementMapper();
        ProtocolMapperModel attributeUsername = SAMLUserPropertyAttributeStatementMapper.createAttributeMapper("SamlEmail", "email", "emailAddress", "basic", null, false, null);
        attributeUsername.setId(UUID.randomUUID().toString());
        mockHelper.getProtocolMappers().put(attributeUsername, userMapper);

        SAML11RequestedToken token = getSAML11RequestedToken();
        assertEquals(mockHelper.getEmail(), token.getEmail());
    }

    @Test
    public void testGetFirstName() throws Exception {
        WSFedSAMLAttributeStatementMapper userMapper = new SAMLUserPropertyAttributeStatementMapper();
        ProtocolMapperModel attributeUsername = SAMLUserPropertyAttributeStatementMapper.createAttributeMapper("SamlFirstName", "firstName", "givenname", "basic", null, false, null);
        attributeUsername.setId(UUID.randomUUID().toString());
        mockHelper.getProtocolMappers().put(attributeUsername, userMapper);
        when(mockHelper.getUser().getFirstName()).thenReturn("John");

        SAML11RequestedToken token = getSAML11RequestedToken();
        assertEquals("John", token.getFirstName());
    }

    @Test
    public void testGetLastName() throws Exception {
        WSFedSAMLAttributeStatementMapper userMapper = new SAMLUserPropertyAttributeStatementMapper();
        ProtocolMapperModel attributeUsername = SAMLUserPropertyAttributeStatementMapper.createAttributeMapper("SamlLastName", "lastName", "surname", "basic", null, false, null);
        attributeUsername.setId(UUID.randomUUID().toString());
        mockHelper.getProtocolMappers().put(attributeUsername, userMapper);
        when(mockHelper.getUser().getLastName()).thenReturn("Smith");

        SAML11RequestedToken token = getSAML11RequestedToken();
        assertEquals("Smith", token.getLastName());
    }

    @Test
    public void testValidate() throws Exception {
        SAML11RequestedToken token = getSAML11RequestedToken();
        WSFedIdentityProviderConfig config = mock(WSFedIdentityProviderConfig.class);
        when(config.getWsFedRealm()).thenReturn(mockHelper.getClientId());

        Response result = token.validate(mockHelper.getActiveKey().getPublicKey(), config, mock(EventBuilder.class), mockHelper.getSession());
        assertNull(result);
    }

    @Test
    public void testValidateIncorrectKey() throws Exception {
        SAML11RequestedToken token = getSAML11RequestedToken();
        WSFedIdentityProviderConfig config = mock(WSFedIdentityProviderConfig.class);
        when(config.getWsFedRealm()).thenReturn(mockHelper.getClientId());

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        keyGen.initialize(1024, random);
        KeyPair pair = keyGen.generateKeyPair();

        Response result = token.validate(pair.getPublic(), config, mock(EventBuilder.class), mockHelper.getSession());
        assertNotNull(result);
        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), result.getStatus());
    }
}
