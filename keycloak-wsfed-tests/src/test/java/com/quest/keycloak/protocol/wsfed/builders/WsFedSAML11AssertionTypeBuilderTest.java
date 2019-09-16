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

package com.quest.keycloak.protocol.wsfed.builders;

import com.quest.keycloak.common.wsfed.MockHelper;
import com.quest.keycloak.common.wsfed.TestHelpers;
import com.quest.keycloak.protocol.wsfed.mappers.*;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.keycloak.dom.saml.v1.assertion.*;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.saml.common.constants.GeneralConstants;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.processing.core.saml.v2.util.XMLTimeUtil;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

import static com.quest.keycloak.protocol.wsfed.builders.SAML11AssertionTypeBuilder.CLOCK_SKEW;
import static com.quest.keycloak.protocol.wsfed.builders.WsFedSAMLAssertionTypeAbstractBuilder.WSFED_NAME_ID_FORMAT;
import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.any;

/**
 * This class tests the generation of WSFed 1.1 Tokens. It also serves to test the generation of attributes through
 * the mappers.
 *
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 10/8/2016
 */
public class WsFedSAML11AssertionTypeBuilderTest {

    private MockHelper mockHelper;

    @Before
    public void Before() {
        MockitoAnnotations.initMocks(this);
        mockHelper = TestHelpers.getMockHelper();
    }

    @Test
    public void testSamlTokenGeneration() throws Exception {

//        mockHelper.getClientAttributes().put(WSFedSAML11AssertionTypeBuilder, "false");
        mockHelper.getClientSessionNotes().put(GeneralConstants.NAMEID_FORMAT, JBossSAMLURIConstants.NAMEID_FORMAT_UNSPECIFIED.get());

        //Role Mapper
        ProtocolMapperModel roleMappingModel = mock(ProtocolMapperModel.class);
        when(roleMappingModel.getProtocolMapper()).thenReturn(UUID.randomUUID().toString());
        WSFedSAMLRoleListMapper roleListMapper = mock(WSFedSAMLRoleListMapper.class);
        mockHelper.getProtocolMappers().put(roleMappingModel, roleListMapper);

        //Attribute Mapper
        ProtocolMapperModel attributeMappingModel = mock(ProtocolMapperModel.class);
        when(attributeMappingModel.getProtocolMapper()).thenReturn(UUID.randomUUID().toString());
        WSFedSAMLAttributeStatementMapper attributeMapper = mock(WSFedSAMLAttributeStatementMapper.class);
        mockHelper.getProtocolMappers().put(attributeMappingModel, attributeMapper);



        mockHelper.initializeMockValues();

        //SAML Token generation
        WsFedSAML11AssertionTypeBuilder samlBuilder = new WsFedSAML11AssertionTypeBuilder();
        samlBuilder.setRealm(mockHelper.getRealm())
                .setUriInfo(mockHelper.getUriInfo())
                .setAccessCode(mockHelper.getAccessCode())
                .setClientSession(mockHelper.getClientSessionModel())
                .setUserSession(mockHelper.getUserSessionModel())
                .setSession(mockHelper.getSession());

        SAML11AssertionType token = samlBuilder.build();

        assertNotNull(token);

        assertEquals(String.format("%s/realms/%s", mockHelper.getBaseUri(), mockHelper.getRealmName()), token.getIssuer());
        // TODO fix me! Check the specs if the name id format is a part of the SAML 1.1 token
//        assertEquals(URI.create(mockHelper.getClientSessionNotes().get(WSFED_NAME_ID_FORMAT)), JBossSAMLURIConstants.NAMEID_FORMAT_UNSPECIFIED);

        assertNotNull(token.getIssueInstant());
        assertNotNull(token.getConditions().getNotBefore());
        assertNotNull(token.getConditions().getNotOnOrAfter());

        assertNotNull(token.getStatements());
        assertNotNull(token.getConditions().getNotOnOrAfter());

        // Verify that the token time is within the time interval specified by the conditions statement
        // and that the time interval is adjusted by a small amount to account for clock skew
        assertEquals(token.getConditions().getNotBefore(), XMLTimeUtil.subtract(token.getIssueInstant(), CLOCK_SKEW));
        assertEquals(XMLTimeUtil.add(token.getConditions().getNotBefore(), mockHelper.getAccessTokenLifespanForImplicitFlow() * 1000 + CLOCK_SKEW + CLOCK_SKEW), token.getConditions().getNotOnOrAfter());
        assertEquals(XMLTimeUtil.add(token.getIssueInstant(), mockHelper.getAccessTokenLifespanForImplicitFlow() * 1000 + CLOCK_SKEW), token.getConditions().getNotOnOrAfter());

        assertEquals(mockHelper.getClientId(), ((SAML11AudienceRestrictionCondition) token.getConditions().get().get(0)).get().get(0).toString());

        assertTrue(token.getStatements().size() > 1);
        assertNotNull(token.getStatements().get(1));
        assertTrue(token.getStatements().get(1) instanceof SAML11AuthenticationStatementType);

        SAML11AuthenticationStatementType authType = (SAML11AuthenticationStatementType)token.getStatements().get(1);
        assertEquals(authType.getAuthenticationInstant(), token.getIssueInstant());
        assertEquals(authType.getAuthenticationMethod().toString(), JBossSAMLURIConstants.AC_PASSWORD_PROTECTED_TRANSPORT.get());
        assertEquals(authType.getSubject().getSubjectConfirmation().getConfirmationMethod().get(0), URI.create("urn:oasis:names:tc:SAML:1.0:cm:bearer"));

        AuthenticatedClientSessionModel clientSession = mockHelper.getClientSessionModel();
        verify(clientSession, times(1)).setNote(WsFedSAML11AssertionTypeBuilder.WSFED_NAME_ID, mockHelper.getUserName());
        verify(clientSession, times(1)).setNote(WSFED_NAME_ID_FORMAT, mockHelper.getClientSessionNotes().get(GeneralConstants.NAMEID_FORMAT));

        verify(roleListMapper, times(1)).mapRoles(any(AttributeStatementType.class), eq(roleMappingModel), eq(mockHelper.getSession()), eq(mockHelper.getUserSessionModel()), eq(mockHelper.getClientSessionModel()));
        verify(attributeMapper, times(1)).transformAttributeStatement(any(AttributeStatementType.class), eq(attributeMappingModel), eq(mockHelper.getSession()), eq(mockHelper.getUserSessionModel()), eq(mockHelper.getClientSessionModel()));

    }

    @Test
    public  void testSAMLTokenGenerationRoleWithNamespaceInFriendlyName() throws ConfigurationException {
        mockHelper.getClientSessionNotes().put(GeneralConstants.NAMEID_FORMAT, JBossSAMLURIConstants.NAMEID_FORMAT_UNSPECIFIED.get());

        WSFedSAMLRoleListMapper roleMapper = new SAMLRoleListMapper();

        ProtocolMapperModel attributeRoles = SAMLRoleListMapper.create("Role mapper joined","Role", "basic", "testClaimsNamespace", true);
        attributeRoles.setId(UUID.randomUUID().toString());
        mockHelper.getProtocolMappers().put(attributeRoles, roleMapper);

        mockHelper.initializeMockValues();

        //SAML Token generation
        WsFedSAML11AssertionTypeBuilder samlBuilder = new WsFedSAML11AssertionTypeBuilder();
        samlBuilder.setRealm(mockHelper.getRealm())
                .setUriInfo(mockHelper.getUriInfo())
                .setAccessCode(mockHelper.getAccessCode())
                .setClientSession(mockHelper.getClientSessionModel())
                .setUserSession(mockHelper.getUserSessionModel())
                .setSession(mockHelper.getSession());

        SAML11AssertionType token = samlBuilder.build();

        assertTrue(token.getStatements().get(0) instanceof SAML11AttributeStatementType);
        SAML11AttributeStatementType attributesStatements = (SAML11AttributeStatementType)token.getStatements().get(0);
        assertEquals(1, attributesStatements.get().size());
        SAML11AttributeType attribute = attributesStatements.get().get(0);
        assertEquals("role", attribute.getAttributeName());

        assertEquals(URI.create("testClaimsNamespace"), attribute.getAttributeNamespace());

        List<?> attributeValues = attribute.get();
        assertTrue(attributeValues.contains("role1"));
        assertTrue(attributeValues.contains("role2"));
        assertTrue(attributeValues.contains("role3"));
        assertTrue(attributeValues.contains("role4"));
    }

    @Test
    public void testSAMLTokenGenerationAttributeMapping() throws ConfigurationException {
        mockHelper.getClientSessionNotes().put(GeneralConstants.NAMEID_FORMAT, JBossSAMLURIConstants.NAMEID_FORMAT_UNSPECIFIED.get());

        WSFedSAMLAttributeStatementMapper userMapper = new SAMLUserPropertyAttributeStatementMapper();
        WSFedSAMLAttributeStatementMapper attributeMapper = new SAMLUserAttributeStatementMapper();

        ProtocolMapperModel attributeEmail = SAMLUserPropertyAttributeStatementMapper.createAttributeMapper("SamlEmail", "email", "e-mail", "basic", null, false, null);
        attributeEmail.setId(UUID.randomUUID().toString());
        mockHelper.getProtocolMappers().put(attributeEmail, userMapper);

        ProtocolMapperModel attributeUsername = SAMLUserPropertyAttributeStatementMapper.createAttributeMapper("SamlUsername", "username", "upn", "basic", null, false, null);
        attributeUsername.setId(UUID.randomUUID().toString());
        mockHelper.getProtocolMappers().put(attributeUsername, userMapper);

        ProtocolMapperModel attributeMemberOf = SAMLUserAttributeStatementMapper.createAttributeMapper("SamlMemberOf", "memberOf", "memberOf", "basic", null, false, null);
        attributeMemberOf.setId(UUID.randomUUID().toString());
        mockHelper.getProtocolMappers().put(attributeMemberOf, attributeMapper);

        mockHelper.initializeMockValues();
        when(mockHelper.getUser().getAttribute("memberOf")).thenReturn(Collections.singletonList("aGroup"));

        //SAML Token generation
        WsFedSAML11AssertionTypeBuilder samlBuilder = new WsFedSAML11AssertionTypeBuilder();
        samlBuilder.setRealm(mockHelper.getRealm())
                .setUriInfo(mockHelper.getUriInfo())
                .setAccessCode(mockHelper.getAccessCode())
                .setClientSession(mockHelper.getClientSessionModel())
                .setUserSession(mockHelper.getUserSessionModel())
                .setSession(mockHelper.getSession());

        SAML11AssertionType token = samlBuilder.build();

        assertTrue(token.getStatements().get(0) instanceof SAML11AttributeStatementType);
        SAML11AttributeStatementType attributesStatements = (SAML11AttributeStatementType)token.getStatements().get(0);

        List<String> attributeValues = attributesStatements.get().stream().flatMap(attributeList ->
                attributeList.get().stream().map(attributeValue -> (String)attributeValue)).collect(Collectors.toList());

        assertTrue(attributeValues.contains("aGroup"));
        assertTrue(attributeValues.contains("first.last@somedomain.com"));
        assertTrue(attributeValues.contains("username"));
    }

    @Test
    public void testSAMLTokenGenerationAttributeMappingWithNamespaceInFriendlyName() throws ConfigurationException {
        mockHelper.getClientSessionNotes().put(GeneralConstants.NAMEID_FORMAT, JBossSAMLURIConstants.NAMEID_FORMAT_UNSPECIFIED.get());

        WSFedSAMLAttributeStatementMapper userMapper = new SAMLUserPropertyAttributeStatementMapper();
        WSFedSAMLAttributeStatementMapper attributeMapper = new SAMLUserAttributeStatementMapper();

        ProtocolMapperModel attributeEmail = SAMLUserPropertyAttributeStatementMapper.createAttributeMapper("SamlEmail", "email", "e-mail", "basic", "testClaimsNamespace", false, null);
        attributeEmail.setId(UUID.randomUUID().toString());
        mockHelper.getProtocolMappers().put(attributeEmail, userMapper);

        ProtocolMapperModel attributeUsername = SAMLUserPropertyAttributeStatementMapper.createAttributeMapper("SamlUsername", "username", "upn", "basic", "testClaimsNamespace", false, null);
        attributeUsername.setId(UUID.randomUUID().toString());
        mockHelper.getProtocolMappers().put(attributeUsername, userMapper);

        ProtocolMapperModel attributeMemberOf = SAMLUserAttributeStatementMapper.createAttributeMapper("SamlMemberOf", "memberOf", "memberOf", "basic", "testClaimsNamespace", false, null);
        attributeMemberOf.setId(UUID.randomUUID().toString());
        mockHelper.getProtocolMappers().put(attributeMemberOf, attributeMapper);

        mockHelper.initializeMockValues();
        when(mockHelper.getUser().getAttribute("memberOf")).thenReturn(Collections.singletonList("aGroup"));

        //SAML Token generation
        WsFedSAML11AssertionTypeBuilder samlBuilder = new WsFedSAML11AssertionTypeBuilder();
        samlBuilder.setRealm(mockHelper.getRealm())
                .setUriInfo(mockHelper.getUriInfo())
                .setAccessCode(mockHelper.getAccessCode())
                .setClientSession(mockHelper.getClientSessionModel())
                .setUserSession(mockHelper.getUserSessionModel())
                .setSession(mockHelper.getSession());

        SAML11AssertionType token = samlBuilder.build();

        assertTrue(token.getStatements().get(0) instanceof SAML11AttributeStatementType);
        SAML11AttributeStatementType attributesStatements = (SAML11AttributeStatementType)token.getStatements().get(0);

        List<SAML11AttributeType> attributes = attributesStatements.get();
        for(SAML11AttributeType attr : attributes) {
            assertEquals(URI.create("testClaimsNamespace"), attr.getAttributeNamespace());
        }

        List<String> attributeValues = attributesStatements.get().stream().flatMap(attributeList ->
                attributeList.get().stream().map(attributeValue -> (String)attributeValue)).collect(Collectors.toList());

        assertTrue(attributeValues.contains("aGroup"));
        assertTrue(attributeValues.contains("first.last@somedomain.com"));
        assertTrue(attributeValues.contains("username"));
    }

    @Test
    public void testSAMLTokenGenerationGroupMappingJoined() throws ConfigurationException {
        mockHelper.getClientSessionNotes().put(GeneralConstants.NAMEID_FORMAT, JBossSAMLURIConstants.NAMEID_FORMAT_UNSPECIFIED.get());

        WSFedSAMLAttributeStatementMapper groupMapper = new SAMLGroupMembershipMapper();

        ProtocolMapperModel attributeGroups = SAMLGroupMembershipMapper.create("Group mapper joined","memberOf", "basic", null, true);
        attributeGroups.setId(UUID.randomUUID().toString());
        mockHelper.getProtocolMappers().put(attributeGroups, groupMapper);

        mockHelper.initializeMockValues();

        //SAML Token generation
        WsFedSAML11AssertionTypeBuilder samlBuilder = new WsFedSAML11AssertionTypeBuilder();
        samlBuilder.setRealm(mockHelper.getRealm())
                .setUriInfo(mockHelper.getUriInfo())
                .setAccessCode(mockHelper.getAccessCode())
                .setClientSession(mockHelper.getClientSessionModel())
                .setUserSession(mockHelper.getUserSessionModel())
                .setSession(mockHelper.getSession());

        SAML11AssertionType token = samlBuilder.build();

        assertTrue(token.getStatements().get(0) instanceof SAML11AttributeStatementType);
        SAML11AttributeStatementType attributesStatements = (SAML11AttributeStatementType)token.getStatements().get(0);
        assertEquals(1, attributesStatements.get().size());
        SAML11AttributeType attribute = attributesStatements.get().get(0);
        assertEquals("memberOf", attribute.getAttributeName());

        List<?> attributeValues = attribute.get();
        assertTrue(attributeValues.contains("group1"));
        assertTrue(attributeValues.contains("group2"));
        assertTrue(attributeValues.contains("group3"));
    }

    @Test
    public void testSAMLTokenGenerationGroupMappingNotJoined() throws ConfigurationException {
        mockHelper.getClientSessionNotes().put(GeneralConstants.NAMEID_FORMAT, JBossSAMLURIConstants.NAMEID_FORMAT_UNSPECIFIED.get());

        WSFedSAMLAttributeStatementMapper groupMapper = new SAMLGroupMembershipMapper();

        ProtocolMapperModel attributeGroups = SAMLGroupMembershipMapper.create("Group mapper joined","memberOf", "basic", null, false);
        attributeGroups.setId(UUID.randomUUID().toString());
        mockHelper.getProtocolMappers().put(attributeGroups, groupMapper);

        mockHelper.initializeMockValues();

        //SAML Token generation
        WsFedSAML11AssertionTypeBuilder samlBuilder = new WsFedSAML11AssertionTypeBuilder();
        samlBuilder.setRealm(mockHelper.getRealm())
                .setUriInfo(mockHelper.getUriInfo())
                .setAccessCode(mockHelper.getAccessCode())
                .setClientSession(mockHelper.getClientSessionModel())
                .setUserSession(mockHelper.getUserSessionModel())
                .setSession(mockHelper.getSession());

        SAML11AssertionType token = samlBuilder.build();

        assertTrue(token.getStatements().get(0) instanceof SAML11AttributeStatementType);
        SAML11AttributeStatementType attributesStatements = (SAML11AttributeStatementType)token.getStatements().get(0);
        assertEquals(3, attributesStatements.get().size());
        Set<String> attributeNameSet = attributesStatements.get().stream().map(attribute -> attribute.getAttributeName()).collect(Collectors.toSet());
        assertEquals(1, attributeNameSet.size());
        assertEquals("memberOf", attributeNameSet.toArray(new String[1])[0]);

        List<String> attributeValues = attributesStatements.get().stream().flatMap(attributeList ->
                attributeList.get().stream().map(attributeValue -> (String)attributeValue)).collect(Collectors.toList());

        assertTrue(attributeValues.contains("group1"));
        assertTrue(attributeValues.contains("group2"));
        assertTrue(attributeValues.contains("group3"));
    }


    @Test
    public void testSAMLTokenGenerationRoleMappingJoined() throws ConfigurationException {
        mockHelper.getClientSessionNotes().put(GeneralConstants.NAMEID_FORMAT, JBossSAMLURIConstants.NAMEID_FORMAT_UNSPECIFIED.get());

        WSFedSAMLRoleListMapper roleMapper = new SAMLRoleListMapper();

        ProtocolMapperModel attributeRoles = SAMLRoleListMapper.create("Role mapper joined","Role", "basic", null, true);
        attributeRoles.setId(UUID.randomUUID().toString());
        mockHelper.getProtocolMappers().put(attributeRoles, roleMapper);

        mockHelper.initializeMockValues();

        //SAML Token generation
        WsFedSAML11AssertionTypeBuilder samlBuilder = new WsFedSAML11AssertionTypeBuilder();
        samlBuilder.setRealm(mockHelper.getRealm())
                .setUriInfo(mockHelper.getUriInfo())
                .setAccessCode(mockHelper.getAccessCode())
                .setClientSession(mockHelper.getClientSessionModel())
                .setUserSession(mockHelper.getUserSessionModel())
                .setSession(mockHelper.getSession());

        SAML11AssertionType token = samlBuilder.build();

        assertTrue(token.getStatements().get(0) instanceof SAML11AttributeStatementType);
        SAML11AttributeStatementType attributesStatements = (SAML11AttributeStatementType)token.getStatements().get(0);
        assertEquals(1, attributesStatements.get().size());
        SAML11AttributeType attribute = attributesStatements.get().get(0);
        assertEquals("role", attribute.getAttributeName());

        List<?> attributeValues = attribute.get();
        assertTrue(attributeValues.contains("role1"));
        assertTrue(attributeValues.contains("role2"));
        assertTrue(attributeValues.contains("role3"));
        assertTrue(attributeValues.contains("role4"));
    }

    @Test
    public void testSAMLTokenGenerationRoleMappingNotJoined() throws ConfigurationException {
        mockHelper.getClientSessionNotes().put(GeneralConstants.NAMEID_FORMAT, JBossSAMLURIConstants.NAMEID_FORMAT_UNSPECIFIED.get());

        WSFedSAMLRoleListMapper roleMapper = new SAMLRoleListMapper();

        ProtocolMapperModel attributeRoles = SAMLRoleListMapper.create("Role mapper joined","Role", "basic", null, false);
        attributeRoles.setId(UUID.randomUUID().toString());
        mockHelper.getProtocolMappers().put(attributeRoles, roleMapper);

        mockHelper.initializeMockValues();

        //SAML Token generation
        WsFedSAML11AssertionTypeBuilder samlBuilder = new WsFedSAML11AssertionTypeBuilder();
        samlBuilder.setRealm(mockHelper.getRealm())
                .setUriInfo(mockHelper.getUriInfo())
                .setAccessCode(mockHelper.getAccessCode())
                .setClientSession(mockHelper.getClientSessionModel())
                .setUserSession(mockHelper.getUserSessionModel())
                .setSession(mockHelper.getSession());

        SAML11AssertionType token = samlBuilder.build();

        assertTrue(token.getStatements().get(0) instanceof SAML11AttributeStatementType);
        SAML11AttributeStatementType attributesStatements = (SAML11AttributeStatementType)token.getStatements().get(0);
        assertEquals(4, attributesStatements.get().size());
        Set<String> attributeNameSet = attributesStatements.get().stream().map(attribute -> attribute.getAttributeName()).collect(Collectors.toSet());
        assertEquals(1, attributeNameSet.size());
        assertEquals("role", attributeNameSet.toArray(new String[1])[0]);

        List<String> attributeValues = attributesStatements.get().stream().flatMap(attributeList ->
                attributeList.get().stream().map(attributeValue -> (String)attributeValue)).collect(Collectors.toList());

        assertTrue(attributeValues.contains("role1"));
        assertTrue(attributeValues.contains("role2"));
        assertTrue(attributeValues.contains("role3"));
        assertTrue(attributeValues.contains("role4"));
    }

    @Test
    public void testSAMLTokenGenerationJSTrivial() throws ConfigurationException {
        mockHelper.getClientSessionNotes().put(GeneralConstants.NAMEID_FORMAT, JBossSAMLURIConstants.NAMEID_FORMAT_UNSPECIFIED.get());

        WSFedSAMLAttributeStatementMapper scriptMapper = new SAMLScriptBasedMapper();

        ProtocolMapperModel attributeScript = SAMLScriptBasedMapper.create("Trivial script mapper","const", "basic", null, "var s = 'This is a trivial test'; s;", false);
        attributeScript.setId(UUID.randomUUID().toString());
        mockHelper.getProtocolMappers().put(attributeScript, scriptMapper);

        mockHelper.initializeMockValues();

        //SAML Token generation
        WsFedSAML11AssertionTypeBuilder samlBuilder = new WsFedSAML11AssertionTypeBuilder();
        samlBuilder.setRealm(mockHelper.getRealm())
                .setUriInfo(mockHelper.getUriInfo())
                .setAccessCode(mockHelper.getAccessCode())
                .setClientSession(mockHelper.getClientSessionModel())
                .setUserSession(mockHelper.getUserSessionModel())
                .setSession(mockHelper.getSession());

        SAML11AssertionType token = samlBuilder.build();

        assertTrue(token.getStatements().get(0) instanceof SAML11AttributeStatementType);
        SAML11AttributeStatementType attributesStatements = (SAML11AttributeStatementType)token.getStatements().get(0);
        assertEquals(1, attributesStatements.get().size());
        Set<String> attributeNameSet = attributesStatements.get().stream().map(attribute -> attribute.getAttributeName()).collect(Collectors.toSet());
        assertEquals(1, attributeNameSet.size());
        assertEquals("const", attributeNameSet.toArray(new String[1])[0]);

        List<String> attributeValues = attributesStatements.get().stream().flatMap(attributeList ->
                attributeList.get().stream().map(attributeValue -> (String)attributeValue)).collect(Collectors.toList());

        assertTrue(attributeValues.contains("This is a trivial test"));
    }

    @Test
    public void testSAMLTokenGenerationJSMorphedGroup() throws ConfigurationException {
        mockHelper.getClientSessionNotes().put(GeneralConstants.NAMEID_FORMAT, JBossSAMLURIConstants.NAMEID_FORMAT_UNSPECIFIED.get());

        WSFedSAMLAttributeStatementMapper scriptMapper = new SAMLScriptBasedMapper();
        String script = "var theUser = user; " +
                "var groups = user.getGroups(); " +
                "var result = ''; " +
                "for each (var group in groups) result = result + 'morph-' + group.getName() + ';';" +
                "result;";
        ProtocolMapperModel attributeScript = SAMLScriptBasedMapper.create("Trivial script mapper","morphedGroup", "basic", null, script, false);
        attributeScript.setId(UUID.randomUUID().toString());
        mockHelper.getProtocolMappers().put(attributeScript, scriptMapper);

        mockHelper.initializeMockValues();

        //SAML Token generation
        WsFedSAML11AssertionTypeBuilder samlBuilder = new WsFedSAML11AssertionTypeBuilder();
        samlBuilder.setRealm(mockHelper.getRealm())
                .setUriInfo(mockHelper.getUriInfo())
                .setAccessCode(mockHelper.getAccessCode())
                .setClientSession(mockHelper.getClientSessionModel())
                .setUserSession(mockHelper.getUserSessionModel())
                .setSession(mockHelper.getSession());

        SAML11AssertionType token = samlBuilder.build();

        assertTrue(token.getStatements().get(0) instanceof SAML11AttributeStatementType);
        SAML11AttributeStatementType attributesStatements = (SAML11AttributeStatementType)token.getStatements().get(0);
        assertEquals(1, attributesStatements.get().size());
        Set<String> attributeNameSet = attributesStatements.get().stream().map(attribute -> attribute.getAttributeName()).collect(Collectors.toSet());
        assertEquals(1, attributeNameSet.size());
        assertEquals("morphedGroup", attributeNameSet.toArray(new String[1])[0]);

        List<String> attributeValues = attributesStatements.get().stream().flatMap(attributeList ->
                attributeList.get().stream().map(attributeValue -> (String)attributeValue)).collect(Collectors.toList());

        assertTrue(attributeValues.get(0).contains("morph-group1;"));
        assertTrue(attributeValues.get(0).contains("morph-group2;"));
        assertTrue(attributeValues.get(0).contains("morph-group3;"));
    }

    @Test
    public void testSAMLTokenGenerationJSMorphedGroupArrayMultiple() throws ConfigurationException {
        mockHelper.getClientSessionNotes().put(GeneralConstants.NAMEID_FORMAT, JBossSAMLURIConstants.NAMEID_FORMAT_UNSPECIFIED.get());

        WSFedSAMLAttributeStatementMapper scriptMapper = new SAMLScriptBasedMapper();
        String script = "var theUser = user; " +
                "var groups = user.getGroups(); " +
                "var array = []; " +
                "for each (var group in groups) array.push('morph-' + group.getName());" +
                "var result = Java.to(array);" +
                "result;";
        ProtocolMapperModel attributeScript = SAMLScriptBasedMapper.create("Trivial script mapper","morphedGroup", "basic", null, script, false);
        attributeScript.setId(UUID.randomUUID().toString());
        mockHelper.getProtocolMappers().put(attributeScript, scriptMapper);

        mockHelper.initializeMockValues();

        //SAML Token generation
        WsFedSAML11AssertionTypeBuilder samlBuilder = new WsFedSAML11AssertionTypeBuilder();
        samlBuilder.setRealm(mockHelper.getRealm())
                .setUriInfo(mockHelper.getUriInfo())
                .setAccessCode(mockHelper.getAccessCode())
                .setClientSession(mockHelper.getClientSessionModel())
                .setUserSession(mockHelper.getUserSessionModel())
                .setSession(mockHelper.getSession());

        SAML11AssertionType token = samlBuilder.build();

        assertTrue(token.getStatements().get(0) instanceof SAML11AttributeStatementType);
        SAML11AttributeStatementType attributesStatements = (SAML11AttributeStatementType)token.getStatements().get(0);
        assertEquals(3, attributesStatements.get().size());
        Set<String> attributeNameSet = attributesStatements.get().stream().map(attribute -> attribute.getAttributeName()).collect(Collectors.toSet());
        assertEquals(1, attributeNameSet.size());
        assertEquals("morphedGroup", attributeNameSet.toArray(new String[1])[0]);

        List<String> attributeValues = attributesStatements.get().stream().flatMap(attributeList ->
                attributeList.get().stream().map(attributeValue -> (String)attributeValue)).collect(Collectors.toList());

        assertTrue(attributeValues.contains("morph-group1"));
        assertTrue(attributeValues.contains("morph-group2"));
        assertTrue(attributeValues.contains("morph-group3"));
    }

    @Test
    public void testSAMLTokenGenerationJSMorphedGroupListSingle() throws ConfigurationException {
        mockHelper.getClientSessionNotes().put(GeneralConstants.NAMEID_FORMAT, JBossSAMLURIConstants.NAMEID_FORMAT_UNSPECIFIED.get());

        WSFedSAMLAttributeStatementMapper scriptMapper = new SAMLScriptBasedMapper();
        String script = "var list = new java.util.ArrayList(); " +
                "for each (var group in user.getGroups()) list.add('morph-' + group.getName());" +
                "list;";
        ProtocolMapperModel attributeScript = SAMLScriptBasedMapper.create("Trivial script mapper","morphedGroup", "basic", null, script, true);
        attributeScript.setId(UUID.randomUUID().toString());
        mockHelper.getProtocolMappers().put(attributeScript, scriptMapper);

        mockHelper.initializeMockValues();

        //SAML Token generation
        WsFedSAML11AssertionTypeBuilder samlBuilder = new WsFedSAML11AssertionTypeBuilder();
        samlBuilder.setRealm(mockHelper.getRealm())
                .setUriInfo(mockHelper.getUriInfo())
                .setAccessCode(mockHelper.getAccessCode())
                .setClientSession(mockHelper.getClientSessionModel())
                .setUserSession(mockHelper.getUserSessionModel())
                .setSession(mockHelper.getSession());

        SAML11AssertionType token = samlBuilder.build();

        assertTrue(token.getStatements().get(0) instanceof SAML11AttributeStatementType);
        SAML11AttributeStatementType attributesStatements = (SAML11AttributeStatementType)token.getStatements().get(0);
        assertEquals(1, attributesStatements.get().size());
        Set<String> attributeNameSet = attributesStatements.get().stream().map(attribute -> attribute.getAttributeName()).collect(Collectors.toSet());
        assertEquals(1, attributeNameSet.size());
        assertEquals("morphedGroup", attributeNameSet.toArray(new String[1])[0]);

        List<String> attributeValues = attributesStatements.get().stream().flatMap(attributeList ->
                attributeList.get().stream().map(attributeValue -> (String)attributeValue)).collect(Collectors.toList());

        assertTrue(attributeValues.contains("morph-group1"));
        assertTrue(attributeValues.contains("morph-group2"));
        assertTrue(attributeValues.contains("morph-group3"));
    }

    @Ignore
    @Test
    public void testSAMLTokenGenerationJSShadowGroup() throws ConfigurationException {
        mockHelper.getClientSessionNotes().put(GeneralConstants.NAMEID_FORMAT, JBossSAMLURIConstants.NAMEID_FORMAT_UNSPECIFIED.get());

        WSFedSAMLAttributeStatementMapper scriptMapper = new SAMLScriptBasedMapper();
        String script = "var theUser = user; " +
                "var HttpGet = Java.type('org.apache.http.client.methods.HttpGet');" +
                "var HttpClients = Java.type('org.apache.http.impl.client.HttpClients');" +
                "var EntityUtils = Java.type('org.apache.http.util.EntityUtils');" +
                "var StandardCharsets = Java.type('java.nio.charset.StandardCharsets');" +
                "var request = new HttpGet('http://localhost/shadowgroups/usg/' + theUser.getUsername() + '?applicationUrl=smip.dev.icrc.org&mobilityStatus=mobile&jobFunctionCode=000152');" +
                "request.addHeader('referer', 'http://test.com');" +
                "var client = HttpClients.createDefault();" +
                "var response = client.execute(request);" +
                "try {" +
                "   var jsonString = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);" +
                "   var obj = JSON.parse(jsonString);" +
                "   var array = obj.$values;" +
                "} finally {" +
                "   response.close();" +
                "   client.close();" +
                "}" +
                "var result = Java.to(array);" +
                "result;";
        ProtocolMapperModel attributeScript = SAMLScriptBasedMapper.create("Trivial script mapper","morphedGroup", "basic", null, script, false);
        attributeScript.setId(UUID.randomUUID().toString());
        mockHelper.getProtocolMappers().put(attributeScript, scriptMapper);

        mockHelper.initializeMockValues();

        //SAML Token generation
        WsFedSAML11AssertionTypeBuilder samlBuilder = new WsFedSAML11AssertionTypeBuilder();
        samlBuilder.setRealm(mockHelper.getRealm())
                .setUriInfo(mockHelper.getUriInfo())
                .setAccessCode(mockHelper.getAccessCode())
                .setClientSession(mockHelper.getClientSessionModel())
                .setUserSession(mockHelper.getUserSessionModel())
                .setSession(mockHelper.getSession());

        SAML11AssertionType token = samlBuilder.build();

        assertTrue(token.getStatements().get(0) instanceof SAML11AttributeStatementType);
        SAML11AttributeStatementType attributesStatements = (SAML11AttributeStatementType)token.getStatements().get(0);
        assertEquals(7, attributesStatements.get().size());
        Set<String> attributeNameSet = attributesStatements.get().stream().map(attribute -> attribute.getAttributeName()).collect(Collectors.toSet());
        assertEquals(1, attributeNameSet.size());
        assertEquals("morphedGroup", attributeNameSet.toArray(new String[1])[0]);

        List<String> attributeValues = attributesStatements.get().stream().flatMap(attributeList ->
                attributeList.get().stream().map(attributeValue -> (String)attributeValue)).collect(Collectors.toList());

        assertTrue(attributeValues.contains("alpha"));
        assertTrue(attributeValues.contains("bravo"));
        assertTrue(attributeValues.contains("charlie"));
        assertTrue(attributeValues.contains("delta"));
        assertTrue(attributeValues.contains(mockHelper.getUser().getUsername()));
    }

}
