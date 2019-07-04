package com.quest.keycloak.protocol.wsfed.mappers;

import com.quest.keycloak.protocol.wsfed.WSFedLoginProtocol;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.saml.mappers.GroupMembershipMapper;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * This class handles the mapping of groups to attributes for the WSFed protocol. Groups are handled like any other
 * attributes in output to the SAML claims, but must read from the Keycloak groups rather than from a user's attributes.
 *
 * @author ADD
 */
public class SAMLGroupMembershipMapper extends AbstractWsfedProtocolMapper implements WSFedSAMLAttributeStatementMapper {

    public static final String PROVIDER_ID = "wsfed-saml-group-membership-mapper";
    //The mapper can be static as it holds no state. No reason to have multiple instances
    private static final GroupMembershipMapper mapper;
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        mapper = new GroupMembershipMapper();
        configProperties.addAll(mapper.getConfigProperties());
        addNamespaceToFriendlyProperty(configProperties);
    }

    @Override
    public String getDisplayCategory() {
        return "SAML Group Mapper";
    }

    @Override
    public String getDisplayType() {
        return "SAML Group list";
    }

    @Override
    public String getHelpText() {
        return "Group names are stored in an attribute value.  There is either one attribute with multiple attribute values, or an attribute per group name depending on how you configure it.  You can also specify the attribute name i.e. 'member' or 'memberOf' being examples.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    /**
     * This method directly calls the keycloak group mapper to add the group attributes to the passed attribute statement.
     * The result is therefore in SAML 2.0 by default.
     * The mapper itself uses the mapping model (normally the mapper created in the GUI) and the state of the sessions
     * to get the values to add to the attributes.
     *
     * @param attributeStatement The attribute statements to be added to a token
     * @param mappingModel       The mapping model reflects the values that are actually input in the GUI
     * @param session            The current session
     * @param userSession        The current user session
     * @param clientSession      The current client session
     */
    @Override
    public void transformAttributeStatement(AttributeStatementType attributeStatement, ProtocolMapperModel mappingModel, KeycloakSession session, UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
        mapper.transformAttributeStatement(attributeStatement, mappingModel, session, userSession, clientSession);
    }

    /**
     * Creates an protocol mapper model for the this group membership mapper. This mapper model is meant to be used for
     * testing, as normally such objects are created in a different manner through the keycloak GUI.
     *
     * @param name              The name of the mapper (this has no functional use)
     * @param samlAttributeName The name of the attribute in the SAML attribute
     * @param nameFormat        can be "basic", "URI reference" or "unspecified"
     * @param friendlyName      a display name, only useful for the keycloak GUI
     * @param singleAttribute   If true, all groups will be stored under one attribute with multiple attribute values
     * @return a Protocol Mapper for a group mapping
     */
    public static ProtocolMapperModel create(String name, String samlAttributeName, String nameFormat, String friendlyName, boolean singleAttribute) {
        ProtocolMapperModel model = GroupMembershipMapper.create(name, samlAttributeName, nameFormat, friendlyName, singleAttribute);
        model.setProtocolMapper(PROVIDER_ID);
        model.setProtocol(WSFedLoginProtocol.LOGIN_PROTOCOL);
        return model;
    }
}
