package com.quest.keycloak.broker.wsfed.mappers;

import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;

public class Utils {

    public static AttributeStatementType buildAssertionAttributeStatement(String attributeName, String attributeFriendlyName, String attributeValue) {
        AttributeType attr = new AttributeType("");
        attr.setName(attributeName);
        attr.setFriendlyName(attributeFriendlyName);
        attr.addAttributeValue(attributeValue);
        AttributeStatementType.ASTChoiceType choice = new AttributeStatementType.ASTChoiceType(attr);
        AttributeStatementType ast = new AttributeStatementType();
        ast.addAttribute(choice);

        return ast;
    }
}
