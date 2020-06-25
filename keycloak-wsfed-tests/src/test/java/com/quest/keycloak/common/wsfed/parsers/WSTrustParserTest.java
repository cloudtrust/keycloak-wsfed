package com.quest.keycloak.common.wsfed.parsers;

import java.io.IOException;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;

import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.picketlink.common.constants.WSTrustConstants;
import org.picketlink.common.exceptions.ParsingException;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityTokenResponse;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityTokenResponseCollection;

public class WSTrustParserTest extends AbstractParserTest {
    @Test
    public void supportTest() {
        WSTrustParser parser = new WSTrustParser();
        Assert.assertFalse(parser.supports(new QName("dummy", "dummy")));
        Assert.assertTrue(parser.supports(new QName(WSTrustConstants.BASE_NAMESPACE, "dummy")));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void rstrCollectionTest() throws ParsingException, IOException {
        Assert.assertNotNull(parseFile("/samples/complete.xml", RequestSecurityTokenResponseCollection.class));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void rstrTest() throws ParsingException, IOException {
        Assert.assertNotNull(parseFile("/samples/complete.xml", RequestSecurityTokenResponse.class,
                c -> c.substring(c.indexOf('>')+1, c.indexOf("</RequestSecurityTokenResponseCollection"))));
    }

    @Test(expected = RuntimeException.class)
    public void emptyXmlReaderTest() throws ParsingException {
        XMLEventReader mockReader = Mockito.mock(XMLEventReader.class);
        Mockito.when(mockReader.hasNext()).thenReturn(false);
        new WSTrustParser().parse(mockReader);
    }
}
