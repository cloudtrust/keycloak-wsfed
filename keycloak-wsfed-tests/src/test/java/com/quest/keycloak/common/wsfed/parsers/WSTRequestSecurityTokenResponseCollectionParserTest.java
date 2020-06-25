package com.quest.keycloak.common.wsfed.parsers;

import java.io.IOException;
import java.util.Map;
import java.util.function.Function;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.StartElement;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.picketlink.common.constants.WSTrustConstants;
import org.picketlink.common.exceptions.ParsingException;
import org.picketlink.common.parsers.ParserNamespaceSupport;
import org.picketlink.common.util.StaxParserUtil;
import org.picketlink.identity.federation.core.parsers.ParserController;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityTokenResponse;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityTokenResponseCollection;
import org.picketlink.identity.federation.ws.policy.AppliesTo;
import org.picketlink.identity.federation.ws.trust.BinarySecretType;
import org.picketlink.identity.federation.ws.trust.ComputedKeyType;
import org.picketlink.identity.federation.ws.wss.secext.UsernameTokenType;

public class WSTRequestSecurityTokenResponseCollectionParserTest extends AbstractParserTest {
    public static class AdditionalNamespaceSupport implements ParserNamespaceSupport {
        private String tag = "AdditionalTag";

        @Override
        public boolean supports(QName qname) {
            return tag.equals(qname.getLocalPart());
        }

        @Override
        public Object parse(XMLEventReader xmlEventReader) throws ParsingException {
            StartElement startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
            StaxParserUtil.validate(startElement, tag);
            if (!StaxParserUtil.hasTextAhead(xmlEventReader)) {
                return this;
            }

            return new AppliesToUnknownTag(StaxParserUtil.getElementText(xmlEventReader));
        }
    };

    public static class AppliesToUnknownTag extends AppliesTo {
        private String value;

        public AppliesToUnknownTag(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }

    private AdditionalNamespaceSupport additionalTagSupport;

    @Before
    public void testSetup() {
        if (additionalTagSupport==null) {
            additionalTagSupport = new AdditionalNamespaceSupport();
            ParserController.add(additionalTagSupport);
        }
    }

    @Test
    public void supportRSTCollectionTest() {
        WSTRequestSecurityTokenResponseCollectionParser parser = new WSTRequestSecurityTokenResponseCollectionParser();
        Assert.assertFalse(parser.supports(new QName("dummy", "dummy")));
        Assert.assertFalse(parser.supports(new QName(WSTrustConstants.BASE_NAMESPACE, "dummy")));
        Assert.assertFalse(parser.supports(new QName("dummy", WSTrustConstants.RSTR_COLLECTION)));
        Assert.assertTrue(parser.supports(new QName(WSTrustConstants.BASE_NAMESPACE, WSTrustConstants.RSTR_COLLECTION)));
    }

    @Test
    public void supportRSTTest() {
        WSTRequestSecurityTokenResponseParser parser = new WSTRequestSecurityTokenResponseParser();
        Assert.assertFalse(parser.supports(new QName("dummy", "dummy")));
        Assert.assertFalse(parser.supports(new QName(WSTrustConstants.BASE_NAMESPACE, "dummy")));
        Assert.assertFalse(parser.supports(new QName("dummy", WSTrustConstants.RST)));
        Assert.assertTrue(parser.supports(new QName(WSTrustConstants.BASE_NAMESPACE, WSTrustConstants.RST)));
    }

    private RequestSecurityTokenResponseCollection readRSTRCollection(String filename) throws ParsingException {
        try {
        @SuppressWarnings("unchecked")
        XMLEventReader reader = getXMLEventReader(filename);
        return (RequestSecurityTokenResponseCollection)new WSTrustParser().parse(reader);
        } catch (IOException ioe) {
            throw new ParsingException("invalid input");
        }
    }

    private RequestSecurityTokenResponse readFirstRSTR(String filename) throws ParsingException {
        return readRSTRCollection(filename).getRequestSecurityTokenResponses().get(0);
    }

    @SuppressWarnings("unchecked")
    private RequestSecurityTokenResponse readFirstRSTRAlterInput(String filename, Function<String, String>... updaters) throws ParsingException, IOException {
        XMLEventReader reader = getXMLEventReader(filename, updaters);
        RequestSecurityTokenResponseCollection res = (RequestSecurityTokenResponseCollection)new WSTrustParser().parse(reader);
        return res.getRequestSecurityTokenResponses().get(0);
    }

    private String replaceXMLTag(String xml, String tagName, String replaceValue) {
        int pos = 0;
        String search = "<"+tagName;
        while (pos>=0 && pos<xml.length()) {
            pos = xml.indexOf(search, pos);
            if (pos>=0) {
                char c = xml.charAt(pos+search.length());
                if ((c>='A' && c<='Z') || (c>='a' && c<='z') || c=='_') {
                    continue;
                }
                int end = xml.indexOf('>', pos);
                String tag = xml.substring(pos, end).trim();
                if (!tag.endsWith("/")) {
                    end = xml.indexOf("</"+tagName, pos);
                    if (end>pos) {
                        end = xml.indexOf('>', end);
                    }
                }
                if (pos<end) {
                    xml = xml.replace(xml.substring(pos, end+1), replaceValue);
                }
                pos = end;
            }
        }
        return xml;
    }

    @Test(expected = ParsingException.class)
    public void emptyInputTest() throws ParsingException {
        readFirstRSTR("/samples/empty.xml");
    }

    @Test(expected = RuntimeException.class)
    public void dummyInputTest() throws ParsingException {
        readFirstRSTR("/samples/dummy.xml");
    }

    @Test
    public void missingContextTest() throws ParsingException {
        RequestSecurityTokenResponse resp = readFirstRSTR("/samples/without-context.xml");
        Assert.assertEquals("", resp.getContext());
    }

    @Test
    public void contextTest() throws ParsingException {
        RequestSecurityTokenResponse resp = readFirstRSTR("/samples/minimum.xml");
        Assert.assertEquals("context-name", resp.getContext());
    }

    @Test
    public void completeRequestTest() throws ParsingException {
        RequestSecurityTokenResponse resp = readFirstRSTR("/samples/complete.xml");
        Assert.assertEquals("complete", resp.getContext());
        Assert.assertEquals("http://uri/request-type", resp.getRequestType().toString());
        Assert.assertEquals("http://uri/token-type", resp.getTokenType().toString());
        Assert.assertEquals("http://uri/key-type", resp.getKeyType().toString());
        Assert.assertEquals("2002-05-30T09:00:00", resp.getLifetime().getCreated().toString());
        Assert.assertEquals("2020-09-30T18:45:00", resp.getLifetime().getExpires().toString());
        UsernameTokenType onBehalfOf = (UsernameTokenType)resp.getOnBehalfOf().getAny().get(0);
        Assert.assertEquals("user-id", onBehalfOf.getId());
        Assert.assertEquals("username", onBehalfOf.getUsername().getValue());
        Assert.assertEquals(256l, resp.getKeySize());
        Assert.assertNotNull(resp.getRequestedTokenCancelled());
        BinarySecretType entropyType = (BinarySecretType)resp.getEntropy().getAny().get(0);
        Assert.assertEquals("TYPE999", entropyType.getType());
        Assert.assertArrayEquals("ABCDEFGH".getBytes(), entropyType.getValue());
        BinarySecretType reqProofToken = (BinarySecretType)resp.getRequestedProofToken().getAny().get(0);
        Assert.assertEquals("TYPE888", reqProofToken.getType());
        Assert.assertArrayEquals("STUVWXYZ".getBytes(), reqProofToken.getValue());
        Object useKey = resp.getUseKey().getAny().get(0);
        Assert.assertTrue(useKey.toString().contains("X509"));
        Object reqSecurityToken = resp.getRequestedSecurityToken().getAny().get(0);
        Assert.assertTrue(reqSecurityToken.toString().contains("AnyContent"));
        Map<javax.xml.namespace.QName, String> attrbs = resp.getRequestedAttachedReference().getSecurityTokenReference().getOtherAttributes();
        Assert.assertTrue(attrbs.values().contains("attached-tktype"));
        attrbs = resp.getRequestedUnattachedReference().getSecurityTokenReference().getOtherAttributes();
        Assert.assertTrue(attrbs.values().contains("unattached-tktype"));
        Assert.assertEquals("status.code", resp.getStatus().getCode());
        Assert.assertEquals("status.reason", resp.getStatus().getReason());
        Assert.assertTrue(resp.getRenewing().isAllow());
        Assert.assertTrue(resp.getRenewing().isOK());
    }

    @SuppressWarnings("unchecked")
    @Test(expected = NullPointerException.class)
    public void noLifeTimeCreated() throws ParsingException, IOException {
        readFirstRSTRAlterInput("/samples/complete.xml", c -> replaceXMLTag(c, "Created", "<NotCreated/>"));
    }

    @SuppressWarnings("unchecked")
    @Test(expected = RuntimeException.class)
    public void noLifeTimeExpires() throws ParsingException, IOException {
        readFirstRSTRAlterInput("/samples/complete.xml", c -> replaceXMLTag(c, "Expires", "<NotExpires/>"));
    }

    @SuppressWarnings("unchecked")
    @Test(expected = ParsingException.class)
    public void requestTypeWithoutText() throws ParsingException, IOException {
        readFirstRSTRAlterInput("/samples/complete.xml", c -> replaceXMLTag(c, "RequestType", "<RequestType/>"));
    }

    @SuppressWarnings("unchecked")
    @Test(expected = ParsingException.class)
    public void tokenTypeWithoutText() throws ParsingException, IOException {
        readFirstRSTRAlterInput("/samples/complete.xml", c -> replaceXMLTag(c, "TokenType", "<TokenType/>"));
    }

    @SuppressWarnings("unchecked")
    @Test(expected = ParsingException.class)
    public void keyTypeWithoutText() throws ParsingException, IOException {
        readFirstRSTRAlterInput("/samples/complete.xml", c -> replaceXMLTag(c, "KeyType", "<KeyType/>"));
    }

    @SuppressWarnings("unchecked")
    @Test(expected = ParsingException.class)
    public void keyTypeInvalidURI() throws ParsingException, IOException{
        readFirstRSTRAlterInput("/samples/complete.xml", c -> replaceXMLTag(c, "KeyType", "<KeyType>}{</KeyType>"));
    }

    @SuppressWarnings("unchecked")
    @Test(expected = ParsingException.class)
    public void keySizeEmpty() throws ParsingException, IOException {
        readFirstRSTRAlterInput("/samples/complete.xml", c -> replaceXMLTag(c, "KeySize", "<KeySize/>"));
    }

    @SuppressWarnings("unchecked")
    @Test(expected = ParsingException.class)
    public void keySizeNotANumber() throws ParsingException, IOException {
        readFirstRSTRAlterInput("/samples/complete.xml", c -> replaceXMLTag(c, "KeySize", "<KeySize>not-a-numbe</KeySize>"));
    }

    @Test(expected = ParsingException.class)
    public void invalidRequestTypeTest() throws ParsingException {
        readFirstRSTR("/samples/invalid-request-type.xml");
    }

    @SuppressWarnings("unchecked")
    @Test
    public void binarySecretWithoutTypeTest() throws Throwable {
        RequestSecurityTokenResponse resp = readFirstRSTRAlterInput("/samples/complete.xml", c -> c.replace(" Type=\"TYPE999\"", ""));
        BinarySecretType entropyType = (BinarySecretType)resp.getEntropy().getAny().get(0);
        Assert.assertNull(entropyType.getType());
        Assert.assertArrayEquals("ABCDEFGH".getBytes(), entropyType.getValue());
    }

    @SuppressWarnings("unchecked")
    @Test(expected = ParsingException.class)
    public void binarySecretWithoutTextTest() throws Throwable {
        readFirstRSTRAlterInput("/samples/complete.xml", c -> replaceXMLTag(c, "BinarySecret", "<BinarySecret></BinarySecret>"));
    }

    @SuppressWarnings("unchecked")
    @Test(expected = ParsingException.class)
    public void noBinarySecretTest() throws Throwable {
        try {
            readFirstRSTRAlterInput("/samples/complete.xml", c -> replaceXMLTag(c, "BinarySecret", "<NotABinarySecret/>"));
        } catch (RuntimeException re) {
            throw re.getCause();
        }
    }

    @SuppressWarnings("unchecked")
    @Test(expected = RuntimeException.class)
    public void invalidUseKeyTypeTest() throws Throwable {
        readFirstRSTRAlterInput("/samples/complete.xml", c -> replaceXMLTag(c, "X509Certificate", "<OtherCertificate/>"));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void useKeyKeyValueTest() throws Throwable {
        RequestSecurityTokenResponse resp = readFirstRSTRAlterInput("/samples/complete.xml", c -> replaceXMLTag(c, "X509Certificate", "<KeyValue/>"));
        Object useKey = resp.getUseKey().getAny().get(0);
        Assert.assertTrue(useKey.toString().contains("KeyValue"));
    }

    @SuppressWarnings("unchecked")
    @Test(expected = ParsingException.class)
    public void requestedProofTokenWithEmptyBinarySecretAlgorithmTest() throws Throwable {
        readFirstRSTRAlterInput("/samples/complete-computed-key.xml",
                c -> replaceXMLTag(c, "RequestedProofToken", "<RequestedProofToken><BinarySecret Type=\"Invalid\"/></RequestedProofToken>"));
    }

    @Test
    public void requestedProofTokenWithComputedKeyTest() throws Throwable {
        RequestSecurityTokenResponse resp = readFirstRSTR("/samples/complete-computed-key.xml");
        ComputedKeyType keyType = (ComputedKeyType)resp.getRequestedProofToken().getAny().get(0);
        Assert.assertEquals("Algorithm", keyType.getAlgorithm());
    }

    @SuppressWarnings("unchecked")
    @Test(expected = ParsingException.class)
    public void requestedProofTokenWithComputedKeyMissingAlgorithmTest() throws Throwable {
        readFirstRSTRAlterInput("/samples/complete-computed-key.xml",
                c -> replaceXMLTag(c, "RequestedProofToken", "<RequestedProofToken><ComputedKey/></RequestedProofToken>"));
    }

    @SuppressWarnings("unchecked")
    @Test(expected = RuntimeException.class)
    public void requestedProofTokenWithUnknownContentTest() throws Throwable {
        readFirstRSTRAlterInput("/samples/complete-computed-key.xml",
                c -> replaceXMLTag(c, "RequestedProofToken", "<RequestedProofToken><UnknownContent/></RequestedProofToken>"));
    }

    @Test(expected = RuntimeException.class)
    public void unknownTagTest() throws Throwable {
        readFirstRSTR("/samples/unknown-tag.xml");
    }

    @SuppressWarnings("unchecked")
    @Test
    public void unknownTagWithAddedSupportTest() throws Throwable {
        RequestSecurityTokenResponse res = readFirstRSTRAlterInput("/samples/unknown-tag.xml", c -> c.replace("UnknownTag", "AdditionalTag"));
        AppliesToUnknownTag appliesTo = (AppliesToUnknownTag)res.getAppliesTo();
        Assert.assertEquals("http://uri/unknown-tag", appliesTo.getValue());
    }

    @SuppressWarnings("unchecked")
    @Test(expected = ParsingException.class)
    public void invalidStatusCodeTest() throws Throwable {
        readFirstRSTRAlterInput("/samples/complete.xml",
                c -> replaceXMLTag(c, "Code", "<Code/>"));
    }

    @SuppressWarnings("unchecked")
    @Test(expected = ParsingException.class)
    public void invalidStatusReasonTest() throws Throwable {
        readFirstRSTRAlterInput("/samples/complete.xml",
                c -> replaceXMLTag(c, "Reason", "<Reason/>"));
    }

    @SuppressWarnings("unchecked")
    @Test(expected = RuntimeException.class)
    public void statusWithUnknownTagTest() throws Throwable {
        readFirstRSTRAlterInput("/samples/complete.xml",
                c -> replaceXMLTag(c, "Reason", "<Unknown/>"));
    }

    @Test(expected = RuntimeException.class)
    @SuppressWarnings("unchecked")
    public void invalidCollectionTest() throws ParsingException, IOException {
        parseFile("/samples/invalid-collection.xml", RequestSecurityTokenResponseCollection.class);
    }
}
