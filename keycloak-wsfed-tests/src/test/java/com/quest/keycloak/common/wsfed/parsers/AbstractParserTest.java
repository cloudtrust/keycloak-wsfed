package com.quest.keycloak.common.wsfed.parsers;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.function.Function;

import javax.xml.stream.XMLEventReader;

import org.picketlink.common.exceptions.ParsingException;
import org.picketlink.common.util.StaxParserUtil;

public abstract class AbstractParserTest {
    @SuppressWarnings({ "unchecked" })
    protected <T> T parseFile(String filename, Class<T> clazz, Function<String, String>... updaters) throws ParsingException, IOException {
        return clazz.cast(new WSTrustParser().parse(getXMLEventReader(filename, updaters)));
    }

    protected InputStream getInputStream(String filename) {
        InputStream stream = WSTRequestSecurityTokenResponseCollectionParserTest.class.getResourceAsStream(filename);
        if (stream==null) {
            try {
                stream = new FileInputStream("src/test/resources"+filename);
            } catch (IOException e) {
                // Ignore
            }
        }
        return stream;
    }

    @SuppressWarnings("unchecked")
    protected XMLEventReader getXMLEventReader(String filename, Function<String, String>... updaters) throws IOException {
        if (updaters==null) {
            return StaxParserUtil.getXMLEventReader(getInputStream(filename));
        }
        String xml;
        try (InputStream input = getInputStream(filename)) {
            byte[] content = new byte[input.available()];
            input.read(content);
            xml = new String(content, StandardCharsets.UTF_8);
        }
        if (updaters!=null) {
            for(Function<String, String> updater : updaters) {
                xml = updater.apply(xml);
            }
        }
        try (InputStream stream = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8))) {
            return StaxParserUtil.getXMLEventReader(stream);
        }
    }
}
