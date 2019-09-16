package com.quest.keycloak.integration;

import com.quest.keycloak.protocol.wsfed.AbstractWSFedLoginProtocolFactory;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Before;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.resource.RealmResourceProviderFactory;
import org.keycloak.test.FluentTestsHelper;
import org.keycloak.testsuite.AbstractKeycloakTest;

import java.io.File;
import java.net.URI;
import java.util.List;

import static org.keycloak.representations.idm.CredentialRepresentation.PASSWORD;
import static org.keycloak.testsuite.admin.Users.setPasswordFor;
import static org.keycloak.testsuite.utils.io.IOUtil.loadRealm;

public abstract class AbstractWsFedAuthTest extends AbstractKeycloakTest {
    protected static final String KEYCLOAK_URL = getKeycloakUrl();
    protected UserRepresentation bburkeUser;

    private static String getKeycloakUrl() {
        String url = FluentTestsHelper.DEFAULT_KEYCLOAK_URL;
        try {
            URI uri = new URI(FluentTestsHelper.DEFAULT_KEYCLOAK_URL);
            url = url.replace(String.valueOf(uri.getPort()), System.getProperty("auth.server.http.port", "8080"));
        } catch (Exception e) {
            // Ignore
        }
        return url;
    }

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        testRealms.add(loadRealm("/realm-test-wsfed.json"));
    }

    @Deployment
    public static WebArchive deploy() {
        return ShrinkWrap.create(WebArchive.class, "run-on-server-classes.war")
                .addPackages(true, "com.quest.keycloak")
                .addAsManifestResource(new File("src/test/resources", "manifest.xml"))
                .addAsServiceProvider(RealmResourceProviderFactory.class, AbstractWSFedLoginProtocolFactory.class);
    }

    @Before
    public void beforeAuthTest() {
        bburkeUser = createUserRepresentation("bburke", "bburke@redhat.com", "Bill", "Burke", true);
        setPasswordFor(bburkeUser, PASSWORD);
    }

    public static UserRepresentation createUserRepresentation(String username, String email, String firstName, String lastName, boolean enabled) {
        UserRepresentation user = new UserRepresentation();
        user.setUsername(username);
        user.setEmail(email);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setEnabled(enabled);
        return user;
    }
}
