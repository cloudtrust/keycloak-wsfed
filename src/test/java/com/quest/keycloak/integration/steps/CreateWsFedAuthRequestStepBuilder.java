package com.quest.keycloak.integration.steps;

import com.quest.keycloak.common.wsfed.WSFedConstants;
import com.quest.keycloak.integration.WsFedClientBuilder;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;

import java.net.URI;

/** Inspired from the parent project https://github.com/keycloak/keycloak */
public class CreateWsFedAuthRequestStepBuilder extends AbstractStepBuilder {

    private final URI authServerWsFedUrl;
    private final String consumerUrl;
    private final String clientId;
    private final String context;

    private WsFedClientBuilder clientBuilder;

    public CreateWsFedAuthRequestStepBuilder(WsFedClientBuilder clientBuilder, URI authServerWsFedUrl, String consumerUrl, String clientId, String context) {
        super(clientBuilder);
        this.clientBuilder = clientBuilder;
        this.authServerWsFedUrl = authServerWsFedUrl;
        this.consumerUrl = consumerUrl;
        this.clientId = clientId;
        this.context = context;
    }


    @Override
    public HttpUriRequest perform(CloseableHttpClient client, URI currentURI, CloseableHttpResponse currentResponse, HttpClientContext httpClientContext) throws Exception {
        URIBuilder builder = new URIBuilder(authServerWsFedUrl);
        builder.setParameter("wa", WSFedConstants.WSFED_SIGNIN_ACTION)
                .setParameter("wtrealm", clientId)
                .setParameter("wreply", consumerUrl)
                .setParameter("wctx", context);

        return new HttpGet(builder.build());
    }

}
