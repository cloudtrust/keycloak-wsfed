package com.quest.keycloak.integration;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.jboss.logging.Logger;

import io.cloudtrust.keycloak.exceptions.CtRuntimeException;

import java.net.URI;
import java.util.Arrays;
import java.util.List;

/** Inspired from the parent project https://github.com/keycloak/keycloak */
public class WsFedClient {

    @FunctionalInterface
    public interface Step {
        HttpUriRequest perform(CloseableHttpClient client, URI currentURI, CloseableHttpResponse currentResponse, HttpClientContext context) throws Exception;
    }

    @FunctionalInterface
    public interface ResultExtractor<T> {
        T extract(CloseableHttpResponse response) throws Exception;
    }

    public static final class DoNotFollowRedirectStep implements Step {

        @Override
        public HttpUriRequest perform(CloseableHttpClient client, URI uri, CloseableHttpResponse response, HttpClientContext context) throws Exception {
            return null;
        }
    }

    public static class RedirectStrategyWithSwitchableFollowRedirect extends LaxRedirectStrategy {

        public boolean redirectable = true;

        @Override
        protected boolean isRedirectable(String method) {
            return redirectable && super.isRedirectable(method);
        }

        public void setRedirectable(boolean redirectable) {
            this.redirectable = redirectable;
        }
    }

    private static final Logger LOG = Logger.getLogger(WsFedClient.class);

    private final HttpClientContext context = HttpClientContext.create();

    private final RedirectStrategyWithSwitchableFollowRedirect strategy = new RedirectStrategyWithSwitchableFollowRedirect();

    public void execute(Step... steps) {
        executeAndTransform(resp -> null, Arrays.asList(steps));
    }

    public void execute(List<Step> steps) {
        executeAndTransform(resp -> null, steps);
    }

    public <T> T executeAndTransform(ResultExtractor<T> resultTransformer, Step... steps) {
        return executeAndTransform(resultTransformer, Arrays.asList(steps));
    }

    public <T> T executeAndTransform(ResultExtractor<T> resultTransformer, List<Step> steps) {
        CloseableHttpResponse currentResponse = null;
        URI currentUri = URI.create("about:blank");
        strategy.setRedirectable(true);

        try (CloseableHttpClient client = createHttpClientBuilderInstance().setRedirectStrategy(strategy).build()) {
            for (int i = 0; i < steps.size(); i ++) {
                Step s = steps.get(i);
                LOG.infof("Running step %d: %s", i, s.getClass());

                CloseableHttpResponse origResponse = currentResponse;

                HttpUriRequest request = s.perform(client, currentUri, origResponse, context);
                if (request == null) {
                    LOG.info("Last step returned no request, continuing with next step.");
                    continue;
                }

                // Setting of follow redirects has to be set before executing the final request of the current step
                if (i < steps.size() - 1 && steps.get(i + 1) instanceof DoNotFollowRedirectStep) {
                    LOG.debugf("Disabling following redirects");
                    strategy.setRedirectable(false);
                    i++;
                } else {
                    strategy.setRedirectable(true);
                }

                LOG.infof("Executing HTTP request to %s", request.getURI());
                currentResponse = client.execute(request, context);

                currentUri = request.getURI();
                List<URI> locations = context.getRedirectLocations();
                if (locations != null && ! locations.isEmpty()) {
                    currentUri = locations.get(locations.size() - 1);
                }

                LOG.infof("Landed to %s", currentUri);

                if (currentResponse != origResponse && origResponse != null) {
                    origResponse.close();
                }
            }

            LOG.info("Going to extract response");

            return resultTransformer.extract(currentResponse);
        } catch (Exception ex) {
            throw new CtRuntimeException(ex);
        }
    }

    public HttpClientContext getContext() {
        return context;
    }

    protected HttpClientBuilder createHttpClientBuilderInstance() {
        return HttpClientBuilder.create();
    }
}
