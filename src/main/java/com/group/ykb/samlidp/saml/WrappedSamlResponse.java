package com.group.ykb.samlidp.saml;

public class WrappedSamlResponse {
    private final String samlResponse;
    private final String assertionConsumerServiceUrl;

    public WrappedSamlResponse(String samlResponse, String assertionConsumerServiceUrl) {
        this.samlResponse = samlResponse;
        this.assertionConsumerServiceUrl = assertionConsumerServiceUrl;
    }

    public String getSamlResponse() {
        return samlResponse;
    }

    public String getAssertionConsumerServiceUrl() {
        return assertionConsumerServiceUrl;
    }
}
