package com.group.ykb.samlidp.servlet;

import org.springframework.web.servlet.DispatcherServlet;
import com.group.ykb.samlidp.saml.SamlResponseGenerator;
import com.group.ykb.samlidp.saml.WrappedSamlResponse;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SamlServlet extends DispatcherServlet {

    private final SamlResponseGenerator samlFactory = new SamlResponseGenerator();

    @Override
    public void service(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if(!"/idp/login".equals(request.getRequestURI()))
            throw new RuntimeException("URI not recognized");

        String samlRequest = request.getParameter("SAMLRequest");
        if(samlRequest==null)
            throw new IllegalArgumentException("SAMLRequest cannot be null");
        samlRequest = decodeBase64(samlRequest);
        WrappedSamlResponse wrappedSamlResponse;
        try {
            wrappedSamlResponse = samlFactory.generateSAMLResponse(samlRequest);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        StringBuilder endpoint = new StringBuilder(wrappedSamlResponse.getAssertionConsumerServiceUrl())
                .append("?SAMLResponse=")
                .append(encodeUrl(encodeBase64(wrappedSamlResponse.getSamlResponse())));
        response.sendRedirect(endpoint.toString());
    }

    private String encodeBase64(String input) {
        return Base64.getEncoder().encodeToString(input.getBytes(StandardCharsets.UTF_8));
    }

    private String decodeBase64(String input) {
        return new String(Base64.getDecoder().decode(input));
    }

    private String encodeUrl(String input) throws UnsupportedEncodingException {
        return URLEncoder.encode(input, StandardCharsets.UTF_8.toString());
    }

}
