package com.group.ykb.samlidp.saml;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.*;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.*;
import org.opensaml.xml.signature.impl.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.util.UUID;

public class SamlResponseGenerator {

    static {
        try {
            DefaultBootstrap.bootstrap();
        } catch (Exception e) {
            throw new RuntimeException("Error initializing OpenSAML", e);
        }
    }

    public WrappedSamlResponse generateSAMLResponse(String samlRequestStr) throws Exception {
        AuthnRequestImpl samlRequest = unmarshalSamlRequest(samlRequestStr);
        String spIssuer = samlRequest.getIssuer().getValue();
        String assertionConsumerServiceURL = samlRequest.getAssertionConsumerServiceURL();
        String samlRequestId = samlRequest.getID();

        PrivateKey privateKey = PemKeyLoader.get().getPrivateKey();
        java.security.PublicKey publicKey = PemKeyLoader.get().getPublicKey();

        ResponseBuilder responseBuilder = new ResponseBuilder();
        Response response = responseBuilder.buildObject();

        response.setID(UUID.randomUUID().toString());
        response.setIssueInstant(new org.joda.time.DateTime());
        response.setDestination(assertionConsumerServiceURL);
        response.setIssuer(createIssuer(IdpConfig.ISSUER));
        response.setInResponseTo(samlRequestId);

        Credential credential = createCredential(privateKey, publicKey);
        Signature signature = createSignature(credential);
        response.setSignature(signature);

        response.setStatus(createStatus());

        response.getAssertions().add(createAssertion(spIssuer, assertionConsumerServiceURL, samlRequestId));

        MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
        Marshaller marshaller = marshallerFactory.getMarshaller(response);
        Element responseElement = marshaller.marshall(response);

        Signer.signObject(signature);

        StringWriter writer = new StringWriter();
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.transform(new DOMSource(responseElement), new StreamResult(writer));

        return new WrappedSamlResponse(writer.toString(), assertionConsumerServiceURL);
    }

    private Credential createCredential(PrivateKey privateKey, java.security.PublicKey publicKey) {
        BasicX509Credential credential = new BasicX509Credential();
        credential.setPrivateKey(privateKey);
        credential.setPublicKey(publicKey);
        return credential;
    }

    private Signature createSignature(Credential credential) {
        SignatureBuilder signatureBuilder = new SignatureBuilder();
        Signature signature = signatureBuilder.buildObject();

        signature.setSigningCredential(credential);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        return signature;
    }

    private Issuer createIssuer(String issuerValue) {
        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(issuerValue);
        return issuer;
    }

    private Status createStatus() {
        StatusBuilder statusBuilder = new StatusBuilder();
        Status status = statusBuilder.buildObject();

        StatusCodeBuilder statusCodeBuilder = new StatusCodeBuilder();
        StatusCode statusCode = statusCodeBuilder.buildObject();
        statusCode.setValue(StatusCode.SUCCESS_URI);
        status.setStatusCode(statusCode);
        return status;
    }

    private Assertion createAssertion(String spIssuer, String assertionConsumerServiceURL, String samlRequestId) {
        AssertionBuilder assertionBuilder = new AssertionBuilder();
        Assertion assertion = assertionBuilder.buildObject();

        assertion.setID(UUID.randomUUID().toString());
        assertion.setIssueInstant(new DateTime());
        assertion.setVersion(SAMLVersion.VERSION_20);

        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(IdpConfig.ISSUER);
        assertion.setIssuer(issuer);

        assertion.setSubject(createSubject(spIssuer, assertionConsumerServiceURL, samlRequestId));

        assertion.setConditions(createConditions(spIssuer));

        assertion.getAuthnStatements().add(createAuthnStatement());

        return assertion;
    }

    private Subject createSubject(String spIssuer, String assertionConsumerServiceURL, String samlRequestId) {
        SubjectBuilder subjectBuilder = new SubjectBuilder();
        Subject subject = subjectBuilder.buildObject();

        NameIDBuilder nameIDBuilder = new NameIDBuilder();
        NameID nameID = nameIDBuilder.buildObject();
        nameID.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
        nameID.setValue(IdpConfig.getNameId(spIssuer));
        subject.setNameID(nameID);

        SubjectConfirmationBuilder subjectConfirmationBuilder = new SubjectConfirmationBuilder();
        SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();
        subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");

        SubjectConfirmationDataBuilder subjectConfirmationDataBuilder = new SubjectConfirmationDataBuilder();
        SubjectConfirmationData subjectConfirmationData = subjectConfirmationDataBuilder.buildObject();
        subjectConfirmationData.setInResponseTo(samlRequestId);
        subjectConfirmationData.setNotOnOrAfter(new DateTime().plusMinutes(15));
        subjectConfirmationData.setRecipient(assertionConsumerServiceURL);

        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        subject.getSubjectConfirmations().add(subjectConfirmation);

        return subject;
    }

    private Conditions createConditions(String spIssuer) {
        ConditionsBuilder conditionsBuilder = new ConditionsBuilder();
        Conditions conditions = conditionsBuilder.buildObject();

        conditions.setNotBefore(new DateTime().minusMinutes(5));
        conditions.setNotOnOrAfter(new DateTime().plusMinutes(10));

        AudienceRestrictionBuilder audienceRestrictionBuilder = new AudienceRestrictionBuilder();
        AudienceRestriction audienceRestriction = audienceRestrictionBuilder.buildObject();

        AudienceBuilder audienceBuilder = new AudienceBuilder();
        Audience audience = audienceBuilder.buildObject();
        audience.setAudienceURI(spIssuer);

        audienceRestriction.getAudiences().add(audience);
        conditions.getAudienceRestrictions().add(audienceRestriction);

        return conditions;
    }

    private AuthnStatement createAuthnStatement() {
        AuthnStatementBuilder authnStatementBuilder = new AuthnStatementBuilder();
        AuthnStatement authnStatement = authnStatementBuilder.buildObject();
        authnStatement.setAuthnInstant(new DateTime());

        AuthnContextBuilder authnContextBuilder = new AuthnContextBuilder();
        AuthnContext authnContext = authnContextBuilder.buildObject();

        AuthnContextClassRefBuilder authnContextClassRefBuilder = new AuthnContextClassRefBuilder();
        AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject();
        authnContextClassRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");

        authnContext.setAuthnContextClassRef(authnContextClassRef);
        authnStatement.setAuthnContext(authnContext);

        return authnStatement;
    }

    public AuthnRequestImpl unmarshalSamlRequest(String samlRequestString) throws Exception {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        Document document = documentBuilder.parse(new ByteArrayInputStream(samlRequestString.getBytes()));
        Element element = document.getDocumentElement();
        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
        return (AuthnRequestImpl) unmarshaller.unmarshall(element);
    }
}