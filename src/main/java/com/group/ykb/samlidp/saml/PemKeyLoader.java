package com.group.ykb.samlidp.saml;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class PemKeyLoader {

    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    private static PemKeyLoader keyLoader;

    public static PemKeyLoader get() {
        if (keyLoader == null)
            keyLoader = new PemKeyLoader();
        return keyLoader;
    }

    private PemKeyLoader() {
        try {
            privateKey = loadPrivateKey();
            publicKey = loadPublicKey();
        } catch(Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private PrivateKey loadPrivateKey() throws Exception {
        String privateKey;
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream("credentials/private_key.pem")) {
            if(inputStream==null)
                throw new Exception("Private key file not found");
            try (Scanner scanner = new Scanner(inputStream, StandardCharsets.UTF_8.name())) {
                privateKey = scanner.useDelimiter("\\A").next();
            }
        }
        privateKey = privateKey
                .replace("-----BEGIN PRIVATE KEY-----","")
                .replace("-----END PRIVATE KEY-----","")
                .replaceAll("\n","")
                .replaceAll("\r","")
                .replaceAll(" ","");
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    private PublicKey loadPublicKey() throws Exception {
        String publicKey;
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream("credentials/public_key.pem")) {
            if(inputStream==null)
                throw new Exception("Public key file not found");
            try (Scanner scanner = new Scanner(inputStream, StandardCharsets.UTF_8.name())) {
                publicKey = scanner.useDelimiter("\\A").next();
            }
        }
        publicKey = publicKey
                .replace("-----BEGIN PUBLIC KEY-----","")
                .replace("-----END PUBLIC KEY-----","")
                .replaceAll("\n","")
                .replaceAll("\r","")
                .replaceAll(" ","");
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    public PrivateKey getPrivateKey() {
        if(privateKey==null)
            throw new RuntimeException("Private key file not found");
        return privateKey;
    }

    public PublicKey getPublicKey() {
        if(publicKey==null)
            throw new RuntimeException("Private key file not found");
        return publicKey;
    }

}
