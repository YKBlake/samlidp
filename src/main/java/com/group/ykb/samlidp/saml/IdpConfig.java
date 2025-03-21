package com.group.ykb.samlidp.saml;

import java.util.HashMap;
import java.util.Map;

public class IdpConfig {

    public static final String ISSUER = "{issuer_url}";
    private static final Map<String, String> ISSUER_USERNAME = new HashMap<>();

    static {
        ISSUER_USERNAME.put("default", "username");
    }

    public static String getNameId(String issuer) {
        String nameId = ISSUER_USERNAME.get(issuer);
        if(nameId==null)
            nameId = ISSUER_USERNAME.get("default");
        return nameId;
    }

}
