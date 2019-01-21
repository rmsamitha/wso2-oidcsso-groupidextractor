package org.wso2.sample.oidcsso.gropuid.impl;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
//import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import net.minidev.json.JSONArray;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.NewPostLoginExecutor;
import org.wso2.carbon.apimgt.hostobjects.oidc.internal.AuthenticationToken;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import java.util.HashMap;
import java.util.Map;


public class OIDCSSOGroupIdExtractor implements NewPostLoginExecutor {

    private static final Log log = LogFactory.getLog(OIDCSSOGroupIdExtractor.class);

    public String getGroupingIdentifiers(String loginResponse) {

        String organization = null;
        try {
            AuthenticationToken oidcAuthenticationToken = getAuthenticationToken(loginResponse);
            JWT idToken = JWTParser.parse(oidcAuthenticationToken.getIdTokenValue());
            JWTClaimsSet idClaims = idToken.getJWTClaimsSet();
            Map<String, Object> customClaims = new HashMap<>(idClaims.getClaims());

            if (customClaims.containsKey("organization") && (customClaims.get("organization") != null)){
                organization = (String) customClaims.get("organization");
                String userName = (String) customClaims.get("sub");
                String tenantDomain = MultitenantUtils.getTenantDomain(userName);
                organization = tenantDomain + "/" + organization;
            }
            else {
                log.warn("Id token does not contain the organization claim");
            }
        }
        catch (Exception e){
            log.error("Error occured while trying to get group Identifier from Id token response" , e);
        }

        return organization;
    }

    public String[] getGroupingIdentifierList(String loginResponse) {
        String organization = null;
        String[] groupIdArray = null;
        try {
            AuthenticationToken oidcAuthenticationToken = getAuthenticationToken(loginResponse);
            JWT idToken = JWTParser.parse(oidcAuthenticationToken.getIdTokenValue());
            JWTClaimsSet idClaims = idToken.getJWTClaimsSet();
            Map<String, Object> customClaims = new HashMap<>(idClaims.getClaims());

            if (customClaims.containsKey("organization") && (customClaims.get("organization") != null)) {
                if ((customClaims.get("organization")) instanceof String){
                    organization = (String) customClaims.get("organization");
                }
                // if there are multiple goupids, nimbus returns a JSONArray object
                else if ((customClaims.get("organization")) instanceof JSONArray){
                    String unprocessedOrg;
                    JSONArray jsonArray;
                    jsonArray = (JSONArray) customClaims.get("organization");
                    //convert JSONArray to a string ( ["org-wso2","org-apim"] ) and process for expected format
                    unprocessedOrg = (jsonArray.toJSONString()).substring(1,(jsonArray.toJSONString()).length()-1);
                    organization = unprocessedOrg.replace("\"","");
                }
                else {
                    log.warn("Unable to fetch the organization values from the id token");
                }
            }
            if (organization != null) {
                if (organization.contains(",")){
                    groupIdArray = organization.split(",");
                    for (int i = 0; i < groupIdArray.length; i++) {
                        groupIdArray[i] = groupIdArray[i].trim();
                    }
                }
                else {
                    organization = organization.trim();
                    groupIdArray = new String[]{organization};
                }
            }
            else {
                // If claim is null then returning a empty string
                groupIdArray = new String[]{};
            }
        }
        catch (Exception e) {
            log.error("Error occured while trying to get group Identifier from Id token response", e);
        }
        return groupIdArray;
    }

    private static AuthenticationToken getAuthenticationToken(String jsonTokenResponse)
            throws Exception {

        JsonElement jsonRoot = new JsonParser().parse(jsonTokenResponse);
        if (!jsonRoot.isJsonObject()) {
            throw new Exception("Token Endpoint did not return a JSON object: " + jsonRoot);
        }
        JsonObject tokenResponse = jsonRoot.getAsJsonObject();

        if (tokenResponse.get("error") != null) {

            // Handle error
            String error = tokenResponse.get("error").getAsString();
            log.error("Token Endpoint returned: " + error);
            throw new Exception("Unable to obtain Access Token.  Token Endpoint returned: " + error);

        } else {

            // get out all the token strings
            String accessTokenValue;
            String idTokenValue;
            String refreshTokenValue = null;

            if (tokenResponse.has("access_token")) {
                accessTokenValue = tokenResponse.get("access_token").getAsString();
            } else {
                throw new Exception("Token Endpoint did not return an access_token: " +
                        jsonTokenResponse);
            }

            if (tokenResponse.has("id_token")) {
                idTokenValue = tokenResponse.get("id_token").getAsString();
            } else {
                log.error("Token Endpoint did not return an id_token");
                throw new Exception("Token Endpoint did not return an id_token");
            }

            if (tokenResponse.has("refresh_token")) {
                refreshTokenValue = tokenResponse.get("refresh_token").getAsString();
            }

            return new AuthenticationToken(idTokenValue,
                    accessTokenValue, refreshTokenValue);

        }
    }

}
