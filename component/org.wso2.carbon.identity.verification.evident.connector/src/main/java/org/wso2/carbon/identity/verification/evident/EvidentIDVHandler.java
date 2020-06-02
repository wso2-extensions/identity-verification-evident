/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.verification.evident;

import edu.emory.mathcs.backport.java.util.Arrays;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.identity.verification.evident.constants.EvidentIDVConstants;
import org.wso2.carbon.identity.verification.evident.exception.EvidentAPIException;
import org.wso2.carbon.identity.verification.evident.exception.EvidentIDVHandlerException;
import org.wso2.carbon.identity.verification.evident.internal.EvidentIDVDataHolder;
import org.wso2.carbon.user.core.UserStoreConfigConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static org.wso2.carbon.identity.recovery.IdentityRecoveryConstants.ACCOUNT_LOCKED_CLAIM;
import static org.wso2.carbon.identity.recovery.IdentityRecoveryConstants.ACCOUNT_STATE_CLAIM_URI;
import static org.wso2.carbon.identity.recovery.IdentityRecoveryConstants.ACCOUNT_STATE_UNLOCKED;
import static org.wso2.carbon.identity.recovery.IdentityRecoveryConstants.EMAIL_ADDRESS_CLAIM;
import static org.wso2.carbon.identity.recovery.IdentityRecoveryConstants.SELF_SIGNUP_ROLE;
import static org.wso2.carbon.identity.verification.evident.constants.EvidentIDVConstants.EVIDENT_API_PATH_VERIFY_REQUESTS;
import static org.wso2.carbon.identity.verification.evident.constants.EvidentIDVConstants.EVIDENT_VERIFICATION_ID_CLAIM_URI;
import static org.wso2.carbon.identity.recovery.IdentityRecoveryConstants.PENDING_SELF_REGISTRATION;
import static org.wso2.carbon.user.core.UserCoreConstants.DEFAULT_PROFILE;

/**
 * Handles sending user verification request to Evident and unlocking user account after verification successful.
 */
public class EvidentIDVHandler extends AbstractEventHandler implements IdentityConnectorConfig {

    public static final Log log = LogFactory.getLog(EvidentIDVHandler.class);
    public static final String NOT_ELIGIBLE = "NOT_ELIGIBLE";

    private String key;
    private String secret;
    private String basePath;
    private String emailSummary = "";
    private String emailDescription = "";
    private String userStores;

    public EvidentIDVHandler() {

    }

    public void handleEvent(Event event) throws IdentityEventException {

        Map<String, Object> eventProperties = event.getEventProperties();
        String username = (String) eventProperties.get(IdentityEventConstants.EventProperty.USER_NAME);
        UserStoreManager userStoreManager =
                (UserStoreManager) eventProperties.get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER);

        String tenantDomain = (String) eventProperties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN);

        Property[] identityProperties;
        try {
            identityProperties = EvidentIDVDataHolder.getInstance()
                    .getIdentityGovernanceService().getConfiguration(getPropertyNames(), tenantDomain);
        } catch (IdentityGovernanceException e) {
            throw new IdentityEventException("Error while retrieving account lock handler properties.", e);
        }

        boolean enabled = false;

        for (Property property : identityProperties) {
            if (EvidentIDVConstants.EVIDENT_VERIFICATION_ENABLE.equals(property.getName())) {
                enabled = Boolean.parseBoolean(property.getValue());
            }
            if (EvidentIDVConstants.EVIDENT_API_KEY.equals(property.getName())) {
                key = property.getValue();
            }
            if (EvidentIDVConstants.EVIDENT_API_SECRET.equals(property.getName())) {
                secret = property.getValue();
            }
            if (EvidentIDVConstants.EVIDENT_API_BASE_PATH.equals(property.getName())) {
                basePath = property.getValue();
            }
            if (EvidentIDVConstants.EVIDENT_USER_STORES.equals(property.getName())) {
                userStores = property.getValue();
            }
            if (EvidentIDVConstants.EVIDENT_EMAIL_SUMMARY.equals(property.getName())) {
                emailSummary = property.getValue();
            }
            if (EvidentIDVConstants.EVIDENT_EMAIL_DESCRIPTION.equals(property.getName())) {
                emailDescription = property.getValue();
            }
        }

        if (enabled) {
            // Property validation
            if (StringUtils.isEmpty(key) || StringUtils.isEmpty(secret) || StringUtils.isEmpty(basePath)) {
                log.warn("Evident identity verification is enabled but one or more required parameters are not " +
                        "provided");
                return;
            }

            // Validate user store
            if (StringUtils.isNotEmpty(userStores)) {
                List userStoreList = Arrays.asList(userStores.trim().split("\\s*,\\s*"));
                String currentUserStore = userStoreManager.getRealmConfiguration().getUserStoreProperties().get(
                        UserStoreConfigConstants.DOMAIN_NAME);
                if (!userStoreList.contains(currentUserStore)) {
                    if (log.isDebugEnabled()) {
                        log.debug("User: " + username + " is trying to login. Returning since the user store: " +
                                currentUserStore + " is not engaged in Evident identity verification.");
                    }
                    return;
                }
            }

            if (IdentityEventConstants.Event.PRE_AUTHENTICATION.equals(event.getEventName())) {
                handlePreAuthenticationEvent(username, userStoreManager);
            } else if (IdentityEventConstants.Event.POST_ADD_USER.equals(event.getEventName())) {
                handlePostAddUserEvent(username, userStoreManager, eventProperties);
            }
        }
    }

    private void handlePreAuthenticationEvent(String username, UserStoreManager userStoreManager)
            throws IdentityEventException {

        try {
            String evidentId = getEvidentId(userStoreManager, username);
            if (evidentId != null && !evidentId.equals(NOT_ELIGIBLE)) {
                if (getEvidentVerificationStatus(evidentId)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Evident verification completed for the user: " + username);
                    }
                    // Unlock user account
                    HashMap<String, String> userClaims = new HashMap<>();
                    userClaims.put(ACCOUNT_LOCKED_CLAIM, Boolean.FALSE.toString());
                    userClaims.put(ACCOUNT_STATE_CLAIM_URI, ACCOUNT_STATE_UNLOCKED);
                    userStoreManager.setUserClaimValues(username, userClaims, DEFAULT_PROFILE);
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Evident verification is not yet completed for the user: " + username);
                    }
                }
            } else if (evidentId == null) {
                log.warn("User: " + username + " is eligible for Evident identity verification but the Evident " +
                        "ID couldn't be found.");
            }

        } catch (UserStoreException e) {
            throw new IdentityEventException("Error occurred during PreAuthenticationEvent, while reading claims " +
                    "of the user: " + username, e);
        }
    }

    private void handlePostAddUserEvent(String username, UserStoreManager userStoreManager,
                                        Map<String, Object> eventProperties)
            throws EvidentAPIException, EvidentIDVHandlerException {

        String id;
        try {
            if (isVerifiableUser(eventProperties)) {
                String email = userStoreManager.getUserClaimValue(username, EMAIL_ADDRESS_CLAIM, DEFAULT_PROFILE);
                if (email == null) {
                    log.warn("Evident identity verification is enabled but the email address was not found for " +
                            "the user: " + username);
                    return;
                }
                id = sendEvidentVerificationRequest(email);
            } else {
                // User is not eligible for identity verification.
                if (log.isDebugEnabled()) {
                    log.debug("User " + username + " is not eligible for Evident identity verification");
                }
                return;
            }
        } catch (UserStoreException e) {
            throw new EvidentIDVHandlerException("Error while extracting the email address of the user: " + username, e);
        }

        try {
            if (id != null) {
                HashMap<String, String> userClaims = new HashMap<>();
                userClaims.put(ACCOUNT_LOCKED_CLAIM, Boolean.TRUE.toString());
                userClaims.put(EVIDENT_VERIFICATION_ID_CLAIM_URI, id);
                userStoreManager.setUserClaimValues(username, userClaims, DEFAULT_PROFILE);
            } else {
                throw new EvidentIDVHandlerException("Evident verification request ID was null for the user: " + username);
            }
        } catch (UserStoreException e) {
            throw new EvidentIDVHandlerException("Error while setting the evident verification request ID of the " +
                    "user: " + username, e);
        }
    }

    /**
     * Evident identity verification is only supported for self sign up users. This method returns true if the
     * eventProperties contained self sign up role.
     *
     * @param eventProperties Event properties.
     * @return True if the user is verifiable, False otherwise.
     */
    private boolean isVerifiableUser(Map<String, Object> eventProperties) {

        String[] roleList = (String[]) eventProperties.get(IdentityEventConstants.EventProperty.ROLE_LIST);
        return Arrays.asList(roleList).contains(SELF_SIGNUP_ROLE);
    }

    /**
     * Extract the Evident ID of the given user, if the user is in a verifiable state. i.e. the account should be
     * locked and the account state claim should represent self sign up.
     *
     * @param userStoreManager User Store Manager
     * @param username         User name of the user
     * @return True if eligible, False otherwise.
     * @throws UserStoreException On error
     */
    private String getEvidentId(UserStoreManager userStoreManager, String username) throws UserStoreException {

        Map<String, String> claimValues = userStoreManager.getUserClaimValues(username,
                new String[]{
                        ACCOUNT_LOCKED_CLAIM,
                        ACCOUNT_STATE_CLAIM_URI,
                        EVIDENT_VERIFICATION_ID_CLAIM_URI
                }, DEFAULT_PROFILE);

        String accountLocked = claimValues.get(ACCOUNT_LOCKED_CLAIM);
        String accountState = claimValues.get(ACCOUNT_STATE_CLAIM_URI);

        if (accountLocked == null || !accountLocked.equals(Boolean.TRUE.toString()) ||
                accountState == null || !accountState.equals(PENDING_SELF_REGISTRATION)) {
            return NOT_ELIGIBLE;
        } else {
            return claimValues.get(EVIDENT_VERIFICATION_ID_CLAIM_URI);
        }
    }

    /**
     * Initiate evident verify request for the given user.
     *
     * @param email Email of the user.
     * @return Verify Id of the request
     * @throws EvidentAPIException if any errors occurred.
     */
    private String sendEvidentVerificationRequest(String email) throws EvidentAPIException {

        String urlPath = basePath + "/" + EVIDENT_API_PATH_VERIFY_REQUESTS;
        HttpURLConnection con = null;
        String response;
        try {
            URL url = new URL(urlPath);
            con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("POST");
            con.setDoOutput(true);
            con.setRequestProperty("Content-Type", "application/json");
            con.setRequestProperty("Authorization", "Basic " + getEncodedCredential());

            // TODO: 2020-05-30 Should allow to customize from UI
            String data = "{\n" +
                    "\t\"email\": \"" + email + "\",\n" +
                    "\t\"summary\": \"" + emailSummary + "\",\n" +
                    "\t\"description\": \"" + emailDescription + "\"," +
                    "\n" +
                    "\t\"userAuthenticationType\": \"blindtrust\",\n" +
                    "\t\"attributesRequested\": [\n" +
                    "\t\t{\n" +
                    "\t\t\t\"attributeType\": \"identity_assurance.document_verification.americas.us.drivers_license" +
                    ".verification_status\"\n" +
                    "\t\t},\n" +
                    "\t\t{\n" +
                    "\t\t\t\"attributeType\": \"core.fullname\"\n" +
                    "\t\t}\n" +
                    "\t]\n" +
                    "}";
            OutputStream os = con.getOutputStream();
            os.write(data.getBytes(StandardCharsets.UTF_8));
            os.close();

            if (log.isDebugEnabled()) {
                log.debug("Sending POST request to the path: " + urlPath);
            }

            con.connect();

            response = getResponse(con);

            int status = con.getResponseCode();
            if (status != 200) {
                throw new EvidentAPIException("Evident API error. Error code: " + con.getResponseCode() + " Error " +
                        "message: " + response);
            }

        } catch (IOException e) {
            throw new EvidentAPIException("Error while sending Evident verify request. ", e);
        } finally {
            if (con != null) {
                con.disconnect();
            }
        }

        JSONObject object = new JSONObject(response);
        String id = object.get("id").toString();

        if (log.isDebugEnabled()) {
            String userIdentityToken = object.get("userIdentityToken").toString();
            log.debug("Evident verification request sent for the user with email: " + email);
            log.debug("Evident verification request id: " + id);
            log.debug("Evident verification request user id token: " + userIdentityToken);
        }

        return id;
    }

    /**
     * Check whether the verification is completed for the given verify ID.
     *
     * @param verifyId Verify request ID.
     * @return True if verification completed, False otherwise.
     * @throws EvidentAPIException If any errors occurred.
     */
    private boolean getEvidentVerificationStatus(String verifyId) throws EvidentAPIException {

        String urlPath = basePath + "/" + EVIDENT_API_PATH_VERIFY_REQUESTS + "/" + verifyId;
        HttpURLConnection con = null;
        String response;
        try {
            URL url = new URL(urlPath);
            con = (HttpURLConnection) url.openConnection();
            con.setDoOutput(true);
            con.setRequestProperty("Content-Type", "application/json");
            con.setRequestProperty("Authorization", "Basic " + getEncodedCredential());

            if (log.isDebugEnabled()) {
                log.debug("Sending GET request to the path: " + urlPath);
            }

            con.connect();

            response = getResponse(con);

            int status = con.getResponseCode();
            if (status != 200) {
                throw new EvidentAPIException("Error status returned from the Evident API. Error code: " +
                        con.getResponseCode() + " Error message: " + response);
            }

        } catch (IOException e) {
            throw new EvidentAPIException("Error occurred while sending Evident API request. ", e);
        } finally {
            if (con != null) {
                con.disconnect();
            }
        }

        JSONObject object = new JSONObject(response);
        return isUserVerified(object);
    }

    /**
     * Checks whether the required verifications are completed.
     *
     * @param responseJSON API Response.
     * @return True if checks are passed.
     */
    private boolean isUserVerified(JSONObject responseJSON) {

        // TODO: 2020-05-30 Should be allowed to customize from UI
        JSONArray attributes = responseJSON.getJSONArray("attributes");
        for (int i = 0; i < attributes.length(); i++) {
            JSONObject attribute = attributes.getJSONObject(i);
            String type = attribute.getString("type");
            if (type.equals("identity_assurance.document_verification.americas.us.drivers_license" +
                    ".verification_status") && attribute.has("values")) {
                JSONArray values = attribute.getJSONArray("values");
                return values.getString(0).equals("Valid");
            }
        }
        return false;
    }

    /**
     * Extract String response body from HttpURLConnection
     *
     * @param con HttpURLConnection.
     * @return Response body as a string.
     * @throws IOException If errors occurred.
     */
    private String getResponse(HttpURLConnection con) throws IOException {

        BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) {
            sb.append(line).append("\n");
        }
        br.close();
        return sb.toString();
    }

    /**
     * Read API credentials and return base64 encoded value.
     */
    private String getEncodedCredential() {

        return Base64.getEncoder().encodeToString((key + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public String getName() {

        return "evidentEventHandler";
    }

    @Override
    public String getFriendlyName() {

        return "Evident Identity Verification";
    }

    @Override
    public String getCategory() {

        return "Account Management Policies";
    }

    @Override
    public String getSubCategory() {

        return "DEFAULT";
    }

    @Override
    public int getOrder() {

        return 50;
    }

    @Override
    public Map<String, String> getPropertyNameMapping() {

        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(EvidentIDVConstants.EVIDENT_VERIFICATION_ENABLE, "Enable Identity Verification");
        nameMapping.put(EvidentIDVConstants.EVIDENT_API_KEY, "API Key");
        nameMapping.put(EvidentIDVConstants.EVIDENT_API_SECRET, "API Secret");
        nameMapping.put(EvidentIDVConstants.EVIDENT_API_BASE_PATH, "API Base Path");
        nameMapping.put(EvidentIDVConstants.EVIDENT_EMAIL_SUMMARY, "Verification Email Summary");
        nameMapping.put(EvidentIDVConstants.EVIDENT_EMAIL_DESCRIPTION, "Verification Email Description");
        nameMapping.put(EvidentIDVConstants.EVIDENT_USER_STORES, "Verify Enabled User Stores");
        return nameMapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {

        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(EvidentIDVConstants.EVIDENT_VERIFICATION_ENABLE, "Verify the identities of self sign-up " +
                "users with Evident. Note: User Self Registration needs to be enabled.");
        nameMapping.put(EvidentIDVConstants.EVIDENT_API_KEY, "API key obtained from Evident.");
        nameMapping.put(EvidentIDVConstants.EVIDENT_API_SECRET, "API secret obtained from Evident.");
        nameMapping.put(EvidentIDVConstants.EVIDENT_API_BASE_PATH, "API base path of the Evident. Ex: " +
                "https://verify.api.demo.evidentid.com");
        nameMapping.put(EvidentIDVConstants.EVIDENT_EMAIL_SUMMARY, "This will appear in the verification request " +
                "email along with the text: [Action Required to Complete Your <Summary>].");
        nameMapping.put(EvidentIDVConstants.EVIDENT_EMAIL_DESCRIPTION, "This will appear in the verification request " +
                "email as the description.");
        nameMapping.put(EvidentIDVConstants.EVIDENT_USER_STORES, "Verification will only be engaged for the user " +
                "stores added here. Comma separated multiple values accepted. If kept empty, verification will be " +
                "applied to all user stores.");

        return nameMapping;
    }

    @Override
    public String[] getPropertyNames() {

        List<String> properties = new ArrayList<>();
        properties.add(EvidentIDVConstants.EVIDENT_VERIFICATION_ENABLE);
        properties.add(EvidentIDVConstants.EVIDENT_API_BASE_PATH);
        properties.add(EvidentIDVConstants.EVIDENT_API_KEY);
        properties.add(EvidentIDVConstants.EVIDENT_API_SECRET);
        properties.add(EvidentIDVConstants.EVIDENT_EMAIL_SUMMARY);
        properties.add(EvidentIDVConstants.EVIDENT_EMAIL_DESCRIPTION);
        properties.add(EvidentIDVConstants.EVIDENT_USER_STORES);
        return properties.toArray(new String[0]);
    }

    @Override
    public Properties getDefaultPropertyValues(String s) {

        Map<String, String> defaultProperties = new HashMap<>();
        defaultProperties.put(EvidentIDVConstants.EVIDENT_VERIFICATION_ENABLE, Boolean.FALSE.toString());
        defaultProperties.put(EvidentIDVConstants.EVIDENT_API_BASE_PATH, "https://verify.api.demo.evidentid.com");
        defaultProperties.put(EvidentIDVConstants.EVIDENT_API_KEY, "");
        defaultProperties.put(EvidentIDVConstants.EVIDENT_API_SECRET, "");
        defaultProperties.put(EvidentIDVConstants.EVIDENT_EMAIL_SUMMARY, "Identity Verification");
        defaultProperties.put(EvidentIDVConstants.EVIDENT_EMAIL_DESCRIPTION, "WSO2 needs to verify your US driver's " +
                "license in order to accept you as a new user.");
        defaultProperties.put(EvidentIDVConstants.EVIDENT_USER_STORES, UserStoreConfigConstants.PRIMARY);
        Properties properties = new Properties();
        properties.putAll(defaultProperties);
        return properties;
    }

    @Override
    public Map<String, String> getDefaultPropertyValues(String[] strings, String s) {

        return null;
    }
}
