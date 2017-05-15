/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.testsuite.oidc;

import java.util.Map;

import org.jboss.arquillian.graphene.page.Page;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.keycloak.events.Details;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.UserAttributeMapper;
import org.keycloak.protocol.oidc.utils.OIDCResponseType;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testsuite.AbstractTestRealmKeycloakTest;
import org.keycloak.testsuite.Assert;
import org.keycloak.testsuite.AssertEvents;
import org.keycloak.testsuite.pages.AppPage;
import org.keycloak.testsuite.pages.LoginPage;
import org.keycloak.testsuite.util.OAuthClient;

public class OIDCUserAttributeMapperTest extends AbstractTestRealmKeycloakTest {

    @Rule
    public AssertEvents events = new AssertEvents(this);

    @Page
    protected AppPage appPage;

    @Page
    protected LoginPage loginPage;

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {
    }

    @Before
    public void clientConfiguration() {
        oauth.clientId("test-app");
        oauth.responseType(OIDCResponseType.CODE);
    }

    AccessToken login() {
        oauth.nonce("abcdef123456");
        driver.navigate().to(oauth.getLoginFormUrl());
        loginPage.assertCurrent();
        loginPage.login("test-user@localhost", "password");
        Assert.assertEquals(AppPage.RequestType.AUTH_RESPONSE, appPage.getRequestType());

        events.expectLogin().detail(Details.USERNAME, "test-user@localhost").assertEvent();

        String code = new OAuthClient.AuthorizationEndpointResponse(oauth).getCode();
        OAuthClient.AccessTokenResponse response = oauth.doAccessTokenRequest(code, "password");

        Assert.assertEquals(200, response.getStatusCode());
        AccessToken accessToken = oauth.verifyToken(response.getAccessToken());
        return accessToken;
    }

    void addUserAttributeWithMapper(String id, String value) {
        System.out.println("Begin addUserAttributeWithMapper()");
        System.out.flush();
        // Create a user attribute
        UserRepresentation user = findUser("test-user@localhost");
        user.singleAttribute(id, value);
        // Apply new user attribute
        updateUser(user);

        System.out.println("Middle addUserAttributeWithMapper()");
        System.out.flush();
        // Create a protocol mapper for the user attribute
        ProtocolMapperRepresentation protocolMapper = new ProtocolMapperRepresentation();
        Map<String, String> protocolMapperConfig = protocolMapper.getConfig();
        protocolMapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        protocolMapper.setName(id);
        protocolMapperConfig.put(ProtocolMapperUtils.USER_ATTRIBUTE, id);
        protocolMapperConfig.put(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, id);
        protocolMapper.setProtocolMapper(UserAttributeMapper.PROVIDER_ID);
        protocolMapperConfig.put(OIDCAttributeMapperHelper.JSON_TYPE, "String");
        protocolMapperConfig.put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true");
        protocolMapperConfig.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true");
        protocolMapperConfig.put(ProtocolMapperUtils.MULTIVALUED, "false");
        // Apply new protocol mapper
        ClientRepresentation client = testRealm().clients().findByClientId("test-app").get(0);
        testRealm().clients().get(client.getId()).getProtocolMappers().createMapper(protocolMapper);
        System.out.println("End addUserAttributeWithMapper()");
        System.out.flush();
    }

    @Test
    public void fullStringAttribute() {
        addUserAttributeWithMapper("fullStringAttribute", "fine greetings to thee");
        AccessToken accessToken = login();

        Map<String, Object> claims = accessToken.getOtherClaims();
        Object attributeValue = claims.get("fullStringAttribute");
        Assert.assertNotNull(attributeValue);
        Assert.assertEquals(attributeValue, "fine greetings to thee");
    }

    @Test
    public void nullStringAttribute() {
        addUserAttributeWithMapper("nullStringAttribute", null);
        AccessToken accessToken = login();

        Map<String, Object> claims = accessToken.getOtherClaims();
        Assert.assertFalse(claims.containsKey("nullStringAttribute"));
        Object attributeValue = claims.get("nullStringAttribute");
        Assert.assertNull(attributeValue);
    }
}
