package org.wso2.custom.authenticator.local;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
//import org.apache.tomcat.websocket.BasicAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.custom.authenticator.local.internal.BasicCustomAuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.model.IdentityErrorMsgContext;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticator;
import org.wso2.carbon.identity.application.authenticator.basicauth.internal.BasicAuthenticatorServiceComponent;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.UUID;

public class BasicCustomAuthenticator extends BasicAuthenticator {


    private static final long serialVersionUID = 181966453941602976L;
    private static final String PASSWORD_PROPERTY = "PASSWORD_PROPERTY";
    private static final String PASSWORD_RESET_ENDPOINT = "accountrecoveryendpoint/confirmrecovery.do?";
    private static final Log log = LogFactory.getLog(BasicCustomAuthenticator.class);
    private static String RE_CAPTCHA_USER_DOMAIN = "user-domain-recaptcha";
    private static final String SINGLE_SYSTEM_USER_IDENTIFIER_CLAIM = "http://wso2.org/claims/organization";


    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        String username = request.getParameter(BasicCustomAuthenticatorConstants.USER_NAME);
        String password = request.getParameter(BasicCustomAuthenticatorConstants.PASSWORD);
        String uuidClient = request.getParameter(BasicCustomAuthenticatorConstants.SUUID);


        Map<String, Object> authProperties = context.getProperties();
        if (authProperties == null) {
            authProperties = new HashMap<>();
            context.setProperties(authProperties);
        }

        Map<String, String> runtimeParams = getRuntimeParams(context);
        if (runtimeParams != null) {
            String usernameFromContext = runtimeParams.get(FrameworkConstants.JSAttributes.JS_OPTIONS_USERNAME);
            if (usernameFromContext != null && !usernameFromContext.equals(username)) {
                if (log.isDebugEnabled()) {
                    log.debug("Username set for identifier first login: " + usernameFromContext + " and username " +
                            "submitted from login page" + username + " does not match.");
                }
                throw new InvalidCredentialsException("Credential mismatch.");
            }
        }

        authProperties.put(PASSWORD_PROPERTY, password);

        boolean isAuthenticated;
        UserStoreManager userStoreManager;
        // Reset RE_CAPTCHA_USER_DOMAIN thread local variable before the authentication
        IdentityUtil.threadLocalProperties.get().remove(RE_CAPTCHA_USER_DOMAIN);
        // Check the authentication
        try {
            int tenantId = IdentityTenantUtil.getTenantIdOfUser(username);
            UserRealm userRealm = BasicCustomAuthenticatorServiceComponent.getRealmService().getTenantUserRealm(tenantId);
            if (userRealm != null) {
                userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();
                isAuthenticated = userStoreManager.authenticate(
                        MultitenantUtils.getTenantAwareUsername(username), password);
            } else {
                throw new AuthenticationFailedException("Cannot find the user realm for the given tenant: " +
                        tenantId, User.getUserFromUserName(username));
            }
        } catch (IdentityRuntimeException e) {
            if (log.isDebugEnabled()) {
                log.debug("BasicAuthentication failed while trying to get the tenant ID of the user " + username, e);
            }
            throw new AuthenticationFailedException(e.getMessage(), User.getUserFromUserName(username), e);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("BasicAuthentication failed while trying to authenticate", e);
            }
            throw new AuthenticationFailedException(e.getMessage(), User.getUserFromUserName(username), e);
        }

        if (!isAuthenticated) {
            if (log.isDebugEnabled()) {
                log.debug("User authentication failed due to invalid credentials");
            }
            if (IdentityUtil.threadLocalProperties.get().get(RE_CAPTCHA_USER_DOMAIN) != null) {
                username = IdentityUtil.addDomainToName(
                        username, IdentityUtil.threadLocalProperties.get().get(RE_CAPTCHA_USER_DOMAIN).toString());
            }
            IdentityUtil.threadLocalProperties.get().remove(RE_CAPTCHA_USER_DOMAIN);
            throw new InvalidCredentialsException("User authentication failed due to invalid credentials",
                    User.getUserFromUserName(username));
        }
        //Check relevant SP and check the installation.
        if ("Playground_SP".equalsIgnoreCase(context.getServiceProviderName())) {
            String uuidIS;
            try {
                uuidIS = userStoreManager.getUserClaimValue(username,
                        SINGLE_SYSTEM_USER_IDENTIFIER_CLAIM, null);
                log.info("************uuidIS value is*************** " + uuidIS);
            } catch (org.wso2.carbon.user.core.UserStoreException e) {
                throw new AuthenticationFailedException("Error occurred while loading user claim - "
                        + SINGLE_SYSTEM_USER_IDENTIFIER_CLAIM, e);
            }
            //if(request.getParameter("uuidClient").isEmpty()){ //Checking if UUID sent by the user is null
            if (uuidClient == null) {//Checking if UUID sent by the user is null
                if (uuidIS != null) {
                    throw new AuthenticationFailedException("User trying to login from a different device"); //Existing user but UUID not sent
                } else {
                    // New user
                    String newUUID = String.valueOf(UUID.randomUUID());
                    log.info("**********newUUID*************" + newUUID);
                    try {
                        userStoreManager.setUserClaimValue(username, SINGLE_SYSTEM_USER_IDENTIFIER_CLAIM, newUUID, null);
                    } catch (UserStoreException e) {
                        e.printStackTrace();
                    }
                    response.addHeader("uuidClient", newUUID);
                    log.info("**********newUUID IS ADDED *************");
                }
            } else {
                //Existing user
                if (uuidIS == null) {
                    throw new AuthenticationFailedException("Invalid User");
            } else if (!uuidIS.equals(uuidClient)) {
                    throw new AuthenticationFailedException("UUID user sent and UUID in WSO2 IS does not match");
                }
            }
            log.info("*******************");
        }

        String tenantDomain = MultitenantUtils.getTenantDomain(username);

        //TODO: user tenant domain has to be an attribute in the AuthenticationContext
        authProperties.put("user-tenant-domain", tenantDomain);

        username = FrameworkUtils.prependUserStoreDomainToName(username);

        if (getAuthenticatorConfig().getParameterMap() != null) {
            String userNameUri = getAuthenticatorConfig().getParameterMap().get("UserNameAttributeClaimUri");
            if (StringUtils.isNotBlank(userNameUri)) {
                boolean multipleAttributeEnable;
                String domain = UserCoreUtil.getDomainFromThreadLocal();
                if (StringUtils.isNotBlank(domain)) {
                    multipleAttributeEnable = Boolean.parseBoolean(userStoreManager.getSecondaryUserStoreManager(domain)
                            .getRealmConfiguration().getUserStoreProperty("MultipleAttributeEnable"));
                } else {
                    multipleAttributeEnable = Boolean.parseBoolean(userStoreManager.
                            getRealmConfiguration().getUserStoreProperty("MultipleAttributeEnable"));
                }
                if (multipleAttributeEnable) {
                    try {
                        if (log.isDebugEnabled()) {
                            log.debug("Searching for UserNameAttribute value for user " + username +
                                    " for claim uri : " + userNameUri);
                        }
                        String usernameValue = userStoreManager.
                                getUserClaimValue(MultitenantUtils.getTenantAwareUsername(username), userNameUri, null);
                        if (StringUtils.isNotBlank(usernameValue)) {
                            tenantDomain = MultitenantUtils.getTenantDomain(username);
                            usernameValue = FrameworkUtils.prependUserStoreDomainToName(usernameValue);
                            username = usernameValue + "@" + tenantDomain;
                            if (log.isDebugEnabled()) {
                                log.debug("UserNameAttribute is found for user. Value is :  " + username);
                            }
                        }
                    } catch (UserStoreException e) {
                        //ignore  but log in debug
                        if (log.isDebugEnabled()) {
                            log.debug("Error while retrieving UserNameAttribute for user : " + username, e);
                        }
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("MultipleAttribute is not enabled for user store domain : " + domain + " " +
                                "Therefore UserNameAttribute is not retrieved");
                    }
                }
            }
        }
        context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
        String rememberMe = request.getParameter("chkRemember");

        if ("on".equals(rememberMe)) {
            context.setRememberMe(true);
        }
    }

    @Override
    protected boolean retryAuthenticationEnabled() {
        return true;
    }


    @Override
    public String getFriendlyName() {
        return BasicCustomAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {
        return BasicCustomAuthenticatorConstants.AUTHENTICATOR_NAME;
    }


}



