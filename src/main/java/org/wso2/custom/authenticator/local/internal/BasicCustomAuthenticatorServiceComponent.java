package org.wso2.custom.authenticator.local.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.custom.authenticator.local.BasicCustomAuthenticator;


/**
 * @scr.component name="soasecurity.wso2.authenticator.local.basic.component" immediate="true"
 * @scr.reference name="realm.service"
 * interface="org.wso2.carbon.user.core.service.RealmService"cardinality="1..1"
 * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 */
public class BasicCustomAuthenticatorServiceComponent {

    private static Log log = LogFactory.getLog(BasicCustomAuthenticatorServiceComponent.class);

    private static RealmService realmService;

    public static RealmService getRealmService() {
        return realmService;
    }

    protected void activate(ComponentContext ctxt) {
        try {
            BasicCustomAuthenticator basicCustomAuth = new BasicCustomAuthenticator();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), basicCustomAuth, null);
            if (log.isDebugEnabled()) {
                log.info("BasicCustomAuthenticator bundle is activated");
            }
        } catch (Throwable e) {
            log.error("BasicCustomAuthenticator bundle activation Failed", e);
        }
    }

    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.info("BasicCustomAuthenticator bundle is deactivated");
        }
    }

    protected void unsetRealmService(RealmService realmService) {
        log.debug("UnSetting the Realm Service");
        BasicCustomAuthenticatorServiceComponent.realmService = null;
    }

    protected void setRealmService(RealmService realmService) {
        log.debug("Setting the Realm Service");
        BasicCustomAuthenticatorServiceComponent.realmService = realmService;
    }
}