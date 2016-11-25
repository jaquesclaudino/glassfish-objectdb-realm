/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.objectdb.realm;

import com.sun.appserv.security.AppservPasswordLoginModule;


import javax.security.auth.login.LoginException;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Jaques Claudino
 */
public class LoginModule extends AppservPasswordLoginModule {

    private static final Logger LOG = Logger.getLogger(LoginModule.class.getName());

    /**
     * Overrides the authenticateUser() method in AppservPasswordLoginModule
     * Performs authentication of user
     *
     * @throws javax.security.auth.login.LoginException
     */
    @Override
    protected void authenticateUser() throws LoginException {
        LOG.log(Level.INFO, "Autenticate user={0} password={1} realm={2}", new Object[] {_username, _password, _currentRealm});

        if (!(_currentRealm instanceof ObjectDBRealm)) {
            throw new LoginException("Realm not ObjectDBRealm instance. Check 'login.conf'.");
        }
        ObjectDBRealm objectdbRealm = (ObjectDBRealm) _currentRealm;

        if (!objectdbRealm.authenticate(_username, _password)) {
            throw new LoginException("Login Failed for user " + _username);
        }

        LOG.log(Level.INFO, "Login Succeded for user {0}", _username);       
        
        // Call commitUserAuthentication with the group names the user belongs to.
        // Note that this method is called after the authentication has succeeded.
        // If authentication failed do not call this method. Global instance field
        // succeeded is set to true by this method.
        commitUserAuthentication(objectdbRealm.getAuthenticatedGroups(_username));       
    }

}
