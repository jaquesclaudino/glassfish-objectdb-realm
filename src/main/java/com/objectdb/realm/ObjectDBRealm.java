/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.objectdb.realm;

import com.sun.appserv.security.AppservRealm;
import com.sun.enterprise.security.auth.realm.BadRealmException;
import com.sun.enterprise.security.auth.realm.InvalidOperationException;
import com.sun.enterprise.security.auth.realm.NoSuchRealmException;
import com.sun.enterprise.security.auth.realm.NoSuchUserException;
import java.util.ArrayList;
import java.util.Collections;

import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.NoResultException;
import javax.persistence.Persistence;
import javax.security.auth.login.LoginException;

/**
 *
 * @author Jaques Claudino
 * Based on tutorial: http://www.lucubratory.eu/custom-jaas-realm-for-glassfish-3/
 * 
 * copy glassfish-objectdb-realm-x.x.x.jar to glassfish/domains/domain1/lib
 * 
 * login.conf:
 *   objectdbRealm {
 *     com.objectdb.realm.LoginModule required;
 *   };
 * 
 * domain.xml:
 *   <auth-realm name="objectdb-realm" classname="com.objectdb.realm.ObjectDBRealm">
 *     <property name="url" value="/opt/objectdb/db/app.odb"></property>
 *     <property name="user-entity" value="User"></property>
 *     <property name="user-name-column" value="login"></property>
 *     <property name="password-column" value="password"></property>
 *     <property name="group-name-column" value="groupName"></property>
 *   </auth-realm>
 *
 */
public class ObjectDBRealm extends AppservRealm {

    private static final Logger LOG = Logger.getLogger(ObjectDBRealm.class.getName());
    static {
        LOG.setLevel(Level.ALL);
    }
    
    private static final String DEFAULT_JAAS_CONTEXT_VALUE = "objectdbRealm"; //default name in login.conf       
    private static final String PROPERTY_JAAS_CONTEXT = "jaas-context";
    private static final String PROPERTY_URL = "url";
    private static final String PROPERTY_USER_ENTITY = "user-entity";
    private static final String PROPERTY_USER_NAME_COLUMN = "user-name-column";
    private static final String PROPERTY_PASSWORD_COLUMN = "password-column";    
    private static final String PROPERTY_GROUP_NAME_COLUMN = "group-name-column"; //used when groupName placed on userEntity
    private static final String PROPERTY_GROUP_NAME_JPQL = "group-name-jpql"; //example: select u.group.name from User u where u.name=?1
    
    private String url;
    private String userEntity;
    private String userNameColumn;
    private String passwordColumn;    
    private String groupNameColumn; 
    private String groupNameJPQL; 
    
    /**
     * Initialize a realm with some properties. This can be used when
     * instantiating realms from their descriptions. This method may only be
     * called a single time.
     *
     * @param properties - Key-value pairs defined in the Console's Realm
     * declaration.
     *
     * @exception BadRealmException if the configuration parameters identify a
     * corrupt realm
     * @exception NoSuchRealmException if the configuration parameters specify a
     * realm which doesn't exist
     */
    @Override
    public void init(Properties properties) throws BadRealmException, NoSuchRealmException {
        super.init(properties);
        
        LOG.info("ObjectDBRealm initialization");

        String propJaasContext = properties.getProperty(PROPERTY_JAAS_CONTEXT);
        if (propJaasContext == null) {
            LOG.log(Level.INFO, "ObjectDBRealm property {0} not defined. Using default value {1}. Please check your login.conf.", 
                    new Object[] {PROPERTY_JAAS_CONTEXT, DEFAULT_JAAS_CONTEXT_VALUE});
            setProperty(PROPERTY_JAAS_CONTEXT, DEFAULT_JAAS_CONTEXT_VALUE);
        }
        
        url = getMandatoryProperty(properties, PROPERTY_URL);
        userEntity = getMandatoryProperty(properties, PROPERTY_USER_ENTITY);
        userNameColumn = getMandatoryProperty(properties, PROPERTY_USER_NAME_COLUMN);
        passwordColumn = getMandatoryProperty(properties, PROPERTY_PASSWORD_COLUMN);
        
        groupNameColumn = properties.getProperty(PROPERTY_GROUP_NAME_COLUMN);
        groupNameJPQL = properties.getProperty(PROPERTY_GROUP_NAME_JPQL);
    }

    /**
     * Returns a short (preferably less than fifteen characters) description of
     * the kind of authentication which is supported by this realm.
     * @return 
     */
    @Override
    public String getAuthType() {
        return "ObjectDB Realm";
    }

    /**
     * Returns the name of all the groups that this user belongs to.
     *
     * @param username name of the user in this realm whose group listing is
     * needed.
     *
     * @return enumeration of group names (strings).
     *
     * @exception InvalidOperationException thrown if the realm does not support
     * this operation - e.g. Certificate realm does not support this operation
     * @throws com.sun.enterprise.security.auth.realm.NoSuchUserException
     */
    @Override
    public Enumeration getGroupNames(String username) throws InvalidOperationException, NoSuchUserException {
        List<String> list = new ArrayList<>();
                
        EntityManagerFactory emf = Persistence.createEntityManagerFactory(url);
        EntityManager em = emf.createEntityManager();
 
        if (groupNameJPQL != null) {
            list = em.createQuery(groupNameJPQL, String.class)
                    .setParameter(1, username)
                    .getResultList();
        } else {
            try {             
                list.add(em.createQuery(String.format("select u.%s from %s u where u.%s=?1", groupNameColumn, userEntity, userNameColumn), String.class)
                    .setParameter(1, username)
                    .getSingleResult());
            } catch (NoResultException ex) {
                LOG.warning(ex.toString());
            }
        }

        em.close();
        emf.close();

        LOG.log(Level.FINEST, "getGroupNames user={0} groups={1}", new Object[] {username, list.toString()});
        return Collections.enumeration(list);
    }

    public String[] getAuthenticatedGroups(String username) throws LoginException {
        //Get group names for the authenticated user from the Realm class
        Enumeration enumeration = null;
        try {
            enumeration = getGroupNames(username);
        } catch (InvalidOperationException e) {
            throw new LoginException("InvalidOperationException in ObjectDBRealm.getAuthenticatedGroups");
        } catch (NoSuchUserException e) {
            throw new LoginException("NoSuchUserException in ObjectDBRealm.getAuthenticatedGroups");
        }

        //Convert the Enumeration to String[]
        List<String> g = new ArrayList<>();
        while (enumeration != null && enumeration.hasMoreElements()) {
            g.add((String) enumeration.nextElement());
        }
        
        return g.toArray(new String[g.size()]);
    }
    
    public boolean authenticate(String username, String password) throws LoginException {
        boolean ret = false;        
                
        EntityManagerFactory emf = Persistence.createEntityManagerFactory(url);
        EntityManager em = emf.createEntityManager();
 
        try {
            ret = em.createQuery(String.format("select u from %s u where u.%s=?1 and u.%s=?2", userEntity, userNameColumn, passwordColumn))
                .setParameter(1, username)
                .setParameter(2, password)
                .getSingleResult() != null;
            
        } catch (NoResultException ex) {
            LOG.warning(ex.toString());
        }

        em.close();
        emf.close();
        return ret;
    }
    
    public String getMandatoryProperty(Properties properties, String name) throws BadRealmException {        
        String value = properties.getProperty(name);
        if (value == null) {
            throw new BadRealmException(String.format("property %s not defined", name));
        }
        return value;
    }
     
}
