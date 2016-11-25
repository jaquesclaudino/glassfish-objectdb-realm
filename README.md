# glassfish-objectdb-realm

copy glassfish-objectdb-realm-x.x.x.jar to glassfish/domains/domain1/lib

login.conf:
  objectdbRealm {
    com.objectdb.realm.LoginModule required;
  };

domain.xml:
  <auth-realm name="objectdb-realm" classname="com.objectdb.realm.ObjectDBRealm">
    <property name="url" value="/opt/objectdb/db/app.odb"></property>
    <property name="user-entity" value="User"></property>
    <property name="user-name-column" value="login"></property>
    <property name="password-column" value="password"></property>
    <property name="group-name-column" value="groupName"></property>
  </auth-realm>