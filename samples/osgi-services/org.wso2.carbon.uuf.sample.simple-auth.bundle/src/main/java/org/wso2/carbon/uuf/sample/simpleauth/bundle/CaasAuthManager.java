/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.uuf.sample.simpleauth.bundle;

import org.wso2.carbon.security.caas.user.core.exception.AuthorizationStoreException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.store.AuthorizationStore;
import org.wso2.carbon.uuf.sample.simpleauth.bundle.CaasUser;
import org.wso2.carbon.security.caas.user.core.bean.Action;
import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.Permission;
import org.wso2.carbon.security.caas.user.core.bean.Resource;
import org.wso2.carbon.security.caas.user.core.bean.Role;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.service.RealmService;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class CaasAuthManager {

    private static final String DEFAULT_IDENTITY_STORE = "JDBCIdentityStore";
    private static final String DEFAULT_CREDENTIAL_STORE = "JDBCCredentialStore";
    private static final String DEFAULT_AUTHORIZATION_STORE = "JDBCAuthorizationStore";
    private RealmService realmService;

    /*
    * TODO Implement CRUD operations to following beans
    * Action -
    * Group
    * Permission -
    * Resource -
    * Role -
    * User -
    */

    public User addUser(String userName, String tenantDomain){
        return new User.UserBuilder()
                .setUserName(userName)
                .setUserId(UUID.randomUUID().toString())
                .setTenantDomain(tenantDomain)
                .setCredentialStoreId(DEFAULT_CREDENTIAL_STORE)
                .setIdentityStoreId(DEFAULT_IDENTITY_STORE)
                .setIdentityStore(realmService.getIdentityStore())
                .setAuthorizationStore(realmService.getAuthorizationStore())
                .setClaimManager(realmService.getClaimManager())
                .build();
    }

    public Resource addResource(String resourceUri, String prefix, String UserId) throws AuthorizationStoreException {
        AuthorizationStore authorizationStore = realmService.getAuthorizationStore();
        return authorizationStore.addResource(prefix, resourceUri,
                DEFAULT_AUTHORIZATION_STORE, UserId, DEFAULT_IDENTITY_STORE);
    }

    public Action addAction(String prefix, String action) throws AuthorizationStoreException {
        AuthorizationStore authorizationStore = realmService.getAuthorizationStore();
        return authorizationStore.addAction(prefix, action, DEFAULT_AUTHORIZATION_STORE);
    }

    public Permission addPermission(Resource resource, Action action) throws AuthorizationStoreException {
        AuthorizationStore authorizationStore = realmService.getAuthorizationStore();
        return authorizationStore.addPermission(resource, action, DEFAULT_AUTHORIZATION_STORE);
    }

    public Role addRole(String roleName, List<Permission> permissions) throws AuthorizationStoreException {
        AuthorizationStore authorizationStore = realmService.getAuthorizationStore();
        return authorizationStore.addRole(roleName, permissions, DEFAULT_AUTHORIZATION_STORE);
    }

    public Group addGroup(String groupName, String tenantDomain) {
        return new Group.GroupBuilder()
                .setGroupName(groupName)
                .setGroupId(UUID.randomUUID().toString())
                .setTenantDomain(tenantDomain)
                .setIdentityStoreId(DEFAULT_IDENTITY_STORE)
                .setIdentityStore(realmService.getIdentityStore())
                .setAuthorizationStore(realmService.getAuthorizationStore())
                .build();
    }

    //assign roles
    public void assignRoles(User user, List<Role> roles) throws IdentityStoreException, AuthorizationStoreException {
        user.updateRoles(roles);
    }

    public void updateRole(Role role, List<Permission> permissions) throws AuthorizationStoreException {
        AuthorizationStore authorizationStore = realmService.getAuthorizationStore();
        authorizationStore.updatePermissionsInRole(role.getRoleId(), DEFAULT_AUTHORIZATION_STORE, permissions);
    }
}
