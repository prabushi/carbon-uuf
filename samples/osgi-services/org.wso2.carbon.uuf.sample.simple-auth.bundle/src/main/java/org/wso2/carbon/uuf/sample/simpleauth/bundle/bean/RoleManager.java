/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.uuf.sample.simpleauth.bundle.bean;

import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.Permission;
import org.wso2.carbon.security.caas.user.core.bean.Role;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.exception.AuthorizationStoreException;
import org.wso2.carbon.security.caas.user.core.exception.PermissionNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.RoleNotFoundException;
import org.wso2.carbon.security.caas.user.core.service.RealmService;
import org.wso2.carbon.security.caas.user.core.store.AuthorizationStore;
import org.wso2.carbon.uuf.exception.UUFException;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import java.util.List;

public class RoleManager {

    private final AuthorizationStore authorizationStore;

    public RoleManager() {
        try {
            InitialContext initialContext = new InitialContext();
            RealmService realmService = (RealmService) initialContext.lookup(
                    "osgi:service/org.wso2.carbon.security.caas.user.core.service.RealmService");
            authorizationStore = realmService.getAuthorizationStore();
        } catch (NamingException e) {
            throw new UUFException(
                    "Error occurred while calling org.wso2.carbon.security.caas.user.core.service.RealmService." + e);
        }
    }

    public Role createRole(String roleName, List<Permission> permissions, String AuthorizationStoreName)
            throws AuthorizationStoreException {
        String authorizationStoreId = "";//cal API to get authStoreId form its name
        return authorizationStore.addRole(roleName, permissions, authorizationStoreId);
    }

    public void updateRolePermission(Role role, List<Permission> newPermissionList) throws AuthorizationStoreException {
        authorizationStore.updatePermissionsInRole(role.getRoleId(), role.getAuthorizationStoreId(), newPermissionList);
    }

    public void updateRolePermission(Role role, List<Permission> permissionsToBeAssign,
                                     List<Permission> permissionsToBeUnassign) throws AuthorizationStoreException {
        authorizationStore.updatePermissionsInRole(role.getRoleId(), role.getAuthorizationStoreId(),
                                                   permissionsToBeAssign, permissionsToBeUnassign);
    }

    public Role getRole(String roleName) throws RoleNotFoundException, AuthorizationStoreException {
        return authorizationStore.getRole(roleName);
    }

    public List<Role> getRolesOfUser(User user) throws AuthorizationStoreException {
        return authorizationStore.getRolesOfUser(user.getUserId(), user.getIdentityStoreId());
    }

    public List<Role> getRolesOfGroup(Group group) throws AuthorizationStoreException {
        return authorizationStore.getRolesOfGroup(group.getGroupId(), group.getIdentityStoreId());
    }

    public List<Permission> getPermissionsOfRole(Role role)
            throws PermissionNotFoundException, AuthorizationStoreException {
        return authorizationStore.getPermissionsOfRole(role.getRoleId(), role.getRoleId());
    }

    public void deleteRole(Role role) throws AuthorizationStoreException {
        authorizationStore.deleteRole(role);
    }

    public void assignRolesToUser(User user, List<Role> newRoleList) throws AuthorizationStoreException {
        authorizationStore.updateRolesInUser(user.getUserId(), user.getIdentityStoreId(), newRoleList);
    }

    public void assignRolesToGroup(Group group, List<Role> newRoleList) throws AuthorizationStoreException {
        authorizationStore.updateRolesInGroup(group.getGroupId(), group.getIdentityStoreId(), newRoleList);
    }

    public void updateRolesofUser(User user, List<Role> rolesToBeAssign,
                                  List<Role> rolesToBeUnassign) throws AuthorizationStoreException {
        authorizationStore.updateRolesInGroup(user.getUserId(), user.getIdentityStoreId(), rolesToBeAssign,
                                              rolesToBeUnassign);
    }

    public void updateRolesOfGroup(Group group, List<Role> rolesToBeAssign,
                                   List<Role> rolesToBeUnassign) throws AuthorizationStoreException {
        authorizationStore.updateRolesInGroup(group.getGroupId(), group.getIdentityStoreId(), rolesToBeAssign,
                                              rolesToBeUnassign);
    }

    public void getAllAvailableRoles() {
        //call API
    }

}