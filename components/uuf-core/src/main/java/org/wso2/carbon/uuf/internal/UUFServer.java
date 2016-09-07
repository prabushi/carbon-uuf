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

package org.wso2.carbon.uuf.internal;

public class UUFServer {

    private static final boolean DEV_MODE_ENABLED;

    static {
        DEV_MODE_ENABLED = Boolean.parseBoolean(System.getProperties().getProperty("devmode", "false"));
    }

    @Deprecated
    public static boolean isDevModeEnabled() {
        // TODO: 8/13/16 Remove this when Carbon 'Utils.isDevModeEnabled()' is available in C5.20
        return DEV_MODE_ENABLED;
    }
}
