
/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.hashing.pbkdf2.constants;

/**
 * This class contains constants.
 */
public class Constants {

    /**
     * This class contains constants which where specially for PBKDF2 hashing algorithm.
     */
    public static class PBKDF2Constants {

        public static final String PBKDF2_PRF = "PBKDF2WithHmacSHA1";
        public static final String CHARSET_UTF_8 = "UTF-8";
        public static final String ITERATION_NAME = "Iterations";
        public static final String DERIVED_KEY_LENGTH_NAME = "Derived Key Length";
    }

}
