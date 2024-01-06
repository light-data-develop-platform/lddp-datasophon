/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.datasophon.api.security;

import cn.hutool.http.HttpRequest;
import cn.hutool.http.HttpResponse;
import cn.hutool.http.HttpUtil;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.datasophon.api.enums.Status;
import com.datasophon.api.service.SessionService;
import com.datasophon.api.service.UserInfoService;
import com.datasophon.api.utils.SecurityUtils;
import com.datasophon.common.Constants;
import com.datasophon.common.utils.Result;
import com.datasophon.dao.entity.SessionEntity;
import com.datasophon.dao.entity.UserInfoEntity;

import java.io.IOException;
import java.util.Collections;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.httpclient.HttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

public class PasswordAuthenticator implements Authenticator {

    private static final Logger logger = LoggerFactory.getLogger(PasswordAuthenticator.class);

    @Autowired
    private UserInfoService userService;
    @Autowired
    private SessionService sessionService;

    @Value("${lddp.admin.url}")
    public String adminUrl;

    @Override
    public Result authenticate(String username, String password, String extra) {
        Result result = new Result();
        // verify username and password
        UserInfoEntity user = userService.queryUser(username, password);
        if (user == null) {
            result.put(Constants.CODE, Status.USER_NAME_PASSWD_ERROR.getCode());
            result.put(Constants.MSG, Status.USER_NAME_PASSWD_ERROR.getMsg());
            return result;
        }

        // create session
        String sessionId = sessionService.createSession(user, extra);
        if (sessionId == null) {
            result.put(Constants.CODE, Status.LOGIN_SESSION_FAILED.getCode());
            result.put(Constants.MSG, Status.LOGIN_SESSION_FAILED.getMsg());
            return result;
        }
        logger.info("sessionId : {}", sessionId);
        result.put(Constants.DATA, Collections.singletonMap(Constants.SESSION_ID, sessionId));
        result.put(Constants.CODE, Status.SUCCESS.getCode());
        result.put(Constants.MSG, Status.LOGIN_SUCCESS.getMsg());
        result.put(Constants.USER_INFO, user);
        SecurityUtils.getSession().setAttribute(Constants.SESSION_USER, user);
        return result;
    }

    @Override
    public UserInfoEntity getAuthUser(HttpServletRequest request) {
        SessionEntity session = sessionService.getSession(request);
        if (session == null) {
            logger.info("session info is null ");
            return null;
        }
        // get user object from session
        return userService.getById(session.getUserId());
    }

    @Override
    public Result authenticateByLddpToken(String lddpToken, String clientId) {

        Result result = new Result();
        // verify lddpToken
        UserInfoEntity user = getUserDetail(lddpToken, clientId);
        if (user == null) {
            result.put(Constants.CODE, Status.USER_NAME_PASSWD_ERROR.getCode());
            result.put(Constants.MSG, Status.USER_NAME_PASSWD_ERROR.getMsg());
            return result;
        }

        // create session
        String sessionId = sessionService.createSession(user, clientId);
        if (sessionId == null) {
            result.put(Constants.CODE, Status.LOGIN_SESSION_FAILED.getCode());
            result.put(Constants.MSG, Status.LOGIN_SESSION_FAILED.getMsg());
            return result;
        }
        logger.info("sessionId : {}", sessionId);
        result.put(Constants.DATA, Collections.singletonMap(Constants.SESSION_ID, sessionId));
        result.put(Constants.CODE, Status.SUCCESS.getCode());
        result.put(Constants.MSG, Status.LOGIN_SUCCESS.getMsg());
        result.put(Constants.USER_INFO, user);
        SecurityUtils.getSession().setAttribute(Constants.SESSION_USER, user);
        return result;
    }

    public UserInfoEntity getUserDetail(String lddpToken, String clientId) {
        HttpRequest request = HttpUtil.createGet(adminUrl + "/system/user/getInfo").header("Authorization", "Bearer " + lddpToken)
                .header("Clientid", clientId);

        HttpResponse responseBody = null;
        responseBody = request.execute();
        JSONObject result = JSON.parseObject(responseBody.body());

        if (result.getIntValue("code") != 200) {
            return null;
        } else {
            return userConvert(result);
        }
    }

    public UserInfoEntity userConvert(JSONObject data){

        JSONObject object= data.getJSONObject("data").getJSONObject("user");
        Integer userId = object.getIntValue("userId");
        UserInfoEntity user = userService.getById(userId);
        String username = "lddp_" + object.getString("userName");

        if (user == null) {
            user = new UserInfoEntity();
            user.setId(userId);
            user.setUsername(username);
            user.setUserType(1);
            user.setPassword("admin123");
            userService.createUser(user);
            user = userService.getById(userId);
        }

        return user;
    }
}
