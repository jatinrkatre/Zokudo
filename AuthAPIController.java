package com.cards.auth.controllers;


import com.cards.auth.dto.ActivityLogsFiltersDTO;
import com.cards.auth.service.impl.ActivityLogsServiceImpl;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.Authorization;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Slf4j
@RestController
@RequestMapping("/api/v1/authentication")
public class AuthAPIController {

    @Autowired
    ActivityLogsServiceImpl activityLogsService;

    @CrossOrigin(allowCredentials = "true", allowedHeaders = "*", origins = {"*"})
    @GetMapping(value = "/authrequest", consumes = "application/json")
    public void getString(HttpServletRequest request, HttpServletResponse response) {
    }

    @ApiOperation(value = "Get Paged ActivityLogs", authorizations = {@Authorization("basicAuth")})
    @CrossOrigin(allowedHeaders = "*", allowCredentials = "true", origins = {"*"})
    @PostMapping(value = "/getActivityLogs", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Object getActivities(HttpServletRequest request, HttpServletResponse response,
                                @RequestBody ActivityLogsFiltersDTO activityLogsFiltersDTO) {
        return activityLogsService.excute(request, activityLogsFiltersDTO.getProgramUrl(), activityLogsFiltersDTO);
    }
}
