package com.cards.auth.service;

import com.cards.auth.dto.ActivityLogsFiltersDTO;

import javax.servlet.http.HttpServletRequest;

public interface ActivityLogsService {
    Object excute(HttpServletRequest request, String programUrl, ActivityLogsFiltersDTO activityLogsFiltersDTO);
}
