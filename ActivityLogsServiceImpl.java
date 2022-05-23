package com.cards.auth.service.impl;


import com.cards.auth.dto.ActivityLogsFiltersDTO;
import com.cards.auth.entities.ActivityLogs;
import com.cards.auth.repositories.ActivityLogsRepository;
import com.google.common.collect.Maps;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import com.cards.auth.service.ActivityLogsService;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class ActivityLogsServiceImpl implements ActivityLogsService {

    @Autowired
    ActivityLogsRepository activityLogsRepository;

    @Override
    public Object excute(HttpServletRequest request, String programUrl, ActivityLogsFiltersDTO activityLogsFiltersDTO) {
        Sort sort = new Sort(Sort.Direction.DESC, "createdAt");
        Pageable pageable = PageRequest.of(Integer.parseInt(activityLogsFiltersDTO.getPage()), Integer.parseInt(activityLogsFiltersDTO.getSize()), sort);
        Page<ActivityLogs> logsDescending = activityLogsRepository.findAll(pageable);
//        Map<String, Object> map = Maps.newHashMap();
//        map.put("activityLogsList", logsDescending.get().collect(Collectors.toList()));
        return logsDescending;
    }
}
