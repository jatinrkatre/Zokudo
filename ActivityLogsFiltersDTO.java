package com.cards.auth.dto;

import lombok.Data;

@Data
public class ActivityLogsFiltersDTO {

    private String page;
    private String size;
    private String dateRange;
    private String userName;
    private String programUrl;
    private String role;
}
