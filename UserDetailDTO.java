package com.cards.auth.dto;

import lombok.Data;

@Data
public class UserDetailDTO {

    private String userId;
    private String userName;
    private String password;
    private String roleId;
    private String roleName;
    private String privilegeId;
    private String privilegeName;
    private String urlId;
    private String url;
    private String programName;
    private String hostUrl;

}
