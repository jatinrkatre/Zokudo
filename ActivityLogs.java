package com.cards.auth.entities;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.Entity;

import javax.persistence.Table;


@Entity
@Table(name = "activity_logs")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class ActivityLogs extends AbstractEntity {

    private boolean error;
    private String userName;
    private String program;
    //    @Enumerated(EnumType.STRING)
//    private Activity activity;
    private String errorMessage;
    private String sourceIp;
    private String url;
    private String authorization;

}
