package com.cards.auth.repositories;

import com.cards.auth.entities.ActivityLogs;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;

import java.util.Date;

public interface ActivityLogsRepository extends JpaRepository<ActivityLogs, Long>, JpaSpecificationExecutor<ActivityLogs> {

//    @Query("SELECT al FROM ActivityLogs al WHERE al.createdAt")
//    Page<ActivityLogs> getLogsDescending(Pageable page);
}
