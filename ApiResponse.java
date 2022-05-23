package com.cards.auth.dto.response;


import lombok.Builder;
import lombok.Data;
import org.springframework.http.HttpStatus;

@Data
@Builder
public class ApiResponse<T> {

    @Builder.Default
    private HttpStatus status = HttpStatus.OK;

    @Builder.Default
    private String message = "success";

    @Builder.Default
    private String code = HttpStatus.OK.toString();
    private T body;

}
