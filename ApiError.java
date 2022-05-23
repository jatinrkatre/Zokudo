
package com.cards.auth.dto.response;

import org.springframework.http.HttpStatus;

import java.util.List;

public class ApiError {

    private HttpStatus status;
    private String message;
    private List<String> errors;
    private Object details;

    public ApiError(final HttpStatus status, final String message, final List<String> errors) {
        this.status = status;
        this.message = message;
        this.errors = errors;
    }

    public ApiError(final HttpStatus status, final String message, final String error) {
        this.status = status;
        this.message = message;
        this.details=error;
    }

    public ApiError(final HttpStatus status, final String message) {
        this.status = status;
        this.message = message;
    }

    public ApiError(HttpStatus status, String message, Object details) {
        this(status, message);
        this.details = details;
        this.message=message;
        this.status=status;
    }

    public HttpStatus getStatus() {
        return status;
    }

    public void setStatus(HttpStatus status) {
        this.status = status;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public List<String> getErrors() {
        return errors;
    }

    public void setErrors(List<String> errors) {
        this.errors = errors;
    }

    public Object getDetails() {
        return details;
    }

    public void setDetails(Object details) {
        this.details = details;
    }
}
