
package com.cards.auth.config;

import com.cards.auth.dto.response.ApiError;
import com.cards.auth.exceptions.BizException;
import com.cards.auth.exceptions.ForbiddenException;
import com.cards.auth.exceptions.UnAuthorizedException;
import com.google.common.collect.Lists;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@ControllerAdvice(annotations = RestController.class)
public class WebExceptionHandler {

    @ExceptionHandler(BizException.class)
    public ResponseEntity<Object> bizException(final BizException e) {
        log.error(e.getMessage(), e);
        final ApiError error = new ApiError(HttpStatus.INTERNAL_SERVER_ERROR, e.getAdditionalMessage(), e.getAdditionalMessage());
        return new ResponseEntity<>(error, HttpStatus.INTERNAL_SERVER_ERROR);
    }


    @ExceptionHandler(UnAuthorizedException.class)
    public ResponseEntity<Object> unAuthorizedException(final UnAuthorizedException e) {
        log.error(e.getMessage(), e);
        final ApiError error = new ApiError(HttpStatus.UNAUTHORIZED, e.getMessage(), e.getMessage());
        return new ResponseEntity<>(error, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(ForbiddenException.class)
    public ResponseEntity<Object> unAuthenticatedException(final ForbiddenException e) {
        log.error(e.getMessage(), e);
        final ApiError error = new ApiError(HttpStatus.FORBIDDEN, e.getMessage(), e.getMessage());
        return new ResponseEntity<>(error, HttpStatus.FORBIDDEN);
    }


    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Object> methodArgumentNotValidException(final MethodArgumentNotValidException e) {
        log.error(e.getMessage(), e);
        List<String> errors = Lists.newArrayList();
        List<FieldError> fieldErrors = e.getBindingResult().getFieldErrors();
        for (FieldError fieldError : fieldErrors) {
            errors.add(fieldError.getDefaultMessage());
        }
        final ApiError error = new ApiError(HttpStatus.INTERNAL_SERVER_ERROR, "Arguments are invalid", errors);
        return new ResponseEntity<>(error, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Object> httpMessageNotReadableException(final HttpMessageNotReadableException e) {
        log.error(e.getMessage(), e);
        final ApiError error = new ApiError(HttpStatus.INTERNAL_SERVER_ERROR, e.getMostSpecificCause().getMessage(), e.getMostSpecificCause().getMessage());
        return new ResponseEntity<>(error, HttpStatus.INTERNAL_SERVER_ERROR);
    }


    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<Object> handleConstraintViolation(final ConstraintViolationException ex) {
	List<String> errors = new ArrayList<>();
	for (ConstraintViolation<?> violation : ex.getConstraintViolations()) {
	    errors.add(violation.getRootBeanClass().getName() + " " + violation.getPropertyPath() + ": "
		    + violation.getMessage());
	}
	final ApiError error = new ApiError(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage(), errors);
	return new ResponseEntity<>(error, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(Exception.class)
    @ResponseStatus(value = HttpStatus.INTERNAL_SERVER_ERROR)
    public ResponseEntity<?> exception(final Exception e) {
        log.error(e.getMessage(), e);
        final ApiError error = new ApiError(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage(), e.getLocalizedMessage());
        return new ResponseEntity<>(error, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
