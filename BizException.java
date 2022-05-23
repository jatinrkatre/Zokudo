package com.cards.auth.exceptions;


import org.springframework.core.NestedRuntimeException;

public class BizException extends NestedRuntimeException {

    private static final long serialVersionUID = 1L;
    private String errorCode;
    private String additionalMessage;
    private String status;

    public BizException(String errorCode, String additionalMessage, Throwable cause) {
        super(additionalMessage, cause);
        this.errorCode = errorCode;
        this.additionalMessage = additionalMessage;
    }

    public BizException(String errorMessage, Throwable cause) {
        super(errorMessage, cause);
    }

    public BizException(String errorCode, String additionalMessage) {
        super(additionalMessage);
        this.errorCode = errorCode;
        this.additionalMessage = additionalMessage;
    }

    public BizException(String additionalMessage) {
        super(additionalMessage);
        this.additionalMessage = additionalMessage;
    }


    public String getErrorCode() {
        return errorCode;
    }

    public void setErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }

    public String getAdditionalMessage() {
        return additionalMessage;
    }

    public void setAdditionalMessage(String additionalMessage) {
        this.additionalMessage = additionalMessage;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}
