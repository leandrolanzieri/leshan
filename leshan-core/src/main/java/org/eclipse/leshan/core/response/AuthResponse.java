package org.eclipse.leshan.core.response;

import org.eclipse.leshan.core.ResponseCode;

public class AuthResponse extends AbstractLwM2mResponse {

    public AuthResponse(ResponseCode code, String errorMessage, Object coapResponse) {
        super(code, errorMessage, coapResponse);
    }

    // TODO:
    @Override
    public boolean isSuccess() {
        return getCode() == ResponseCode.CHANGED;
    }

    // TODO: 
    @Override
    public boolean isValid() {
        switch (code.getCode()) {
        case ResponseCode.CHANGED_CODE:
        case ResponseCode.BAD_REQUEST_CODE:
        case ResponseCode.INTERNAL_SERVER_ERROR_CODE:
            return true;
        default:
            return false;
        }
    }

    // Syntactic sugar static constructors :

    public static AuthResponse success() {
        return new AuthResponse(ResponseCode.CREATED, null, null);
    }

    public static AuthResponse badRequest(String errorMessage) {
        return new AuthResponse(ResponseCode.BAD_REQUEST, null, errorMessage);
    }

    public static AuthResponse forbidden(String errorMessage) {
        return new AuthResponse(ResponseCode.FORBIDDEN, null, errorMessage);
    }

    public static AuthResponse preconditionFailed(String errorMessage) {
        return new AuthResponse(ResponseCode.PRECONDITION_FAILED, null, errorMessage);
    }

    public static AuthResponse internalServerError(String errorMessage) {
        return new AuthResponse(ResponseCode.INTERNAL_SERVER_ERROR, null, errorMessage);
    }
}
