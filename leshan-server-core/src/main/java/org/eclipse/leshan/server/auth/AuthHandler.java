package org.eclipse.leshan.server.auth;

import org.eclipse.leshan.core.request.AuthRequest;
import org.eclipse.leshan.core.request.Identity;
import org.eclipse.leshan.core.response.AuthResponse;
import org.eclipse.leshan.core.response.SendableResponse;
import org.eclipse.leshan.server.registration.Registration;
import org.eclipse.leshan.server.registration.RegistrationIdProvider;
import org.eclipse.leshan.server.registration.RegistrationServiceImpl;
import org.eclipse.leshan.server.security.Authorizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthHandler {

    private static final Logger LOG = LoggerFactory.getLogger(AuthHandler.class);

    private RegistrationServiceImpl registrationService;
    private Authorizer authorizer;

    public AuthHandler(RegistrationServiceImpl registrationService, Authorizer authorizer,
                       RegistrationIdProvider registrationIdProvider) {
        this.registrationService = registrationService;
        this.authorizer = authorizer;
    }

    public SendableResponse<AuthResponse> auth(AuthRequest request) {
        System.out.println("Checking authorization request from: " + request.getRequester());
        Identity requester = request.getRequester();
        Identity host = request.getHost();

        Registration requesterReg = registrationService.getByAddress(requester.getPeerAddress());
        Registration hostReg = registrationService.getByAddress(host.getPeerAddress());

        System.out.println("Requester: " + requesterReg);
        System.out.println("Host: " + hostReg);

        return new SendableResponse<AuthResponse>(AuthResponse.badRequest("Not implemented"));
    }
}
