package org.eclipse.leshan.server.auth;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.eclipse.leshan.core.Link;
import org.eclipse.leshan.core.model.ResourceModel;
import org.eclipse.leshan.core.node.LwM2mMultipleResource;
import org.eclipse.leshan.core.node.LwM2mObjectInstance;
import org.eclipse.leshan.core.node.LwM2mResource;
import org.eclipse.leshan.core.node.LwM2mResourceInstance;
import org.eclipse.leshan.core.node.LwM2mSingleResource;
import org.eclipse.leshan.core.request.AccessGrant;
import org.eclipse.leshan.core.request.AuthRequest;
import org.eclipse.leshan.core.request.CreateRequest;
import org.eclipse.leshan.core.request.Identity;
import org.eclipse.leshan.core.response.AuthResponse;
import org.eclipse.leshan.core.response.CreateResponse;
import org.eclipse.leshan.core.response.SendableResponse;
import org.eclipse.leshan.server.registration.Registration;
import org.eclipse.leshan.server.registration.RegistrationIdProvider;
import org.eclipse.leshan.server.registration.RegistrationServiceImpl;
import org.eclipse.leshan.server.request.LwM2mRequestSender;
import org.eclipse.leshan.server.security.Authorizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthHandler {

    // We choose a default timeout a bit higher to the MAX_TRANSMIT_WAIT(62-93s) which is the time from starting to
    // send a Confirmable message to the time when an acknowledgement is no longer expected.
    private static final long DEFAULT_TIMEOUT = 2 * 60 * 1000l; // 2min in ms

    private static final Logger LOG = LoggerFactory.getLogger(AuthHandler.class);

    private RegistrationServiceImpl registrationService;
    private LwM2mRequestSender requestSender;
    private Authorizer authorizer;

    public AuthHandler(RegistrationServiceImpl registrationService, Authorizer authorizer,
                       RegistrationIdProvider registrationIdProvider,
                       LwM2mRequestSender requestSender) {
        this.registrationService = registrationService;
        this.requestSender = requestSender;
        this.authorizer = authorizer;
    }

    public SendableResponse<AuthResponse> auth(AuthRequest request) {
        Identity requester = request.getRequester();
        Identity host = request.getHost();

        Registration requesterReg = registrationService.getByAddress(requester.getPeerAddress());
        Registration hostReg = registrationService.getByAddress(host.getPeerAddress());

        if (requesterReg == null || hostReg == null) {
            System.err.println("Could not find registrations");
            return new SendableResponse<>(AuthResponse.badRequest(null));
        }

        System.out.println("Requester: " + requesterReg);
        System.out.println("Host: " + hostReg);

        requesterReg = this.authorizer.isAuthorized(request, requesterReg, requester);
        if (requesterReg == null) {
            return new SendableResponse<>(AuthResponse.forbidden(null));
        }

        // Check that the objects in the request exist in the host
        if (!RequestObjectsExist(request, hostReg)) {
            return new SendableResponse<>(AuthResponse.forbidden(null));
        }

        // TODO: For now always grant the requested access rights
        // YOU SHALL PASS!
        LwM2mObjectInstance[] instances = BuildAccessControlInstances(request, hostReg);
        int objectId = 11002;
        CreateRequest createRequest = new CreateRequest(objectId, instances);

        CreateResponse createResponse = null;
        try {
            createResponse = this.requestSender.send(hostReg, createRequest, null, DEFAULT_TIMEOUT);
        } catch (Exception e) {
            System.err.println("Could not send the create request to the host");
            System.err.println(e);
            return new SendableResponse<>(AuthResponse.forbidden(null));
        }

        if (createResponse == null || createResponse.isFailure()) {
            return new SendableResponse<>(AuthResponse.forbidden(null));
        }

        return new SendableResponse<AuthResponse>(AuthResponse.success());
    }

    private Boolean RequestObjectsExist(AuthRequest request, Registration host) {
        Link links[] = host.getObjectLinks();
        List<String> linksStr = new ArrayList<>();

        for (Link link : links) {
            linksStr.add(link.getUrl());
        }

        for (AccessGrant grant : request.getGrants()) {
            String path = grant.getPath().toString();
            if (!linksStr.contains(path)) {
                System.err.println(path + " is not registered in " + host);
                return false;
            }
        }

        return true;
    }

    private LwM2mObjectInstance[] BuildAccessControlInstances(AuthRequest request, Registration host) {
        List<ACLObjectInstance> instances = new ArrayList<>();
        int newInstanceId = 0;

        for (AccessGrant grant : request.getGrants()) {
            Integer objId = grant.getPath().getObjectId();
            Integer instanceId = grant.getPath().getObjectInstanceId();

            if (instanceId == null &&
                (grant.hasWrite() || grant.hasRead() || grant.hasDelete() || grant.hasExecute())) {
                continue;
            }

            // TODO: Specify the client short ID
            int clientShortId = 1;
            LwM2mResourceInstance aclInstance = LwM2mResourceInstance.newIntegerInstance(clientShortId, grant.getAccess());
            // TODO: Specify owner
            int ownerId = 1;
            instances.add(new ACLObjectInstance(newInstanceId, objId, instanceId, ownerId, aclInstance));
            newInstanceId++;
        }

        return instances.toArray(new ACLObjectInstance[0]);
    }

    /** Instance of the Access Control Object (ID = 2) */
    private static class ACLObjectInstance extends LwM2mObjectInstance {

        private static final int RES_ID_OBJ_ID = 0;
        private static final int RES_ID_OBJ_INST_ID = 1;
        private static final int RES_ID_ACL = 2;
        private static final int RES_ID_OWNER = 3;

        public ACLObjectInstance(int id, Integer objectId, Integer instanceId, Integer owner, LwM2mResourceInstance ...acls) {
            super(id, LwM2mSingleResource.newIntegerResource(RES_ID_OBJ_ID, objectId),
                  LwM2mSingleResource.newIntegerResource(RES_ID_OBJ_INST_ID, instanceId),
                  LwM2mSingleResource.newIntegerResource(RES_ID_OWNER, owner),
                  new LwM2mMultipleResource(RES_ID_ACL, ResourceModel.Type.INTEGER, acls));
        }

        @Override
        public String toString() {
            return String.format("AccessControl [objectId=%s, objectInstanceId=%s]",
                    this.getResource(RES_ID_OBJ_ID).toString(),
                    this.getResource(RES_ID_OBJ_INST_ID).toString());
        }
    }
}
