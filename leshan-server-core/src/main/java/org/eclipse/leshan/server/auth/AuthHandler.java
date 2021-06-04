package org.eclipse.leshan.server.auth;

import java.io.Serializable;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.eclipse.leshan.core.Link;
import org.eclipse.leshan.core.model.ResourceModel;
import org.eclipse.leshan.core.model.ResourceModel.Type;
import org.eclipse.leshan.core.node.LwM2mMultipleResource;
import org.eclipse.leshan.core.node.LwM2mNode;
import org.eclipse.leshan.core.node.LwM2mObject;
import org.eclipse.leshan.core.node.LwM2mObjectInstance;
import org.eclipse.leshan.core.node.LwM2mResource;
import org.eclipse.leshan.core.node.LwM2mResourceInstance;
import org.eclipse.leshan.core.node.LwM2mSingleResource;
import org.eclipse.leshan.core.request.AccessGrant;
import org.eclipse.leshan.core.request.AuthRequest;
import org.eclipse.leshan.core.request.CreateRequest;
import org.eclipse.leshan.core.request.Identity;
import org.eclipse.leshan.core.request.ReadRequest;
import org.eclipse.leshan.core.response.AuthResponse;
import org.eclipse.leshan.core.response.CreateResponse;
import org.eclipse.leshan.core.response.ReadResponse;
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

    private static final int CLIENT_SECURITY_OBJECT_ID = 11000;
    private static final int CLIENT_OBJECT_ID = 11001;
    private static final int CLIENT_ACL_OBJECT_ID = 11002;

    private static final int CLIENT_SECURITY_URI_RESOURCE_ID = 0;
    private static final int CLIENT_SECURITY_SHORT_ID_RESOURCE_ID = 10;

    private static final int CLIENT_SHORTID_RESOURCE_ID = 0;
    private static final int CLIENT_ENDPOINT_RESOURCE_ID = 9;

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
        String hostEndpoint = request.getHostEndpoint();

        Registration requesterReg = registrationService.getByAddress(requester.getPeerAddress());
        Registration hostReg = registrationService.getByEndpoint(hostEndpoint);

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
        LwM2mObjectInstance[] instances = BuildAccessControlInstances(request, requesterReg, hostReg);
        if (instances == null) {
            return new SendableResponse<>(AuthResponse.forbidden(null));
        }

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

    private LwM2mObjectInstance[] BuildAccessControlInstances(AuthRequest request, Registration requester, Registration host) {
        List<ACLObjectInstance> instances = new ArrayList<>();
        int newInstanceId = 0;

        int clientShortId = GetClientShortID(requester, host);
        if (clientShortId < 0) {
            System.err.println("Could not get the requester short ID");
            return null;
        }

        for (AccessGrant grant : request.getGrants()) {
            Integer objId = grant.getPath().getObjectId();
            Integer instanceId = grant.getPath().getObjectInstanceId();

            if (instanceId == null &&
                (grant.hasWrite() || grant.hasRead() || grant.hasDelete() || grant.hasExecute())) {
                continue;
            }

            LwM2mResourceInstance aclInstance = LwM2mResourceInstance.newIntegerInstance(clientShortId, grant.getAccess());
            // TODO: Specify owner
            int ownerId = 1;
            instances.add(new ACLObjectInstance(newInstanceId, objId, instanceId, ownerId, aclInstance));
            newInstanceId++;
        }

        return instances.toArray(new ACLObjectInstance[0]);
    }

    /** Instance of the Access Control Object */
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

    /**
     * Tries to get the short client ID of the requester, in the host.
     *
     * @return
     */
    private int GetClientShortID(Registration requester, Registration host) {
        ReadRequest request = new ReadRequest(CLIENT_OBJECT_ID);
        ReadResponse response = null;
        int shortID = -1;

        try {
            response = this.requestSender.send(host, request, null, DEFAULT_TIMEOUT);
        } catch (Exception e) {
            System.err.println("Could not send the read request to the host");
            System.err.println(e);
            return -1;
        }

        if (!response.isSuccess()) {
            System.err.println("Unsuccessful read request to the host");
            return -1;
        }

        LwM2mObject object = (LwM2mObject) response.getContent();

        for (Map.Entry<Integer, LwM2mObjectInstance> instance : object.getInstances().entrySet()) {
            LwM2mObjectInstance inst = instance.getValue();
            LwM2mResource endpointResource = inst.getResource(CLIENT_ENDPOINT_RESOURCE_ID);

            if (endpointResource == null || endpointResource.getType() != Type.STRING) {
                continue;
            }

            String endpoint = (String) endpointResource.getValue();
            if (endpoint.equals(requester.getEndpoint())) {
                shortID = ((Long) inst.getResource(CLIENT_SHORTID_RESOURCE_ID).getValue()).intValue();
                break;
            }
        }
        return shortID;
    }
}
