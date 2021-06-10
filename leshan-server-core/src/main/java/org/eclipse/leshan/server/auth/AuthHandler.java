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
        int clientShortId = -1;

        /* if credentials are requested, create needed objects */
        if (request.credentialsRequested()) {
            /* TODO: generate these */
            String key_id = "key_identity";
            String key = "secretkey";
            clientShortId = SetClientAccount(hostReg, requesterReg.getEndpoint(), key_id, key);
        }
        else {
            clientShortId = GetClientShortID(hostReg, requesterReg.getEndpoint());
        }

        if (clientShortId < 0) {
            return new SendableResponse<>(AuthResponse.forbidden(null));
        }

        LwM2mObjectInstance[] instances = BuildAccessControlInstances(request, requesterReg, hostReg, clientShortId);

        if (instances == null) {
            return new SendableResponse<>(AuthResponse.forbidden(null));
        }

        CreateRequest createRequest = new CreateRequest(CLIENT_ACL_OBJECT_ID, instances);

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

    private LwM2mObjectInstance[] BuildAccessControlInstances(AuthRequest request, Registration requester, Registration host, int clientShortId) {
        List<ACLObjectInstance> instances = new ArrayList<>();
        int newInstanceId = 0;

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

    private static class ClientObjectInstance extends LwM2mObjectInstance {

        private static final int RES_ID_SCI = 0; /* short client ID */
        private static final int RES_ID_LIFETIME = 1;
        private static final int RES_ID_MIN = 2;
        private static final int RES_ID_MAX = 3;
        private static final int RES_ID_DISABLE = 4;
        private static final int RES_ID_DISABLE_TIME = 5;
        private static final int RES_ID_NOTIFICATIONS = 6;
        private static final int RES_ID_BINDING = 7;
        private static final int RES_ID_ENDPOINT = 9;

        public ClientObjectInstance(int id, Integer shortId, String endpoint) {
            super(id, LwM2mSingleResource.newIntegerResource(RES_ID_SCI, shortId),
                  LwM2mSingleResource.newIntegerResource(RES_ID_LIFETIME, 0),
                  LwM2mSingleResource.newIntegerResource(RES_ID_MIN, 120),
                  LwM2mSingleResource.newIntegerResource(RES_ID_MAX, 360),
                  LwM2mSingleResource.newIntegerResource(RES_ID_DISABLE_TIME, 120),
                  LwM2mSingleResource.newBooleanResource(RES_ID_NOTIFICATIONS, false),
                  LwM2mSingleResource.newStringResource(RES_ID_BINDING, "U"),
                  LwM2mSingleResource.newStringResource(RES_ID_ENDPOINT, endpoint));
        }
    }

    private static class ClientSecurityObjectInstance extends LwM2mObjectInstance {
        private static final int RES_ID_URI = 0;
        private static final int RES_ID_MODE = 2;
        private static final int RES_ID_PUB_KEY_OR_ID = 3;
        private static final int RES_ID_SERVER_PUB = 4;
        private static final int RES_ID_SEC_KEY = 5;
        private static final int RES_ID_SMS_MODE = 6;
        private static final int RES_ID_SMS_PARAMS = 7;
        private static final int RES_ID_SMS_SECRET = 8;
        private static final int RES_ID_SMS_SERVER_NUM = 9;
        private static final int RES_ID_SCI = 10;
        private static final int RES_ID_HOLD_OFF = 11;

        public ClientSecurityObjectInstance(int id, Integer shortId, String key_id, String key) {
            super(id, LwM2mSingleResource.newIntegerResource(RES_ID_MODE, 0), /* PSK Mode for now */
                  LwM2mSingleResource.newBinaryResource(RES_ID_PUB_KEY_OR_ID, key_id.getBytes()),
                  LwM2mSingleResource.newBinaryResource(RES_ID_SEC_KEY, key.getBytes()),
                  LwM2mSingleResource.newIntegerResource(RES_ID_SCI, shortId));
        }
    }

    /**
     * Tries to get the short client ID in a client, of a given endpoint by name
     *
     * @return short ID of the client instance in @p client, negative value on error. The absolute value is the highest ID found.
     */
    private int GetClientShortID(Registration client, String endpoint) {
        ReadRequest request = new ReadRequest(CLIENT_OBJECT_ID);
        ReadResponse response = null;
        int highestID = 1;

        try {
            response = this.requestSender.send(client, request, null, DEFAULT_TIMEOUT);
        } catch (Exception e) {
            System.err.println("Could not send the read request to the client");
            System.err.println(e);
            return -highestID;
        }

        if (!response.isSuccess()) {
            System.err.println("Unsuccessful read request to the client");
            return -highestID;
        }

        LwM2mObject object = (LwM2mObject) response.getContent();

        for (Map.Entry<Integer, LwM2mObjectInstance> instance : object.getInstances().entrySet()) {
            LwM2mObjectInstance inst = instance.getValue();
            LwM2mResource endpointResource = inst.getResource(CLIENT_ENDPOINT_RESOURCE_ID);

            if (endpointResource == null || endpointResource.getType() != Type.STRING) {
                LwM2mResource shortIDResource = inst.getResource(CLIENT_SHORTID_RESOURCE_ID);
                int id = (int)shortIDResource.getValue();
                if (id > highestID) {
                    highestID = id;
                }

                continue;
            }

            String clientEndpoint = (String) endpointResource.getValue();
            if (clientEndpoint.equals(endpoint)) {
                return ((Long) inst.getResource(CLIENT_SHORTID_RESOURCE_ID).getValue()).intValue();
            }
        }

        return -highestID;
    }

    /**
     * Create a new Client Object Instance on a client, using shortId and endpoint name
     *
     * @param client        Client where to create the new instance
     * @param shortId       Short client ID of the peer client account
     * @param endpoint      Endpoint name of the peer client
     *
     * @return  true on success, false otherwise
     */
    private Boolean CreateClientInstance(Registration client, int shortId, String endpoint) {
        LwM2mObjectInstance instance = new ClientObjectInstance(0, shortId, endpoint);
        CreateRequest request = new CreateRequest(CLIENT_OBJECT_ID, instance.getResources().values());

        CreateResponse response = null;
        try {
            response = this.requestSender.send(client, request, null, DEFAULT_TIMEOUT);
        } catch (Exception e) {
            System.err.println("Could not send the client create request to the host");
            System.err.println(e);
            return false;
        }

        if (response == null || response.isFailure()) {
            return false;
        }

        return true;
    }

    /**
     * Create a new Client Security Object Instance on a client, using shortID, PSK ID and PSK Key
     *
     * @param client        Client where to create the new instance
     * @param shortId       Short client ID of the peer client account
     * @param key_id        PSK Identity for the instance
     * @param key           PSK Key for the instance
     *
     * @return  true on success, false otherwise
     */
    private Boolean CreateClientSecurityInstance(Registration client, int shortId, String key_id, String key) {
        LwM2mObjectInstance instance = new ClientSecurityObjectInstance(0, shortId, key_id, key);
        CreateRequest request = new CreateRequest(CLIENT_SECURITY_OBJECT_ID, instance.getResources().values());

        CreateResponse response = null;
        try {
            response = this.requestSender.send(client, request, null, DEFAULT_TIMEOUT);
        } catch (Exception e) {
            System.err.println("Could not send the client security create request to the host");
            System.err.println(e);
            return false;
        }

        if (response == null || response.isFailure()) {
            return false;
        }

        return true;
    }

    /**
     * Creates or updates a peer client account on a given client. The account means the existence
     * of a Client Object instance, with the given endpoint, and a Client Security Object instance,
     * with the given keys and the short ID of the Client Object instance.
     *
     * @param client        Client were to create or update the new account
     * @param endpoint      Endpoint name of the peer client to create or update the account for
     * @param key_id        PSK Identity for the account
     * @param key           PSK Key for the account
     * @return  short client ID of the account in client
     */
    private int SetClientAccount(Registration client, String endpoint, String key_id, String key) {
        /* first check if client with endpoint name exists in client */
        int shortId = GetClientShortID(client, endpoint);
        Boolean newClient = false;

        /* if the client does not exist, create it */
        if (shortId < 0) {
            shortId = (-shortId) + 1;
            if (!CreateClientInstance(client, shortId, endpoint)) {
                System.err.println("Could not create client on " + client);
                return -1;
            }
            newClient = true;
        }

        if (newClient) {
            /* need to create security instance */
            if (!CreateClientSecurityInstance(client, shortId, key_id, key)) {
                System.err.println("Could not create client security on " + client);
                return -1;
            }
            return shortId;
        }
        else {
            throw new RuntimeException("To be implemented, update existing security instance");
        }

    }
}
