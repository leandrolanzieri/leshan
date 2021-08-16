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
import org.eclipse.leshan.core.node.LwM2mPath;
import org.eclipse.leshan.core.node.LwM2mResource;
import org.eclipse.leshan.core.node.LwM2mResourceInstance;
import org.eclipse.leshan.core.node.LwM2mSingleResource;
import org.eclipse.leshan.core.node.ObjectLink;
import org.eclipse.leshan.core.request.AccessGrant;
import org.eclipse.leshan.core.request.AuthRequest;
import org.eclipse.leshan.core.request.CreateRequest;
import org.eclipse.leshan.core.request.Identity;
import org.eclipse.leshan.core.request.ReadRequest;
import org.eclipse.leshan.core.request.WriteRequest;
import org.eclipse.leshan.core.request.WriteRequest.Mode;
import org.eclipse.leshan.core.response.AuthResponse;
import org.eclipse.leshan.core.response.CreateResponse;
import org.eclipse.leshan.core.response.ReadResponse;
import org.eclipse.leshan.core.response.SendableResponse;
import org.eclipse.leshan.core.response.WriteResponse;
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
    //private static final long DEFAULT_TIMEOUT = 2 * 60 * 1000l; // 2min in ms
    private static final long DEFAULT_TIMEOUT = 2000l; // ms

    private static final int CLIENT_SECURITY_OBJECT_ID = 11000;
    private static final int CLIENT_OBJECT_ID = 11001;
    private static final int CLIENT_ACL_OBJECT_ID = 11002;
    private static final int OSCORE_OBJECT_ID = 21;

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

        System.out.println("Serving authorization request");
        System.out.println("From:");
        System.out.println(requesterReg.getEndpoint());
        System.out.println("to access:");
        System.out.println(hostReg.getEndpoint());

        requesterReg = this.authorizer.isAuthorized(request, requesterReg, requester);
        if (requesterReg == null) {
            System.err.println("The requester is not authorized");
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
            System.out.println("Credentials were requested");

            if (SupportsOscore(requesterReg) && SupportsOscore(hostReg)) {
                System.out.println("Both support OSCORE, using that");
                /* TODO: generate these */
                String master_secret = "0123456789abcdef";
                String master_salt = "mastersalt";
                String r_id = "r";
                String s_id = "s";
                clientShortId = SetClientAccount(hostReg, requesterReg.getEndpoint(), master_salt,
                                                 master_secret, r_id, s_id);
                SetClientAccount(requesterReg, hostReg.getEndpoint(), master_salt, master_secret,
                                 s_id, r_id);
            }
            else {
                System.out.println("OSCORE not supported, using DTLS");
                /* TODO: generate these */
                String key_id = "key_identity";
                String key = "secretkey";
                clientShortId = SetClientAccount(hostReg, requesterReg.getEndpoint(), key_id, key);
                SetClientAccount(requesterReg, hostReg.getEndpoint(), key_id, key);
            }
        }
        else {
            System.out.println("Credentials were not requested");
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

        static final int RES_ID_OBJ_ID = 0;
        static final int RES_ID_OBJ_INST_ID = 1;
        static final int RES_ID_ACL = 2;
        static final int RES_ID_OWNER = 3;

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

        static final int RES_ID_SCI = 0; /* short client ID */
        static final int RES_ID_LIFETIME = 1;
        static final int RES_ID_MIN = 2;
        static final int RES_ID_MAX = 3;
        static final int RES_ID_DISABLE = 4;
        static final int RES_ID_DISABLE_TIME = 5;
        static final int RES_ID_NOTIFICATIONS = 6;
        static final int RES_ID_BINDING = 7;
        static final int RES_ID_ENDPOINT = 9;

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
        static final int RES_ID_URI = 0;
        static final int RES_ID_MODE = 2;
        static final int RES_ID_PUB_KEY_OR_ID = 3;
        static final int RES_ID_SERVER_PUB = 4;
        static final int RES_ID_SEC_KEY = 5;
        static final int RES_ID_SMS_MODE = 6;
        static final int RES_ID_SMS_PARAMS = 7;
        static final int RES_ID_SMS_SECRET = 8;
        static final int RES_ID_SMS_SERVER_NUM = 9;
        static final int RES_ID_SCI = 10;
        static final int RES_ID_HOLD_OFF = 11;
        static final int RES_ID_OSCORE_MODE = 17;

        static final int MODE_PSK = 0;
        static final int MODE_RPK = 1;
        static final int MODE_CERTIFICATE = 2;
        static final int MODE_NOSEC = 3;

        public ClientSecurityObjectInstance(int id, Integer shortId, String key_id, String key) {
            super(id, LwM2mSingleResource.newIntegerResource(RES_ID_MODE, MODE_PSK), /* PSK Mode for now */
                  LwM2mSingleResource.newBinaryResource(RES_ID_PUB_KEY_OR_ID, key_id.getBytes()),
                  LwM2mSingleResource.newBinaryResource(RES_ID_SEC_KEY, key.getBytes()),
                  LwM2mSingleResource.newIntegerResource(RES_ID_SCI, shortId));
        }

        public ClientSecurityObjectInstance(int id, Integer shortId, Integer oscore_instance) {
            super(id, LwM2mSingleResource.newIntegerResource(RES_ID_MODE, MODE_NOSEC),
            LwM2mSingleResource.newIntegerResource(RES_ID_SCI, shortId),
            LwM2mSingleResource.newObjectLinkResource(RES_ID_OSCORE_MODE, new ObjectLink(OSCORE_OBJECT_ID, oscore_instance)));
        }
    }

    private static class OscoreObjectInstance extends LwM2mObjectInstance {
        static final int RES_ID_MASTER_SECRET = 0;
        static final int RES_ID_SENDER = 1;
        static final int RES_ID_RECIPIENT = 2;
        static final int RES_ID_AEAD_ALG = 3;
        static final int RES_ID_HMAC_ALG = 4;
        static final int RES_ID_MASTER_SALT = 5;
        static final int RES_ID_CTX = 6;

        public OscoreObjectInstance(int id, String master_secret, String sender_id,
                                    String recipient_id, String master_salt) {
            super(id,
                  LwM2mSingleResource.newStringResource(RES_ID_MASTER_SECRET, master_secret),
                  LwM2mSingleResource.newStringResource(RES_ID_SENDER, sender_id),
                  LwM2mSingleResource.newStringResource(RES_ID_RECIPIENT, recipient_id),
                  LwM2mSingleResource.newIntegerResource(RES_ID_AEAD_ALG, 10), /* AEAD_ALG_AES_CCM_16_64_128 for now */
                  LwM2mSingleResource.newIntegerResource(RES_ID_HMAC_ALG, 0), /* HMAC with SHA-256 for now */
                  LwM2mSingleResource.newStringResource(RES_ID_MASTER_SALT, master_salt)
            );
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

        System.out.format("Trying to get client ID of %s", endpoint);
        System.out.println("In client");
        System.out.println(client.getIdentity().getPeerAddress());
        try {
            response = this.requestSender.send(client, request, null, DEFAULT_TIMEOUT);
        } catch (Exception e) {
            System.err.println("Could not send the read request to the client");
            System.err.println(e);
            return -highestID;
        }

        if (response == null || !response.isSuccess()) {
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
     * Create a new Client Security Object Instance on a client, using shortID and no security mode
     *
     * @param client            Client where to create the new instance
     * @param shortId           Short client ID of the peer client account
     * @param oscore_instance   Instance ID of the related OSCORE object
     *
     * @return  true on success, false otherwise
     */
    private Boolean CreateClientSecurityInstance(Registration client, int shortId, int oscore_instance) {
        LwM2mObjectInstance instance = new ClientSecurityObjectInstance(0, shortId, oscore_instance);
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
     * Create a new OSCORE Object Instance on a client, using the provided shared secrets.
     *
     * @param client                Client where to create the new instance
     * @param master_salt           Master salt
     * @param master_secret         Master secret
     * @param recipient_id          Recipient ID
     * @param sender_id             Sender ID
     *
     * @return instance number on success, -1 otherwise
     */
    private int CreateOscoreInstance(Registration client, String master_salt,
                                         String master_secret, String recipient_id,
                                         String sender_id) {
        LwM2mObjectInstance instance = new OscoreObjectInstance(0, master_secret, sender_id, recipient_id, master_salt);
        CreateRequest request = new CreateRequest(OSCORE_OBJECT_ID, instance.getResources().values());

        CreateResponse response = null;
        try {
            response = this.requestSender.send(client, request, null, DEFAULT_TIMEOUT);
        } catch (Exception e) {
            System.err.println("Could not send the OSCORE create request to the host");
            System.err.println(e);
            return -1;
        }

        if (response == null || response.isFailure()) {
            return -1;
        }

        String location = response.getLocation();
        LwM2mPath path = new LwM2mPath(location);
        if (path.getObjectInstanceId() == null) {
            return -1;
        }

        System.out.format("Created OSCORE, the new instance is %d\n", path.getObjectInstanceId());
        return path.getObjectInstanceId();
    }

    private Boolean UpdateClientSecurityInstance(Registration client, int shortId, String key_id, String key) {
        ReadRequest request = new ReadRequest(CLIENT_SECURITY_OBJECT_ID);
        ReadResponse response = null;

        /* get all client security instances */
        try {
            response = this.requestSender.send(client, request, null, DEFAULT_TIMEOUT);
        } catch (Exception e) {
            System.err.println("Could not send the read request to the client");
            System.err.println(e);
            return false;
        }

        if (!response.isSuccess()) {
            System.err.println("Unsuccessful read request to the client");
            return false;
        }

        LwM2mObject object = (LwM2mObject) response.getContent();
        LwM2mObjectInstance foundInstance = null;

        /* try to find the instance for the given short client ID */
        for (Map.Entry<Integer, LwM2mObjectInstance> instance : object.getInstances().entrySet()) {
            LwM2mObjectInstance inst = instance.getValue();
            LwM2mResource shortIdResource = inst.getResource(CLIENT_SECURITY_SHORT_ID_RESOURCE_ID);
            int id = ((Long) shortIdResource.getValue()).intValue();

            if (id == shortId) {
                foundInstance = inst;
                break;
            }
        }

        if (foundInstance == null) {
            return false;
        }

        /* if found, update it with the provided keys */
        LwM2mResource[] resources = new LwM2mResource[3];
        resources[0] = LwM2mSingleResource.newIntegerResource(ClientSecurityObjectInstance.RES_ID_MODE,
                                                              ClientSecurityObjectInstance.MODE_PSK);
        resources[1] = LwM2mSingleResource.newBinaryResource(ClientSecurityObjectInstance.RES_ID_PUB_KEY_OR_ID,
                                                             key_id.getBytes());
        resources[2] = LwM2mSingleResource.newBinaryResource(ClientSecurityObjectInstance.RES_ID_SEC_KEY,
                                                             key.getBytes());

        WriteRequest writeRequest = new WriteRequest(Mode.UPDATE, CLIENT_SECURITY_OBJECT_ID, foundInstance.getId(),
                                                     resources);
        WriteResponse writeResponse = null;

        try {
            writeResponse = this.requestSender.send(client, writeRequest, null, DEFAULT_TIMEOUT);
        } catch (Exception e) {
            System.err.println("Could not send the write request to the client");
            System.err.println(e);
            return false;
        }

        if (!writeResponse.isSuccess()) {
            System.err.println("Unsuccessful write request to the client");
            return false;
        }
        return true;
    }

    private Boolean UpdateClientSecurityInstance(Registration client, int shortId, int oscore_instance) {
        ReadRequest request = new ReadRequest(CLIENT_SECURITY_OBJECT_ID);
        ReadResponse response = null;

        /* get all client security instances */
        try {
            response = this.requestSender.send(client, request, null, DEFAULT_TIMEOUT);
        } catch (Exception e) {
            System.err.println("Could not send the read request to the client");
            System.err.println(e);
            return false;
        }

        if (!response.isSuccess()) {
            System.err.println("Unsuccessful read request to the client");
            return false;
        }

        LwM2mObject object = (LwM2mObject) response.getContent();
        LwM2mObjectInstance foundInstance = null;

        /* try to find the instance for the given short client ID */
        for (Map.Entry<Integer, LwM2mObjectInstance> instance : object.getInstances().entrySet()) {
            LwM2mObjectInstance inst = instance.getValue();
            LwM2mResource shortIdResource = inst.getResource(CLIENT_SECURITY_SHORT_ID_RESOURCE_ID);
            int id = ((Long) shortIdResource.getValue()).intValue();

            if (id == shortId) {
                foundInstance = inst;
                break;
            }
        }

        if (foundInstance == null) {
            return false;
        }

        /* if found, update it */
        LwM2mResource[] resources = new LwM2mResource[2];
        resources[0] = LwM2mSingleResource.newIntegerResource(ClientSecurityObjectInstance.RES_ID_MODE,
                                                              ClientSecurityObjectInstance.MODE_NOSEC);
        resources[1] = LwM2mSingleResource.newObjectLinkResource(ClientSecurityObjectInstance.RES_ID_OSCORE_MODE,
                                                                 new ObjectLink(OSCORE_OBJECT_ID, oscore_instance));

        WriteRequest writeRequest = new WriteRequest(Mode.UPDATE, CLIENT_SECURITY_OBJECT_ID, foundInstance.getId(),
                                                     resources);
        WriteResponse writeResponse = null;

        try {
            writeResponse = this.requestSender.send(client, writeRequest, null, DEFAULT_TIMEOUT);
        } catch (Exception e) {
            System.err.println("Could not send the write request to the client");
            System.err.println(e);
            return false;
        }

        if (!writeResponse.isSuccess()) {
            System.err.println("Unsuccessful write request to the client");
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

        System.out.format("Setting client account for %s", endpoint);
        System.out.format("ID: %s Key: %s", key_id, key);

        /* if the client does not exist, create it */
        if (shortId < 0) {
            System.out.format("Creating client");
            shortId = (-shortId) + 1;
            if (!CreateClientInstance(client, shortId, endpoint)) {
                System.err.println("Could not create client on " + client);
                return -1;
            }
            newClient = true;
        }

        if (newClient) {
            System.out.format("Creating security instance for the client");
            /* need to create security instance */
            if (!CreateClientSecurityInstance(client, shortId, key_id, key)) {
                System.err.println("Could not create client security on " + client);
                return -1;
            }
            return shortId;
        }
        else {
            System.out.format("The client exists, updating security instance");
            if (!UpdateClientSecurityInstance(client, shortId, key_id, key)) {
                System.err.println("Could not update client security on " + client);
                return -1;
            }
            return shortId;
        }
    }

    private int SetClientAccount(Registration client, String endpoint, String master_salt,
                                 String master_secret, String recipient_id, String sender_id) {
        /* first check if the client with endpoint name exists in client */
        int shortId = GetClientShortID(client, endpoint);
        Boolean newClient = false;

        System.out.format("Setting OSCORE client account for %s\n", endpoint);
        System.out.format("salt: %s secret: %s\n", master_salt, master_secret);
        System.out.format("recepient: %s sender: %s\n", recipient_id, sender_id);

        /* if client does not exist, create it */
        if (shortId < 0) {
            System.out.println("Creating client");
            shortId = (-shortId) + 1;
            if (!CreateClientInstance(client, shortId, endpoint)) {
                System.err.println("Could not create client on " + client);
                return -1;
            }
            newClient = true;
        }

        int oscore_instance = CreateOscoreInstance(client, master_salt, master_secret, recipient_id, sender_id);
        if (oscore_instance < 0) {
            System.err.println("Could not create OSCORE instance on " + client);
            return -1;
        }

        if (newClient) {
            System.out.format("Creating security instance for the client");
            /* need to create security instance */
            if (!CreateClientSecurityInstance(client, shortId, oscore_instance)) {
                System.err.println("Could not create client security on " + client);
                return -1;
            }
            return shortId;
        }
        else {
            System.out.format("The client exists, updating security instance");
            if (!UpdateClientSecurityInstance(client, shortId, oscore_instance)) {
                System.err.println("Could not update client security on " + client);
                return -1;
            }
            return shortId;
        }
    }

    /**
     * Determines whether a client supports the OSCORE object.
     *
     * @param client    Client to test.
     * @return true if the object is supported, false otherwise.
     */
    private boolean SupportsOscore(Registration client) {
        return (client.getSupportedVersion(OSCORE_OBJECT_ID) != null);
    }
}
