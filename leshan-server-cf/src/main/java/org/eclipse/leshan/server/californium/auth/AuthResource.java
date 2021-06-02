package org.eclipse.leshan.server.californium.auth;

import static org.eclipse.leshan.core.californium.ResponseCodeUtil.toCoapResponseCode;

import java.net.InetSocketAddress;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.leshan.core.californium.LwM2mCoapResource;
import org.eclipse.leshan.core.request.AccessGrant;
import org.eclipse.leshan.core.request.AuthRequest;
import org.eclipse.leshan.core.request.Identity;
import org.eclipse.leshan.core.response.AuthResponse;
import org.eclipse.leshan.core.response.SendableResponse;
import org.eclipse.leshan.server.auth.AuthHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthResource extends LwM2mCoapResource {

    private static final Logger LOG = LoggerFactory.getLogger(AuthResource.class);

    private static final String RESOURCE_NAME = "ac";

    private static final String QUERY_PARAM_HOST = "h=";

    private final AuthHandler authHandler;

    public AuthResource(AuthHandler handler) {
        super(RESOURCE_NAME);
        getAttributes().addResourceType("lwm2m.auth");

        authHandler = handler;
    }

    @Override
    public void handleGET(CoapExchange exchange) {
        Request request = exchange.advanced().getRequest();
        LOG.trace("GET received in auth interface: {}", request);

        Response response = new Response(ResponseCode.CONTENT);
        response.setPayload("Test: Authorization Endpoint");
        exchange.respond(response);
    }

    @Override
    public void handlePOST(CoapExchange exchange) {
        Request request = exchange.advanced().getRequest();
        LOG.trace("POST received: {}", request);

        // We should only accept Confirmable messages in this interface
        if (!Type.CON.equals(request.getType())) {
            handleInvalidRequest(exchange, "CON CoAP type expected");
            return;
        }

        if (request.getPayload() == null) {
            System.err.println("Request with no payload");
            exchange.respond(ResponseCode.BAD_REQUEST);
        }

        Identity host = null;

        // Get the request parameters
        for (String param: request.getOptions().getUriQuery()) {
            if (param.startsWith(QUERY_PARAM_HOST)) {
                String hostAddr = param.substring(QUERY_PARAM_HOST.length());
                System.out.println("Host: " + hostAddr);
                try {
                    URI uri = new URI(hostAddr);
                    InetSocketAddress addr = new InetSocketAddress(uri.getHost(), uri.getPort());
                    host = Identity.unsecure(addr);
                } catch (Exception e) {
                    System.err.println("Could not parse host");
                    exchange.respond(ResponseCode.BAD_REQUEST);
                    return;
                }
            }
        }

        if (null == host) {
            System.err.println("Host is mandatory in Authorization requests");
            exchange.respond(ResponseCode.BAD_REQUEST);
        }

        // Decode the requested access
        CBORObject cbor = null;
        try {
            cbor = CBORObject.DecodeFromBytes(request.getPayload());
        } catch (Exception e) {
            System.err.println("Could not parse payload");
            exchange.respond(ResponseCode.BAD_REQUEST);
        }

        System.out.println("Payload: " + cbor);

        if (cbor.getType() != CBORType.Map) {
            System.err.println("The payload should be a map");
            exchange.respond(ResponseCode.BAD_REQUEST);
        }

        List<AccessGrant> grants = new ArrayList<>();
        for (Map.Entry<CBORObject, CBORObject> entry : cbor.getEntries()) {
            grants.add(new AccessGrant(entry.getKey(), (int) entry.getValue().AsNumber().ToInt16Checked()));
        }

        AccessGrant[] grantsArray = new AccessGrant[grants.size()];
        grantsArray = grants.toArray(grantsArray);

        // Get sender identity
        Identity clientIdentity = extractIdentity(request.getSourceContext());

        // Prepare an authorization request to the handler
        AuthRequest authRequest = new AuthRequest(clientIdentity, host, grantsArray);

        System.out.println(authRequest);

        SendableResponse<AuthResponse> sendableResponse = authHandler.auth(authRequest);
        AuthResponse response = sendableResponse.getResponse();
    
        exchange.respond(toCoapResponseCode(response.getCode()), response.getErrorMessage());
        sendableResponse.sent();
    }
}
