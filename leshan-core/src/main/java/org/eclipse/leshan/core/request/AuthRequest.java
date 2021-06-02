package org.eclipse.leshan.core.request;

import com.fasterxml.jackson.annotation.JsonProperty.Access;

import org.eclipse.leshan.core.request.exception.InvalidRequestException;
import org.eclipse.leshan.core.response.AuthResponse;

/**
 * The request to authorize access to client's resources
 */
public class AuthRequest implements UplinkRequest<AuthResponse> {

    private final Identity requester;
    private final Identity host;
    private final AccessGrant grants[];

    /**
     * Sets all fields.
     *
     * @param requester the Identity of the authorization requester
     * @param host the Identity of the host of the resources
     * @throws InvalidRequestException if the requester or host are null
     */
    public AuthRequest(Identity requester, Identity host, AccessGrant grants[]) throws InvalidRequestException {
        if (null == requester || null == host) {
            throw new InvalidRequestException("Requester and Host must be defined");
        }

        this.requester = requester;
        this.host = host;
        this.grants = grants;
    }

    @Override
    public void accept(UplinkRequestVisitor visitor) {
        visitor.visit(this);
    }

    public Identity getRequester() {
        return requester;
    }

    public Identity getHost() {
        return host;
    }

    /**
     * Returns the grants requested on the host resources.
     *
     * @return Array of requested grants
     */
    public AccessGrant[] getGrants() {
        return grants;
    }
}
