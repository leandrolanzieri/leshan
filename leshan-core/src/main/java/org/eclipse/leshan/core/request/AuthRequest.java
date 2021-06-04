package org.eclipse.leshan.core.request;

import com.fasterxml.jackson.annotation.JsonProperty.Access;

import org.eclipse.leshan.core.request.exception.InvalidRequestException;
import org.eclipse.leshan.core.response.AuthResponse;

/**
 * The request to authorize access to client's resources
 */
public class AuthRequest implements UplinkRequest<AuthResponse> {

    private final Identity requester;
    private final String hostEndpoint;
    private final AccessGrant grants[];
    private final Boolean credentials;

    /**
     * Sets all fields.
     *
     * @param requester the Identity of the authorization requester
     * @param host the Identity of the host of the resources
     * @throws InvalidRequestException if the requester or host are null
     */
    public AuthRequest(Identity requester, String hostEndpoint, AccessGrant grants[], Boolean credentials) throws InvalidRequestException {
        if (null == requester || null == hostEndpoint) {
            throw new InvalidRequestException("Requester and Host must be defined");
        }

        this.requester = requester;
        this.hostEndpoint = hostEndpoint;
        this.grants = grants;
        this.credentials = credentials;
    }

    @Override
    public void accept(UplinkRequestVisitor visitor) {
        visitor.visit(this);
    }

    public Identity getRequester() {
        return requester;
    }

    public String getHostEndpoint() {
        return hostEndpoint;
    }

    /**
     * Returns the grants requested on the host resources.
     *
     * @return Array of requested grants
     */
    public AccessGrant[] getGrants() {
        return grants;
    }

    public Boolean credentialsRequested() {
        return credentials;
    }
}
