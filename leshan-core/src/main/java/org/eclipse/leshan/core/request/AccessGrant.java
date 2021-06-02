package org.eclipse.leshan.core.request;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.eclipse.leshan.core.node.LwM2mPath;

public class AccessGrant {

    private static Integer READ     = 1 << 0;
    private static Integer WRITE    = 1 << 1;
    private static Integer EXECUTE  = 1 << 2;
    private static Integer DELETE   = 1 << 3;
    private static Integer CREATE   = 1 << 4;
    private static Integer DISCOVER = 1 << 5;

    private LwM2mPath path;
    private final Integer access;

    public AccessGrant(CBORObject id, Integer access) {
        if (id.getType() != CBORType.Array) {
            throw new RuntimeException("The ID should be an array");
        }

        this.path = null;

        Collection<CBORObject> values = id.getValues();
        if (values.size() != 1 && values.size() != 2) {
            throw new RuntimeException("The ID should be an array of 2 integers");
        }

        for (CBORObject obj: values) {
            if (obj.getType() != CBORType.Integer) {
                throw new RuntimeException("The ID should be an array of integers");
            }

            if (this.path == null) {
                this.path = new LwM2mPath(obj.AsNumber().ToInt16Checked());
            } else {
                int objId = this.path.getObjectId();
                this.path = new LwM2mPath(objId, obj.AsNumber().ToInt16Checked());
            }
        }

        this.access = access;
    }

    public LwM2mPath getPath() {
        return path;
    }

    public Integer getAccess() {
        return access;
    }

    public Boolean hasRead() {
        return (access & READ) != 0;
    }

    public Boolean hasWrite() {
        return (access & WRITE) != 0;
    }

    public Boolean hasExecute() {
        return (access & EXECUTE) != 0;
    }

    public Boolean hasDelete() {
        return (access & DELETE) != 0;
    }

    public Boolean hasCreate() {
        return (access & CREATE) != 0;
    }

    public Boolean hasDiscover() {
        return (access & DISCOVER) != 0;
    }

}
