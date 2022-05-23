
package com.cards.auth.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class UrlMetaData {

    public final String AUTHENTICATE_AND_AUTHORIZE_USER;
    public final String GET_IP_DETAILS;
    private static final String dynamicUrl = "{}/api/";
    public UrlMetaData(@Value(value = "${version}") String version,
                       @Value(value = "${url.context.productcontext}") String PRODUCT_CONTEXT) {
        PRODUCT_CONTEXT = PRODUCT_CONTEXT+dynamicUrl + version;
        this.AUTHENTICATE_AND_AUTHORIZE_USER = PRODUCT_CONTEXT + "/product/userAuthDetails";
        this.GET_IP_DETAILS = PRODUCT_CONTEXT + "/product/getIpDetails";
    }
}
