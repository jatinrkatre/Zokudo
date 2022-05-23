package com.cards.auth.enums;

public enum Activity {

    LOGIN("LOGIN"),
    FAILED_LOGIN("FAILED_LOGIN"),
    LOGOUT("LOGOUT"),
    VISIT("VISIT"),
    ;

    private String value;

    Activity(String value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return value;
    }

    public String getValue() {
        return value;
    }

    public static Activity getEnum(String value) {

        if (value == null)
            throw new IllegalArgumentException();
        for (Activity v : values())
            if (value.equalsIgnoreCase(v.getValue()))
                return v;
        throw new IllegalArgumentException();
    }
}
