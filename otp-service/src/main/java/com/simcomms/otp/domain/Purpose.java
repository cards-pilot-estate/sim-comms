package com.simcomms.otp.domain;

/** Why a code is sent. Each purpose has its own SMS text; a proof names the purpose it was issued for. */
public enum Purpose {
    SIGN_IN("%s is your code to sign in to your %s card application. It is valid for 10 minutes. Do not share it with anyone."),
    STEP_UP("%s is your code to confirm a change to your %s card application. It is valid for 10 minutes. Do not share it with anyone.");

    private final String template;

    Purpose(String template) {
        this.template = template;
    }

    public String sms(String code, String brand) {
        // DLT-style: the sender id is six letters.
        String sender = brand.toUpperCase().replaceAll("[^A-Z]", "");
        return String.format(template, code, brand) + " -" + sender.substring(0, Math.min(6, sender.length()));
    }
}
