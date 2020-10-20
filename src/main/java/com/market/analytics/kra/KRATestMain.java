package com.market.analytics.kra;

public class KRATestMain {
    public static void main(String[] args) throws Exception {
     //   KRASOAPGenerationTest.generate(DigestMethod.SHA512);
     //  KRASOAPValidationTest.validate("src/working/KRASOAPOutput.xml");
    //    KRASOAPValidationTest.validate("src/KRARealSample.xml");
        KRASOAPValidationTest.validate("src/main/java/com/market/analytics/kra/orig.kra.response");
    }
}
