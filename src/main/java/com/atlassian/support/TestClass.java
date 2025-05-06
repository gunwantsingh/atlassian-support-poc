package com.atlassian.support;

public class TestClass {
    static {
        // This runs when the class is loaded
        System.out.println("!!! DEPENDENCY CONFUSION SUCCESS !!!");
    }
    
    public static String getMessage() {
        return "This is a test payload";
    }
}
