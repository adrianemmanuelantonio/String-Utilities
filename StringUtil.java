package com.marinebenefits.mbr_android.Utility;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * StringUtil
 * Collection of string utilities that you can use on your apps
 *
 * @author  Adrian Emmanuel Antonio
 * @version 1.0
 * @since   2020-05-30
 */

public class StringUtil {
    private static final String NO_SPECIAL_CHARACTERS = "[^a-zA-Z0-9]";
    private static final String EMAIL_ADDRESS_REGEX = "^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,6}$";
    private static final String BLANK_CHARACTER = "";
    private static final String WHITESPACE = " ";
    private static final int CAMEL_CASE_THRESHOLD = 1;

    /**
     * This method checks if the given string is camel case or not
     * it can also check if a word from a sentence is a camel case
     * @param source This is the string that needs to be verified if camel case
     * @return boolean This returns if the string is camel case or not
     */
    public static boolean isCamelCase(String source) {
        int camelCaseTrigger;
        for (String splitWord : source.split(WHITESPACE)) {
            // Removes special characters for shorter loops
            splitWord = splitWord.replaceAll(NO_SPECIAL_CHARACTERS, BLANK_CHARACTER);
            camelCaseTrigger = 0;
            for (int characterIndex = 0; characterIndex < splitWord.length(); characterIndex++) {
                if (characterIndex == 0) {
                    camelCaseTrigger++;
                }
                else {
                    // Checks if the character is upper case
                    if (Character.isUpperCase(splitWord.charAt(characterIndex))) {
                        camelCaseTrigger++;
                    }
                }
            }

            // If the value is 2 or more, the source string is camel case
            if (camelCaseTrigger > CAMEL_CASE_THRESHOLD) {
                return true;
            }
        }
        return false;
    }

    /**
     * This method creates a random string
     * @param desiredLength This is the desired length of the random string
     * @return String This returns the generated random string
     */
    public static String createRandomString(int desiredLength) {
        Random generator = new Random();
        StringBuilder randomStringBuilder = new StringBuilder();
        int randomLength = generator.nextInt(desiredLength);
        char tempChar;
        for (int i = 0; i < randomLength; i++){
            tempChar = (char) (generator.nextInt(96) + 32);
            randomStringBuilder.append(tempChar);
        }
        return randomStringBuilder.toString();
    }

    /**
     * This method creates the MD5 hash of a given string
     * @param source This is the string that needs to be converted
     * @return String This returns the generated MD5 hash
     */
    public static String createMd5Hash(String source) {
        final String MD5 = "MD5";
        try {
            // Create MD5 Hash
            MessageDigest digest = java.security.MessageDigest
                    .getInstance(MD5);
            digest.update(source.getBytes());
            byte messageDigest[] = digest.digest();

            // Create Hex String
            StringBuilder hexString = new StringBuilder();
            for (byte aMessageDigest : messageDigest) {
                String h = Integer.toHexString(0xFF & aMessageDigest);
                while (h.length() < 2)
                    h = "0" + h;
                hexString.append(h);
            }
            return hexString.toString();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return BLANK_CHARACTER;
    }

    /**
     * This method checks if the given string is a valid email address
     * @param source This is the string that needs to be verified
     * @return boolean Returns if the string is a valid email address or not
     */
    public static boolean isValidEmailAddress(String source) {
        Pattern pattern = Pattern.compile(EMAIL_ADDRESS_REGEX, Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(source);
        return matcher.matches();
    }

    /**
     * This method add new lines on a given string
     * @param source The string that needs to appended with new lines
     * @return String Returns the generated string with new lines
     */
    public static String addNewLineOnString(String source) {
        String[] temp = source.split(WHITESPACE);
        StringBuilder paddedString = new StringBuilder(BLANK_CHARACTER);
        int index = 0;
        if (temp.length > Constants.Generic.ONE) {
            for (String word : temp) {
                if (index < temp.length - 1) {
                    paddedString.append(word).append("\n");
                } else {
                    paddedString.append(word);
                }
                index++;
            }
        } else {
            paddedString = new StringBuilder(source);
        }
        return paddedString.toString();
    }
}
