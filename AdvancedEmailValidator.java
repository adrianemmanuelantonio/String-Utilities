package com.example.emailtester;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * AdvancedEmailValidator
 * Validates a given email address with advanced filters
 *
 * Author: Adrian Emmanuel Antonio

 * Valid Name Part in Email Address with Example:
 * 1. lowercase Latin letters: abcdefghijklmnopqrstuvwxyz
 * 2. uppercase Latin letters: ABCDEFGHIJKLMNOPQRSTUVWXYZ
 * 3. digits: 0123456789
 * 4. special characters: !#$%&’*+-/=?^_{|}~
 * 5. dot: . (not first or last character or repeated unless quoted)
 * 6. space punctuation such as: "(),:;<>@[\] (with some restrictions)
 * 7. comments: () (are allowed within parentheses, e.g. (comment)xyz@example.com)
 *
 * Valid Domain Part in Email Address with Example:
 * 1. lowercase Latin letters: abcdefghijklmnopqrstuvwxyz
 * 2. uppercase Latin letters: ABCDEFGHIJKLMNOPQRSTUVWXYZ
 * 3. digits: 0123456789
 * 4. hyphen: - (not first or last character)
 * 5. can contain IP address surrounded by square brackets: test@[192.168.2.4] or test@[IPv6:2018:db8::1]
 */

class AdvancedEmailValidator {
    private static final String IP_ADDRESS_REGEX = "(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])";
    private static final String IP_V6_REGEX = "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))";
    private static final String LETTERS_NUMBERS_REGEX = "^[a-zA-Z0-9]*$";
    private static final String EMAIL_ILLEGAL_CHARS = "[<>;]";
    private static final String CONTINUOUS_DOTS_REGEX = "([.])\\1";

    private static final String DOUBLE_QUOTES = "\"";
    private static final String AT_SIGN_STRING = "@";
    private static final String BLANK_SPACE = " ";
    private static final String OPEN_BRACKET = "[";
    private static final String HYPHEN = "-";
    private static final String CLOSE_BRACKET = "]";
    private static final String BLANK = "";
    private static final String IPV6_TAG = "ipv";
    private static final String DOT = ".";

    private static final int ZERO = 0;
    private static final int ONE = 1;
    private static final int TWO = 2;

    private static final char AT_SIGN_CHAR = '@';
    private static final char DOT_CHAR = '.';
    private static final char DOUBLE_QUOTES_CHAR = '"';

    /**
     * Validates if the given email address is valid
     * Uses advance filters and validations
     * @param source The email that needs to be validated
     * @return Boolean the status if it's valid or not
     */
    static boolean validate(String source) {
        if (source == null) return false;
        source = source.trim();

        // Validate if the email has @ character
        if (!source.contains(AT_SIGN_STRING)) {
            return false;
        }

        // Automatic rejection if the email has a space
        // Will vary in system's requirements
        if (source.contains(BLANK_SPACE)) {
            return false;
        }

        // Normal Email Addresses only has @ unless quoted
        if (validateNumberOfAtSigns(source)) {
            return false;
        }

        // Parse the email for the name and domain part using the @ sign
        String[] parsedSource = source.split(AT_SIGN_STRING);
        String local = parsedSource[ZERO];
        String domain = parsedSource[ONE];

        if (instructionsForMultipleAtSignsInsideQuotes(parsedSource)) {
            return true;
        }

        Boolean insideDoubleQuuotes = validateInsideDoubleQuuotes(source, local);
        if (insideDoubleQuuotes != null) {
            return insideDoubleQuuotes;
        }

        // Check for invalid characters
        // Pass of inside double quotes
        if (containsIllegals(source)) {
            // If it's inside double quotes it will be valid
            return local.startsWith(DOUBLE_QUOTES) && local.endsWith(DOUBLE_QUOTES);
        }

        if (checkForInvalidFirstAndLastCharacters(local, domain)) {
            return false;
        }

        if (validateIfIpOrIpV6Address(domain)) {
            return false;
        }

        if (checkForContinuousDots(source)) {
            return false;
        }

        if (!isOnlyLettersAndNumbers(domain)) {
            return isIPAddress(domain) || isIpV6Address(domain);
        }

        return true;
    }

    private static boolean instructionsForMultipleAtSignsInsideQuotes(String[] parsedSource) {
        // If the email has multiple @ sign
        if (parsedSource.length > TWO) {
            StringBuilder tempLocal = new StringBuilder();
            for (int i=ZERO; i<parsedSource.length - ONE; i++) {
                tempLocal.append(parsedSource[i]);
            }

            return tempLocal.toString().startsWith(DOUBLE_QUOTES) && tempLocal.toString().endsWith(DOUBLE_QUOTES);
        }
        return false;
    }

    private static Boolean validateInsideDoubleQuuotes(String source, String local) {
        // All symbols will pass inside double quotes in local part of email
        if (local.startsWith(DOUBLE_QUOTES) && local.endsWith(DOUBLE_QUOTES)) {
            return true;
        }

        if (source.contains("\"")) {
            if (getCharacterCount(local, DOUBLE_QUOTES_CHAR) > ONE) {
                boolean foundQuote = false;
                for (int i = ONE; i<local.length(); i++) {
                    if (local.charAt(i) == DOUBLE_QUOTES_CHAR && local.charAt(i-1) == DOT_CHAR) {
                        foundQuote = true;
                    } else if (foundQuote) {
                        if (local.charAt(i) == DOUBLE_QUOTES_CHAR && local.charAt(i + 1) != DOT_CHAR) {
                            return false;
                        }
                    }
                }
                if (!foundQuote) return false;
            } else {
                return false;
            }
        }
        return null;
    }

    private static boolean checkForInvalidFirstAndLastCharacters(String local, String domain) {
        // Check if index 0 or last index is - which is invalid in local
        if (local.startsWith(HYPHEN) || local.endsWith(HYPHEN)) {
            return true;
        }

        // Check if index 0 or last index is - which is invalid in domain
        if (domain.startsWith(HYPHEN) || domain.endsWith(HYPHEN)) {
            return true;
        }

        // Check if index 0 or last index is . which is invalid in local
        if (local.startsWith(DOT) || local.endsWith(DOT)) {
            return true;
        }

        // Check if index 0 or last index is . which is invalid in domain
        return domain.startsWith(DOT) || domain.endsWith(DOT);
    }

    private static boolean validateIfIpOrIpV6Address(String domain) {
        // Check if the domain is IP Address but not enclosed in []
        if (isIPAddress(domain)) {
            // TODO: asdad
            if (!domain.startsWith(OPEN_BRACKET) && !domain.endsWith(CLOSE_BRACKET)) {
                return true;
            }
        }

        // Verify if the domain is in IP address format
        if (domain.startsWith(OPEN_BRACKET) && domain.endsWith(CLOSE_BRACKET)) {
            if (!isIPAddress(domain)) {
                // Check if it's an IPv6 address
                return !isIpV6Address(domain);
            }
        } else {
            return domain.contains(OPEN_BRACKET) || domain.contains(CLOSE_BRACKET);
        }

        return false;
    }

    private static boolean validateNumberOfAtSigns(String source) {
        // Finding of multiple @ sign in the email
        // Can be vaid if enclosed in " "
        int count = ZERO;
        for(int i = ZERO; i < source.length(); i++) {
            if(source.charAt(i) == AT_SIGN_CHAR) {
                count++;
            }
        }

        if (count > ONE) {
            return !isCharacterInsideQuotes(source, AT_SIGN_CHAR);
        }
        return false;
    }

    private static boolean checkForContinuousDots(String source) {
        Pattern pattern = Pattern.compile(CONTINUOUS_DOTS_REGEX, Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(source);
        return matcher.find();
    }

    private static boolean containsIllegals(String toExamine) {
        Pattern pattern = Pattern.compile(EMAIL_ILLEGAL_CHARS);
        Matcher matcher = pattern.matcher(toExamine);
        return matcher.find();
    }

    private static boolean isIPAddress(String source) {
        String target = source.replace(OPEN_BRACKET, BLANK).replace(CLOSE_BRACKET, BLANK);
        if (target.length() == ZERO) return false;
        Pattern pattern = Pattern.compile(IP_ADDRESS_REGEX);
        Matcher matcher = pattern.matcher(target);
        return matcher.matches();
    }

    private static boolean isIpV6Address(String source) {
        String target = source.toLowerCase().replace(OPEN_BRACKET, BLANK).replace(CLOSE_BRACKET, BLANK).replace(IPV6_TAG, BLANK);
        if (target.length() == ZERO) return false;
        Pattern pattern = Pattern.compile(IP_V6_REGEX);
        Matcher matcher = pattern.matcher(target);
        return matcher.matches();
    }

    private static boolean isOnlyLettersAndNumbers(String source) {
        String target = source.toLowerCase().replace(HYPHEN, BLANK).replace(CLOSE_BRACKET, BLANK).replace(DOT, BLANK);
        if (target.length() == ZERO) return false;
        Pattern pattern = Pattern.compile(LETTERS_NUMBERS_REGEX);
        Matcher matcher = pattern.matcher(target);
        return matcher.matches();
    }

    private static int getCharacterCount(String source, char target) {
        int count = 0;
        for (int i = ZERO; i<source.length(); i++) {
            if (source.charAt(i) == target) {
                count++;
            }
        }
        return count;
    }

    private static boolean isCharacterInsideQuotes(String source, char target) {
        boolean triggeredQuotes = false;
        boolean insideQuotes = false;
        int numberOfQuotes = ZERO;
        for(int i = ZERO; i<source.length(); i++) {
            if (source.charAt(i) == DOUBLE_QUOTES_CHAR) {
                triggeredQuotes = !triggeredQuotes;
                numberOfQuotes++;
            }

            if (source.charAt(i) == target && triggeredQuotes) {
                insideQuotes = true;
            }
        }
        return numberOfQuotes > ONE && insideQuotes;
    }
}
