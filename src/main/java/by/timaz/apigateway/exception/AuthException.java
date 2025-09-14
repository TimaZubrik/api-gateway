package by.timaz.apigateway.exception;

public class AuthException extends RuntimeException {
public AuthException(String operation) {
    super(operation + " failed");
}
}
