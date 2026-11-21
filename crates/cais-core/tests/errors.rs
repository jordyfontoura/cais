use cais_core::ErrorCode;

#[test]
fn stable_exit_classes_are_shared_by_client_and_server() {
    for (code, expected) in [
        (ErrorCode::Internal, 1),
        (ErrorCode::InvalidConfig, 2),
        (ErrorCode::InvalidRequest, 2),
        (ErrorCode::NotAuthorized, 3),
        (ErrorCode::PolicyDenied, 3),
        (ErrorCode::IncompatibleVersion, 4),
        (ErrorCode::Unsupported, 4),
        (ErrorCode::Transport, 5),
        (ErrorCode::Timeout, 5),
        (ErrorCode::Protocol, 5),
        (ErrorCode::Busy, 6),
        (ErrorCode::Conflict, 6),
        (ErrorCode::OperationFailed, 7),
        (ErrorCode::UnknownOutcome, 8),
    ] {
        assert_eq!(code.exit_code(), expected);
        assert_eq!(
            ErrorCode::from_exit_code(expected).unwrap().exit_code(),
            expected
        );
    }
    for unsupported in [0, 9, 255] {
        assert!(ErrorCode::from_exit_code(unsupported).is_none());
    }
}
