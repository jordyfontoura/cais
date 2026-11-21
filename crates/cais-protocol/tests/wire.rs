use cais_core::{CaisError, ErrorCode};
use cais_protocol::*;
use serde_json::json;

#[test]
fn complete_success_and_error_results_roundtrip() {
    for result in [
        Outcome::Success {
            data: json!({"deployment":false}),
        },
        Outcome::Error {
            error: CaisError::new(
                ErrorCode::NotAuthorized,
                "Project is unavailable to this identity.",
            ),
        },
    ] {
        let response = Response {
            protocol_version: 1,
            request_id: "request-1".into(),
            result,
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &response).unwrap();
        let decoded: Response = read_frame(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded.request_id, "request-1");
        assert_eq!(
            serde_json::to_value(decoded).unwrap(),
            serde_json::to_value(response).unwrap()
        );
    }
}

#[test]
fn refuses_zero_oversized_truncated_or_untrusted_frames() {
    for bytes in [
        vec![0, 0, 0, 0],
        (MAX_FRAME as u32 + 1).to_be_bytes().to_vec(),
        vec![0, 0, 0, 5, b'{'],
    ] {
        assert!(read_frame::<Request>(&mut bytes.as_slice()).is_err());
    }
    let mut bytes = Vec::new();
    write_frame(
        &mut bytes,
        &json!({"protocol_version":1,"request_id":"x","caller":"root","operation":{"name":"list"}}),
    )
    .unwrap();
    assert!(read_frame::<Request>(&mut bytes.as_slice()).is_err());
}

#[test]
fn detects_pollution_and_incompatible_peers() {
    assert_eq!(
        read_hello(&mut b"banner!!".as_slice()).unwrap_err().code,
        ErrorCode::Protocol
    );
    let mut bytes = Vec::new();
    let hello = Hello {
        protocol_versions: vec![99],
        ..Hello::default()
    };
    send_hello(&mut bytes, &hello).unwrap();
    assert_eq!(
        read_hello(&mut bytes.as_slice()).unwrap_err().code,
        ErrorCode::IncompatibleVersion
    );
}

#[test]
fn refuses_unknown_operation_and_unknown_result_fields() {
    for operation in [
        json!({"name":"list","caller":"root"}),
        json!({"name":"capabilities","x":1}),
    ] {
        let mut bytes = Vec::new();
        write_frame(
            &mut bytes,
            &json!({"protocol_version":1,"request_id":"x","operation":operation}),
        )
        .unwrap();
        assert!(read_frame::<Request>(&mut bytes.as_slice()).is_err());
    }
    let mut bytes = Vec::new();
    write_frame(
        &mut bytes,
        &json!({"protocol_version":1,"request_id":"x","operation":{"name":"exec","command":"id"}}),
    )
    .unwrap();
    assert!(read_frame::<Request>(&mut bytes.as_slice()).is_err());
    let mut bytes = Vec::new();
    write_frame(&mut bytes, &json!({"protocol_version":1,"request_id":"x","result":{"outcome":"success","data":{},"extra":true}})).unwrap();
    assert!(read_frame::<Response>(&mut bytes.as_slice()).is_err());
}
