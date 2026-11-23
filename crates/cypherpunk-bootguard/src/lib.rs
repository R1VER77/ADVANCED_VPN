//! A constant fallback policy, independent of enrolled profiles, Python and slots.
//! It only removes connectivity after whole-device opt-in; it never opens a VPN.

pub const POLICY: &str = r#"add table inet cypherpunk_vpn
delete table inet cypherpunk_vpn
table inet cypherpunk_vpn {
 chain output { type filter hook output priority -100; policy drop;
  oifname "lo" accept
  meta skuid 0 ip daddr 255.255.255.255 udp sport 68 udp dport 67 accept
 }
 chain forward { type filter hook forward priority -100; policy drop;
 }
}
"#;

/// Unknown or damaged settings cannot cancel a previously requested guard.
/// Absence of both opt-in sources means the device has never requested this guard.
pub fn required(
    marker_present_or_unreadable: bool,
    preferences: Result<Option<&[u8]>, ()>,
) -> bool {
    if marker_present_or_unreadable {
        return true;
    }
    match preferences {
        Ok(None) => false,
        Ok(Some(bytes)) => match serde_json::from_slice::<serde_json::Value>(bytes) {
            Ok(serde_json::Value::Object(value)) => match value.get("mode") {
                None => false,
                Some(serde_json::Value::String(mode)) if mode == "applications" => false,
                _ => true,
            },
            _ => true,
        },
        Err(()) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opt_in_survives_missing_corrupt_or_app_only_preferences() {
        for bytes in [
            None,
            Some(&b"corrupt"[..]),
            Some(&b"{\"mode\":\"applications\"}"[..]),
        ] {
            assert!(required(true, Ok(bytes)));
        }
        assert!(required(true, Err(())));
    }

    #[test]
    fn legacy_whole_device_and_unknown_settings_block() {
        assert!(required(false, Ok(Some(b"{\"mode\":\"whole-device\"}"))));
        for bytes in [
            b"corrupt".as_slice(),
            b"[]",
            b"{\"mode\":false}",
            b"{\"mode\":\"future\"}",
        ] {
            assert!(required(false, Ok(Some(bytes))));
        }
        assert!(required(false, Err(())));
    }

    #[test]
    fn no_whole_device_request_does_not_change_host_networking() {
        assert!(!required(false, Ok(None)));
        assert!(!required(false, Ok(Some(b"{}"))));
        assert!(!required(false, Ok(Some(b"{\"mode\":\"applications\"}"))));
    }

    #[test]
    fn fallback_never_opens_a_carrier_established_flow_or_dns_path() {
        assert_eq!(POLICY.matches("policy drop").count(), 2);
        assert!(!POLICY.contains("established"));
        assert!(!POLICY.contains("dport 53"));
        assert!(!POLICY.contains("cpvpn0"));
    }
}
