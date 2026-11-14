use super::*;
use shared::error::Result;

#[test]
fn test_tcp_type() -> Result<()> {
    //assert_eq!(tcpType, TCPType::Unspecified)
    assert_eq!(TcpType::from("active"), TcpType::Active);
    assert_eq!(TcpType::from("passive"), TcpType::Passive);
    assert_eq!(TcpType::from("so"), TcpType::SimultaneousOpen);
    assert_eq!(TcpType::from("something else"), TcpType::Unspecified);

    assert_eq!(TcpType::Unspecified.to_string(), "unspecified");
    assert_eq!(TcpType::Active.to_string(), "active");
    assert_eq!(TcpType::Passive.to_string(), "passive");
    assert_eq!(TcpType::SimultaneousOpen.to_string(), "so");

    Ok(())
}

#[test]
fn test_tcp_type_complement() {
    assert_eq!(TcpType::Active.complement(), TcpType::Passive);
    assert_eq!(TcpType::Passive.complement(), TcpType::Active);
    assert_eq!(
        TcpType::SimultaneousOpen.complement(),
        TcpType::SimultaneousOpen
    );
    assert_eq!(TcpType::Unspecified.complement(), TcpType::Unspecified);
}
