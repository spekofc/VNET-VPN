//! Sonda de UPnP: despeja as respostas SSDP e tenta mapear uma porta UDP.

use std::time::Duration;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(7899);

    println!("IP local: {:?}", vnet_core::p2p::local_ipv4());

    let sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let msg = concat!(
        "M-SEARCH * HTTP/1.1\r\n",
        "HOST: 239.255.255.250:1900\r\n",
        "MAN: \"ssdp:discover\"\r\n",
        "MX: 2\r\n",
        "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n",
        "\r\n"
    );
    for target in [
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
        "upnp:rootdevice",
        "ssdp:all",
    ] {
        let body = msg.replace(
            "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
            target,
        );
        let _ = sock.send_to(body.as_bytes(), "239.255.255.250:1900").await;
        let mut buf = [0u8; 4096];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                break;
            }
            match tokio::time::timeout(left, sock.recv_from(&mut buf)).await {
                Ok(Ok((n, from))) => {
                    println!("--- resposta de {from} (ST {target})\n{}", String::from_utf8_lossy(&buf[..n]));
                }
                _ => break,
            }
        }
    }

    let Some(ip) = vnet_core::p2p::local_ipv4() else {
        println!("sem rota padrão");
        return;
    };
    let ok = vnet_core::p2p::upnp::map_port(port, ip, port).await;
    println!("map_port({port}) => {ok}");
}
