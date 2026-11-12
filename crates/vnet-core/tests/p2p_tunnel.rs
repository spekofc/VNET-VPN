//! Testes ponta a ponta da malha P2P, sem privilégios de administrador.
//!
//! Todos os nós rodam no mesmo processo, em portas UDP diferentes, e usam ids
//! fixos (o id real é por máquina). O caminho exercitado é o real: código →
//! HELLO → sala cifrada → PING/PONG → pacotes IP (injetados/capturados em vez
//! do TUN) → gossip de membros.

use std::time::Duration;

use vnet_core::p2p::{derive_ip, P2pConfig, Role, Snapshot, Tunnel};

fn wait_for<F>(tunnel: &Tunnel, timeout: Duration, mut ok: F) -> Option<Snapshot>
where
    F: FnMut(&Snapshot) -> bool,
{
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let snap = tunnel.snapshot();
        if ok(&snap) {
            return Some(snap);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Ids fixos e distintos — o IP virtual é derivado deles, então precisam
/// colidir o mínimo possível (a faixa tem 253 endereços).
fn ids() -> ([u8; 8], [u8; 8], [u8; 8]) {
    let a = [0xa1u8; 8];
    let mut b = [0xb2u8; 8];
    while derive_ip(b) == derive_ip(a) {
        b[7] = b[7].wrapping_add(1);
    }
    let mut c = [0xc3u8; 8];
    while derive_ip(c) == derive_ip(a) || derive_ip(c) == derive_ip(b) {
        c[7] = c[7].wrapping_add(1);
    }
    (a, b, c)
}

fn start(room: &str, password: &str, role: Role, node_id: [u8; 8]) -> Tunnel {
    Tunnel::start(P2pConfig {
        room: room.into(),
        password: password.into(),
        role,
        mtu: 1400,
        node_id: Some(node_id),
    })
    .expect("nó inicia")
}

fn ip_of(snap: &Snapshot) -> String {
    snap.virtual_ip.clone().expect("IP virtual publicado")
}

fn in_range(snap: &Snapshot) -> bool {
    match snap.virtual_ip.as_deref() {
        Some(ip) => {
            let o: Vec<u8> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
            ip.starts_with("10.144.0.") && o.len() == 4 && o[3] >= 2 && o[3] <= 254
        }
        None => false,
    }
}

/// Dois nós: um abre a rede, o outro entra com o código.
fn pair(room: &str, password: &str) -> (Tunnel, Tunnel, Snapshot, Snapshot) {
    std::env::set_var("VNET_SKIP_UPNP", "1");
    std::env::set_var("VNET_SKIP_STUN", "1");

    let (id_a, id_b, _) = ids();

    let host = start(room, password, Role::Host, id_a);
    let host_snap = wait_for(&host, Duration::from_secs(10), |s| {
        s.code.is_some() && (s.state == "Waiting" || s.state == "Connected")
    })
    .expect("nó publica o código");

    let endpoint = host_snap.code.clone().unwrap().parse().expect("IP:porta");
    let join = start(room, password, Role::Join { host: endpoint }, id_b);

    let join_snap = wait_for(&join, Duration::from_secs(10), |s| {
        s.state == "Connected" && !s.peers.is_empty()
    })
    .expect("segundo nó conecta");

    (host, join, host_snap, join_snap)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handshake_e_ping() {
    let (host, join, _host_snap, join_snap) = pair("teste-p2p", "segredo");

    assert_eq!(join_snap.peers.len(), 1, "quem entra vê o outro nó");

    let host_now = wait_for(&host, Duration::from_secs(10), |s| !s.peers.is_empty())
        .expect("quem abriu vê o novo nó");
    assert_eq!(host_now.peers.len(), 1);

    // A rede não tem dono: cada lado deriva o próprio IP, e são diferentes.
    assert!(in_range(&host_now), "IP do lado A na faixa: {:?}", host_now.virtual_ip);
    assert!(in_range(&join_snap), "IP do lado B na faixa: {:?}", join_snap.virtual_ip);
    assert_ne!(
        host_now.virtual_ip, join_snap.virtual_ip,
        "ids distintos não podem gerar o mesmo IP"
    );
    assert_eq!(host_now.role, "mesh");
    assert_eq!(join_snap.role, "mesh");

    host.ping(&host_now.peers[0].id);
    let pinged = wait_for(&host, Duration::from_secs(10), |s| {
        s.peers.first().and_then(|p| p.rtt_ms).is_some()
    })
    .expect("RTT medido");
    println!(
        "A={} B={} rtt={:?}ms",
        ip_of(&host_now),
        ip_of(&join_snap),
        pinged.peers[0].rtt_ms
    );

    join.disconnect();
    host.disconnect();
    tokio::time::sleep(Duration::from_millis(300)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pacote_ip_atravessa_cifrado() {
    let (host, join, _, join_snap) = pair("dados-p2p", "outrasenha");

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    join.capture_decrypted(tx);

    // IPv4 mínimo (UDP) saindo do IP do A para o IP derivado do B.
    let mut pkt = vec![0u8; 28];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&28u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&[10, 144, 0, 1]);
    let dst = ip_of(&join_snap);
    let dst_octets: Vec<u8> = dst.split('.').map(|o| o.parse().unwrap()).collect();
    pkt[16..20].copy_from_slice(&dst_octets);
    pkt[20..28].copy_from_slice(b"vnet-pkt");

    host.inject_packet(pkt.clone());

    let got = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("pacote chega ao outro nó")
        .expect("canal aberto");
    assert_eq!(got, pkt, "pacote íntegro depois de cifrar/decifrar");

    // Broadcast de descoberta LAN (Minecraft usa 224.0.2.60:4445).
    let mut bcast = pkt.clone();
    bcast[16..20].copy_from_slice(&[10, 144, 0, 255]);
    host.inject_packet(bcast.clone());
    let got_b = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("broadcast chega")
        .expect("canal aberto");
    assert_eq!(got_b, bcast);

    println!("dados: {} bytes entregues em {dst}", got.len());

    join.disconnect();
    host.disconnect();
    tokio::time::sleep(Duration::from_millis(300)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gossip_liga_o_terceiro_no() {
    std::env::set_var("VNET_SKIP_UPNP", "1");
    std::env::set_var("VNET_SKIP_STUN", "1");
    let (id_a, id_b, id_c) = ids();

    let a = start("malha-3", "senha3", Role::Host, id_a);
    let a_snap = wait_for(&a, Duration::from_secs(10), |s| s.code.is_some())
        .expect("A publica o código");
    let seed = a_snap.code.unwrap().parse().expect("IP:porta");

    // B entra direto em A.
    let b = start("malha-3", "senha3", Role::Join { host: seed }, id_b);
    wait_for(&b, Duration::from_secs(10), |s| !s.peers.is_empty()).expect("B conecta em A");

    // C também entra em A e deve descobrir B pelo gossip, sem código de B.
    let c = start("malha-3", "senha3", Role::Join { host: seed }, id_c);
    let c_snap = wait_for(&c, Duration::from_secs(15), |s| s.peers.len() >= 2)
        .expect("C aprende B pelo gossip");
    assert_eq!(c_snap.peers.len(), 2, "C vê A e B");
    assert_eq!(c_snap.state, "Connected");

    let b_sees_c = wait_for(&b, Duration::from_secs(15), |s| {
        s.peers.iter().any(|p| p.id == hex(id_c))
    })
    .expect("B também vê C");
    assert_eq!(b_sees_c.peers.len(), 2);

    let mut ips: Vec<String> = c_snap.peers.iter().map(|p| p.ip.clone()).collect();
    ips.sort();
    ips.dedup();
    assert_eq!(ips.len(), 2, "IPs distintos no terceiro nó");
    println!("malha: C vê {ips:?}");

    c.disconnect();
    b.disconnect();
    a.disconnect();
    tokio::time::sleep(Duration::from_millis(300)).await;
}

fn hex(id: [u8; 8]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lan_encontra_a_mesma_rede_sem_codigo() {
    std::env::set_var("VNET_SKIP_UPNP", "1");
    std::env::set_var("VNET_SKIP_STUN", "1");
    let (id_a, id_b, _) = ids();

    // Duas máquinas na mesma LAN, mesmo nome + senha, nenhuma sabe o IP da outra.
    let a = start("mesma-lan", "senha-lan", Role::Host, id_a);
    let b = start("mesma-lan", "senha-lan", Role::Host, id_b);

    let found = wait_for(&a, Duration::from_secs(15), |s| !s.peers.is_empty())
        .expect("HELLO em broadcast encontra o outro nó");
    let b_found = wait_for(&b, Duration::from_secs(15), |s| !s.peers.is_empty())
        .expect("os dois lados se encontram");

    assert_eq!(found.peers.len(), 1);
    assert_eq!(b_found.peers.len(), 1);
    println!(
        "LAN: A={} B={} sem código",
        ip_of(&found),
        ip_of(&b_found)
    );

    b.disconnect();
    a.disconnect();
    tokio::time::sleep(Duration::from_millis(300)).await;
}
