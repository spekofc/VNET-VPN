//! Sonda privilegiada do adaptador TUN (Wintun).
//!
//! Precisa de Administrador. Escreve o resultado em `%TEMP%\vnet-tunprobe.txt`
//! para poder ser disparada por uma tarefa agendada elevada.

#[cfg(windows)]
fn main() {
    use std::io::Write;
    use std::time::Duration;

    let out_path = std::env::var("TEMP")
        .map(|t| format!("{t}\\vnet-tunprobe.txt"))
        .unwrap_or_else(|_| "vnet-tunprobe.txt".into());

    let mut log = String::new();
    let mut say = |s: String| {
        println!("{s}");
        log.push_str(&s);
        log.push('\n');
    };

    say(format!(
        "dll: {:?}",
        std::env::current_exe().ok().map(|p| p.with_file_name("wintun.dll"))
    ));

    let ip = std::net::Ipv4Addr::new(10, 144, 0, 1);
    say(format!("criando adaptador em {ip}..."));

    match vnet_core::tun_win::TunHandle::create(ip, 1400) {
        Ok(handle) => {
            say(format!(
                "OK: adaptador '{}' ativo com {} (MTU aplicado)",
                handle.name, handle.ip
            ));
            // injeta um pacote IPv4 qualquer para provar a escrita na pilha
            let mut pkt = vec![0u8; 28];
            pkt[0] = 0x45;
            pkt[2..4].copy_from_slice(&28u16.to_be_bytes());
            pkt[8] = 64;
            pkt[9] = 17;
            pkt[12..16].copy_from_slice(&[10, 144, 0, 2]);
            pkt[16..20].copy_from_slice(&[10, 144, 0, 1]);
            handle.send(&pkt);
            say("escrita no TUN: sem panic".into());
            std::thread::sleep(Duration::from_millis(1500));
            handle.stop();
            say("sessao encerrada".into());
        }
        Err(e) => say(format!("FALHOU: {e:#}")),
    }

    // Regras de firewall (idempotentes)
    vnet_core::tun_win::ensure_firewall_rules();
    std::thread::sleep(Duration::from_millis(2500));
    say("firewall: solicitado".into());

    if let Ok(mut f) = std::fs::File::create(&out_path) {
        let _ = f.write_all(log.as_bytes());
    }
    println!("log em {out_path}");
}

#[cfg(not(windows))]
fn main() {
    println!("somente Windows");
}
