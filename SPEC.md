# VNET — especificação do protocolo

Versão 3 (malha sem dono). Implementação de referência: `crates/vnet-core/src/p2p.rs`.

Objetivo: dois ou mais PCs em redes diferentes formarem uma LAN virtual cifrada sem servidor central, sem conta e sem hierarquia. A rede é definida por um par **nome + senha**; qualquer PC que saiba os dois é membro pleno.

---

## 1. Identidade da rede

```
ikm        = SHA-256("vnet-room-ikm"  ‖ nome ‖ 0x00 ‖ senha)
room_hash  = SHA-256("vnet-room-hash" ‖ nome ‖ 0x00 ‖ senha)[0..16]
chave      = HKDF-SHA256(ikm = ikm, salt = room_hash, info = "vnet-p2p-data-v2", 32 bytes)
```

- `room_hash` é o discriminador da rede: **todo** payload começa com esses 16 bytes e todo pacote cujo prefixo não bater é descartado antes de qualquer decodificação.
- `room_hash` também é o AAD do AEAD, então um pacote válido de outra rede não decifra aqui.
- O nome é normalizado pelo cliente (trim, tamanho mínimo 3) e usado byte a byte em UTF-8. Nome e senha diferenciam maiúsculas de minúsculas.

Consequência de projeto: não há troca de chaves por sessão. A senha é a raiz de confiança e o compromisso dela expõe o histórico. Use senha longa e específica da rede.

## 2. Identidade do nó e endereçamento

Cada máquina tem um id persistente de 8 bytes, gerado aleatoriamente na primeira execução e guardado em `%LOCALAPPDATA%\vnet\node_id` (hex de 16 caracteres). A variável `VNET_NODE_ID` sobrepõe o arquivo — útil para rodar duas instâncias na mesma máquina.

```
ip_octeto = 2 + (be16(SHA-256("vnet-node-ip" ‖ id)[0..2]) mod 253)
ip        = 10.144.0.<ip_octeto>          # .2 … .254
```

| Constante | Valor |
|---|---|
| Faixa virtual | `10.144.0.0/24` |
| Broadcast virtual | `10.144.0.255` |
| Aceito como IP anunciado | `10.144.0.1 – 10.144.0.254` |

A faixa evita `10.0.0.0/8`, `192.168.0.0/16`, `25.0.0.0/8`, `26.0.0.0/8` e `100.64.0.0/10`, para conviver com outras VPNs de malha, CGNAT e LANs domésticas instaladas na mesma máquina.

## 3. Enquadramento

```
 0        4      5                                    N
 +--------+------+------------------------------------+
 | "VNP2" | tipo |            payload                 |
 +--------+------+------------------------------------+
```

Magic de 4 bytes `56 4E 50 32`. Um byte de tipo. Sem campo de tamanho: o limite é o datagrama UDP (MTU 1400 no adaptador).

| Tipo | Nome | Payload mínimo |
|---|---|---|
| `0x01` | HELLO | 28 |
| `0x03` | DATA | 60 |
| `0x04` | PING | 32 |
| `0x05` | PONG | 32 |
| `0x06` | BYE | 24 |
| `0x07` | PEERS | 16 |

Todos os payloads começam com `room_hash` (16 bytes).

## 4. Mensagens

### 4.1 HELLO

```
 0        16       24       28
 +--------+--------+--------+
 | room   |  id    | ip(4)  |
 +--------+--------+--------+
```

Simétrico: não existe ACK nem papel de servidor. Ao receber um HELLO válido de um id desconhecido, o nó registra o remetente, responde com o próprio HELLO e envia `PEERS`. A resposta só é emitida quando o remetente é novo (ou mudou de porta), para não gerar ping-pong.

### 4.2 PEERS (gossip)

```
 0        16      24      28      32      34
 +--------+-------+-------+-------+-------+
 | room   | id(8) | ip(4) | ep(4) | porta |
 +--------+-------+-------+-------+-------+
          \_______ entrada de 18 bytes, repetida n vezes _______/
```

Cada entrada descreve um membro conhecido: id, IP virtual anunciado e o endpoint de transporte **observado por quem envia**. O IP virtual é informativo — o receptor recalcula do id se o anunciado estiver fora da faixa. Endpoints que não passam no filtro de transporte (§7) são ignorados.

Quem recebe tenta HELLO para cada membro novo, no máximo uma vez a cada 8 s por id. É assim que um terceiro nó entra sem receber código de ninguém.

### 4.3 DATA

```
 0      16      24        32        44              44+n
 +------+-------+---------+---------+----------------+
 | room | orig  | seq(8)  | nonce   | ciphertext     |
 +------+-------+---------+---------+----------------+
```

- `orig` — id de quem originou o pacote (não muda no repasse).
- `seq` — contador monotônico por origem, incrementado a cada pacote IP.
- `nonce` — 12 bytes aleatórios por pacote.
- `ciphertext` — ChaCha20-Poly1305 do pacote IP, com `room_hash` como AAD.

O pacote IP original fica no claro só depois de decifrar; o destino é lido do cabeçalho IPv4 (offset 16). Origem igual ao próprio id é descartada (eco).

### 4.4 PING / PONG

```
 +------+-------+----------+
 | room |  id   | carimbo  |
 +------+-------+----------+
```

`PONG` devolve o carimbo original; o RTT é `agora - carimbo`. PING a cada 3 s em cada vizinho; 20 s sem tráfego remove o membro.

### 4.5 BYE

```
 +------+-------+
 | room |  id   |
 +------+-------+
```

Enviado no `disconnect` para todos os vizinhos, que removem o membro imediatamente em vez de esperar timeout.

## 5. Descoberta na LAN

Enquanto o nó está sozinho, a cada 3 s ele envia seu HELLO para:

- `255.255.255.255`, portas 7000–7100;
- broadcast direcionado da interface principal (`x.y.z.255`), mesmas portas.

O socket é aberto com `SO_BROADCAST`. Dois PCs na mesma rede física com o mesmo nome e senha se encontram sem nenhum código. Depois que existe ao menos um vizinho, a varredura para e o gossip assume.

Portas: tenta `7000..=7100` em ordem; se todas estiverem ocupadas, usa uma porta efêmera (o código de convite carrega a porta real).

## 6. Repasse (relay)

Um nó repassa o datagrama cifrado intacto — nunca recifra — nas seguintes condições:

| Destino do pacote IP | Ação |
|---|---|
| o próprio nó | entrega ao adaptador TUN |
| broadcast (`10.144.0.255` ou `224.0.0.0/4`) | entrega local **e** replica a todos os vizinhos |
| IP de um vizinho direto | envia só para ele |
| desconhecido | replica a todos os vizinhos, exceto quem enviou |

Deduplicação por `(origem, seq)` numa janela de 8192 entradas: o mesmo datagrama nunca é processado duas vezes nem volta pelo caminho de onde veio.

Consequência: em malha parcial (dois nós atrás de NAT simétrico), o tráfego passa por um terceiro nó que alcança os dois. O relay só vê ciphertext.

## 7. Filtro de transporte

Máquinas com várias interfaces (outras VPNs de malha, VirtualBox, WSL,
adaptadores desconectados) fazem o broadcast sair por todas — e o eco chega com
um endereço que não leva a lugar nenhum. Antes de registrar um vizinho, a origem
do datagrama precisa passar:

| Origem | Aceita? |
|---|---|
| loopback, link-local | sim |
| `25.0.0.0/8`, `26.0.0.0/8` | não |
| `100.64.0.0/10` | não |
| privada (`10/8`, `172.16/12`, `192.168/16`) | só se compartilhar os dois primeiros octetos com a interface principal |
| unspecified, broadcast, multicast | não |
| pública | sim |

O mesmo filtro vale para endpoints aprendidos via `PEERS`.

## 8. NAT

- **STUN** (RFC 5389, *binding request*) no próprio socket do túnel, antes de abrir o laço de recepção: até 3 tentativas por servidor, 700 ms cada, 5 s de teto. Resultado é o endpoint público exibido no código de convite.
- **UPnP IGD**: `M-SEARCH` em `239.255.255.250:1900`, leitura do `controlURL` e `AddPortMapping` UDP porta interna = externa. Roda em paralelo ao handshake e não bloqueia; ao sair, `DeletePortMapping`.
- Sem UPnP e sem encaminhamento manual, um nó só é alcançável se estiver na mesma LAN ou atrás de NAT cone com mapeamento já aberto.

## 9. Temporizações

| Parâmetro | Valor |
|---|---|
| Repetição de HELLO para o seed | 400 ms |
| Desistência do seed | 20 s (estado `Failed`) |
| Remoção de vizinho mudo | 20 s |
| PING | 3 s |
| Gossip | 2 s |
| Nova tentativa para membro aprendido | 8 s |
| Varredura de LAN | 3 s |
| Publicação de snapshot para a UI | 1 s |

## 10. Estados observáveis

`Connecting` → `Waiting` (sem seed, sozinho) → `Connected` (≥ 1 vizinho) · `Failed` (seed inalcançável) · `Disconnected`.

O estado nunca volta de `Failed` para `Connected` na mesma sessão: uma falha exige novo `connect`.
