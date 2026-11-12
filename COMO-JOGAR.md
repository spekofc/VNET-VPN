# VNET VPN — como jogar com um PC longe

## 1. Arquivo

```
apps\desktop\src-tauri\target\release\vnet-desktop.exe
```

O `wintun.dll` **precisa ficar na mesma pasta do exe** (já está).
Se copiar o exe para outro PC, copie o `wintun.dll` junto.

## 2. Abrir como administrador

O adaptador virtual (Wintun) só é criado com permissão de administrador.

- O próprio app pede elevação ao conectar (UAC): aceite e ele reabre sozinho já conectado.
- Se recusar o UAC, o app conecta mas mostra
  `Adaptador virtual inativo` — o jogo **não** vai enxergar a rede.

Confira depois de conectar: `Gerenciador de dispositivos → Adaptadores de rede → VNET`.

## 3. A rede não tem dono

A rede é só **nome + senha**. Não existe "PC que hospeda": todos são membros
iguais, e cada PC tem um IP virtual fixo, derivado da própria máquina
(ex.: `10.144.0.206`). O IP não muda entre sessões.

- Quem cria a rede primeiro fica em **Aguardando** até alguém entrar.
- **Mesma rede local (Wi-Fi/cabo)**: basta criar com o mesmo nome e senha — os
  PCs se acham sozinhos por broadcast, **sem código nenhum**.
- Qualquer membro pode convidar: o app mostra `Código para convidar` em todo PC.
- Quem entra recebe a lista dos outros membros e conecta direto neles
  (não passa pelo PC de quem convidou).
- A faixa virtual é `10.144.0.0/24`, fora de outras faixas de VPN de malha
  (`25/8`, `26/8`, `100.64/10`), então dá para manter outra VPN instalada
  ao mesmo tempo.

## 4. Primeiro PC (PC A)

1. **Rede → Criar rede**: nome (ex.: `casa`), senha, **Criar**.
2. O app mostra o **Código para convidar** e o IP virtual do PC A.
3. O painel mostra dois códigos:
   - **Mesma rede (LAN)**: `192.168.x.y:7000` — só funciona no mesmo roteador.
   - **Pela internet**: `SEU_IP_PÚBLICO:7000` — precisa de **um ajuste no roteador**.

### Abrir a porta no roteador (uma vez só, em qualquer PC que for o primeiro contato)

No roteador (aba *Port Forwarding* / *Encaminhamento de portas* / *Virtual Server*):

| Campo | Valor |
|---|---|
| Protocolo | UDP |
| Porta externa | 7000 |
| Porta interna | 7000 |
| IP destino | o IP da máquina na LAN (o app mostra, ex.: `192.168.10.25`) |

Se o PC A ficar com 7000, quem estiver fora entra por esse código. Depois disso
a malha se espalha sozinha: outros membros podem convidar com o próprio código.

O app já cria as regras no firewall do Windows (UDP 7000–7100 e 4445) quando roda elevado.

## 5. Segundo PC (PC B, longe)

1. **Rede → Conectar à rede**.
2. Nome: igual ao do PC A.
3. Senha: a mesma.
4. **Código de um membro**: o `PÚBLICO:7000` (ou o `192.168.x.y:7000` se estiverem no mesmo roteador).
5. **Conectar**. Em segundos o status vira **Online** e aparece o membro com o IP virtual dele.

## 6. Abrir o jogo

**PC A** — abra o mundo e faça `Esc → Abrir para LAN`.
O chat mostra a porta (ex.: `Local game hosted on port 51234`).

**PC B** — `Multijogador → Conexão direta`:

```
10.144.0.206:51234
```

(O IP do outro PC aparece no rodapé do card da rede, com botão de copiar.)

Lan discovery automático (`224.0.2.60`) também é encaminhado, mas **conexão direta é o caminho garantido**.

O mesmo vale para outros jogos LAN: use o IP virtual do PC que abriu o jogo e a porta do jogo.

## 7. Se não conectar

| Sintoma | Causa provável | Correção |
|---|---|---|
| Fica em **Conectando** e cai com erro | porta não chega ao outro PC | confira o *port forward* UDP 7000 → IP da LAN; teste com o firewall do roteador desligado |
| Conecta mas nada aparece no jogo | adaptador virtual inativo | rodar como administrador; ver seção 2 |
| Conecta, ping OK, jogo não vê | rede VNET marcada como Pública | `Set-NetConnectionProfile -InterfaceAlias VNET -NetworkCategory Private` (o app tenta sozinho) |
| IP público muda a cada sessão | IP dinâmico do provedor | use DDNS ou confira o código no app antes de enviar |
| Terceiro membro não aparece | gossip ainda propagando | espere ~5 s; se persistir, dê o código de qualquer membro a ele |

O IP público e o código mudam quando o provedor troca o IP ou quando a porta UDP muda — sempre copie o código **atual** do app.

## 8. Limites conhecidos

- Sem UPnP e sem port forward em **nenhum** membro, não há conexão pela internet
  (não existe servidor de rendezvous).
- Basta **um** membro alcançável para o primeiro contato; os demais entram por ele
  e depois falam direto entre si.
- Se dois membros estiverem atrás de NAT simétrico, o tráfego entre eles passa
  pelo membro que os alcança (relay cifrado) — funciona, mas com a latência dele.
- Chat, pastas compartilhadas e iniciar com o Windows ainda são maquete na UI.
