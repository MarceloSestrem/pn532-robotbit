/**
 * PN532 (SPI) – Leitor/Gravador MIFARE Classic (13,56 MHz)
 * Blocos em português para MakeCode (micro:bit)
 * Pinos padrão: MOSI=P13, MISO=P12, SCK=P14, CS=P15
 *
 * Funções expostas:
 *  - Iniciar módulo PN532
 *  - Ler ID do cartão
 *  - Ler dados do cartão (48 bytes: blocos 8–10)
 *  - Escrever dados <texto> (48 bytes: blocos 8–10)
 *  - Desligar RF (opcional)
 */
//% color="#275C6B" weight=100 icon="\uf2bb" block="Leitor PN532"
namespace PN532_SED {

    // ---------- Constantes PN532 ----------
    const PN532_PREAMBLE = 0x00
    const PN532_STARTCODE1 = 0x00
    const PN532_STARTCODE2 = 0xFF
    const PN532_POSTAMBLE = 0x00

    const PN532_HOSTTOPN532 = 0xD4
    const PN532_PN532TOHOST = 0xD5

    // Comandos
    const CMD_SAMConfiguration = 0x14
    const CMD_InListPassiveTarget = 0x4A
    const CMD_InDataExchange = 0x40

    // SPI: instruções
    const SPI_STATREAD = 0x02
    const SPI_DATAWRITE = 0x01
    const SPI_DATAREAD = 0x03

    // Status
    const STATUS_READY = 0x01

    // MIFARE Classic
    const MIFARE_CMD_AUTH_A = 0x60
    const MIFARE_CMD_READ = 0x30
    const MIFARE_CMD_WRITE = 0xA0
    const DEFAULT_KEY: number[] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]

    // Blocos escolhidos (3 * 16 = 48 bytes)
    const DATA_BLOCKS: number[] = [8, 9, 10]
    const AUTH_BLOCK = 11 // autentica no setor que contém 8–10 (chave A)

    // Estado
    let g_uid: number[] = [] // UID do cartão detectado (4, 7 ou 10 bytes; usamos os 4 primeiros p/ auth)

    // ---------- Baixo nível SPI / Frame ----------

    function csLow() { pins.digitalWritePin(DigitalPin.P15, 0) }
    function csHigh() { pins.digitalWritePin(DigitalPin.P15, 1) }

    function spiWriteByte(b: number) { pins.spiWrite(b & 0xFF) }
    function spiReadByte(): number { return pins.spiWrite(0x00) }

    function waitReady(timeoutMs = 100): boolean {
        // Poll de status até ficar pronto
        const start = control.millis()
        while (control.millis() - start < timeoutMs) {
            csLow()
            spiWriteByte(SPI_STATREAD)
            const stat = spiReadByte()
            csHigh()
            if (stat == STATUS_READY) return true
            basic.pause(1)
        }
        return false
    }

    function writeFrame(payload: number[]) {
        // Envia frame host->PN532: [PRE, START1, START2, LEN, LCS, TFI, ...DATA, DCS, POST]
        const len = 1 + payload.length // TFI + payload
        const lcs = (~len + 1) & 0xFF
        let sum = PN532_HOSTTOPN532
        for (let i = 0; i < payload.length; i++) sum = (sum + payload[i]) & 0xFF
        const dcs = (~(sum) + 1) & 0xFF

        csLow()
        spiWriteByte(SPI_DATAWRITE)
        spiWriteByte(PN532_PREAMBLE)
        spiWriteByte(PN532_STARTCODE1)
        spiWriteByte(PN532_STARTCODE2)
        spiWriteByte(len)
        spiWriteByte(lcs)
        spiWriteByte(PN532_HOSTTOPN532)
        for (let i = 0; i < payload.length; i++) spiWriteByte(payload[i])
        spiWriteByte(dcs)
        spiWriteByte(PN532_POSTAMBLE)
        csHigh()
    }

    function readAck(timeoutMs = 100): boolean {
        if (!waitReady(timeoutMs)) return false
        // ACK tem 6 bytes: 00 00 FF 00 FF 00
        csLow()
        spiWriteByte(SPI_DATAREAD)
        let ack: number[] = []
        for (let i = 0; i < 6; i++) ack.push(spiReadByte())
        csHigh()
        return (ack[0] == 0x00 && ack[1] == 0x00 && ack[2] == 0xFF && ack[3] == 0x00 && ack[4] == 0xFF && ack[5] == 0x00)
    }

    function readResponse(timeoutMs = 100): number[] {
        if (!waitReady(timeoutMs)) return null
        csLow()
        spiWriteByte(SPI_DATAREAD)

        // Ler cabeçalho 00 00 FF
        let pre = spiReadByte()
        let start1 = spiReadByte()
        let start2 = spiReadByte()
        if (!(pre == 0x00 && start1 == 0x00 && start2 == 0xFF)) {
            csHigh()
            return null
        }
        let len = spiReadByte()
        let lcs = spiReadByte()
        // checagem LEN+LCS == 0
        if (((len + lcs) & 0xFF) != 0) { csHigh(); return null }

        // payload: TFI + data[len-1]
        let tfi = spiReadByte()
        let data: number[] = []
        let sum = tfi
        for (let i = 0; i < (len - 1); i++) {
            let b = spiReadByte()
            data.push(b)
            sum = (sum + b) & 0xFF
        }
        let dcs = spiReadByte()
        let post = spiReadByte()
        csHigh()

        if (((sum + dcs) & 0xFF) != 0) return null
        if (tfi != PN532_PN532TOHOST) return null
        return data // data[0] é o código do comando + 1 (echo), ex.: 0x41 para 0x40
    }

    // ---------- Comandos de alto nível PN532 ----------

    function samConfiguration(): boolean {
        // CMD 0x14: [Mode, Timeout, IRQ]
        // Mode=0x01 (Normal), Timeout=0x14 (~50ms), IRQ=0x01 (usar IRQ, irrelevante aqui)
        writeFrame([CMD_SAMConfiguration, 0x01, 0x14, 0x01])
        if (!readAck(200)) return false
        const resp = readResponse(200)
        return resp != null && resp[0] == (CMD_SAMConfiguration + 1)
    }

    function inListPassiveTarget106A(): number[] {
        // Procurar 1 target, 106 kbps (Type A)
        writeFrame([CMD_InListPassiveTarget, 0x01, 0x00])
        if (!readAck(200)) return null
        const resp = readResponse(300)
        // resp: [0x4B, NbTg, Tg1, SENS_RES(2), SEL_RES, NFCIDLen, UID...]
        if (!resp || resp[0] != (CMD_InListPassiveTarget + 1)) return null
        if (resp.length < 3 || resp[1] < 1) return null
        // extrair UID
        // estrutura mínima: [0x4B, 0x01, Tg, ATQA1, ATQA2, SAK, UIDLen, UID...]
        let idx = 2
        let tg = resp[idx++] // alvo lógico (geralmente 1)
        if (resp.length < idx + 3) return null
        idx += 3 // pula ATQA(2) + SAK(1)
        if (resp.length < idx + 1) return null
        const uidLen = resp[idx++]
        if (resp.length < idx + uidLen) return null
        let uid: number[] = []
        for (let i = 0; i < uidLen; i++) uid.push(resp[idx + i])
        g_uid = uid
        return uid
    }

    function mifareAuthA(block: number, key: number[], uid: number[]): boolean {
        // InDataExchange: [Tg=1, AUTH_A, block, key[6], uid[4]]
        let frame: number[] = [CMD_InDataExchange, 0x01, MIFARE_CMD_AUTH_A, block]
        for (let i = 0; i < 6; i++) frame.push(key[i] & 0xFF)
        // usar 4 bytes menos significativos da UID p/ auth
        for (let i = 0; i < 4; i++) frame.push(uid[i] & 0xFF)

        writeFrame(frame)
        if (!readAck(200)) return false
        const resp = readResponse(300)
        // resposta de sucesso: [0x41, Status(=0x00), ...]
        return resp != null && resp[0] == (CMD_InDataExchange + 1) && resp[1] == 0x00
    }

    function mifareReadBlock(block: number): number[] {
        // InDataExchange: [Tg=1, READ, block]
        writeFrame([CMD_InDataExchange, 0x01, MIFARE_CMD_READ, block])
        if (!readAck(200)) return null
        const resp = readResponse(300)
        // sucesso: [0x41, 0x00, 16 bytes]
        if (!resp || resp[0] != (CMD_InDataExchange + 1) || resp[1] != 0x00) return null
        if (resp.length < 2 + 16) return null
        let out: number[] = []
        for (let i = 0; i < 16; i++) out.push(resp[2 + i] & 0xFF)
        return out
    }

    function mifareWriteBlock(block: number, data16: number[]): boolean {
        // InDataExchange: [Tg=1, WRITE, block, 16 bytes]
        if (!data16 || data16.length != 16) return false
        let frame: number[] = [CMD_InDataExchange, 0x01, MIFARE_CMD_WRITE, block]
        for (let i = 0; i < 16; i++) frame.push(data16[i] & 0xFF)

        writeFrame(frame)
        if (!readAck(300)) return false
        const resp = readResponse(600)
        // sucesso: [0x41, 0x00]
        return resp != null && resp[0] == (CMD_InDataExchange + 1) && resp[1] == 0x00
    }

    function ensureCard(): boolean {
        // procura cartão e guarda UID em g_uid
        const uid = inListPassiveTarget106A()
        return uid != null
    }

    // ---------- Alto nível: ler/escrever 48 bytes nos blocos 8–10 ----------

    function read48(): string {
        if (!ensureCard()) return null
        // autentica no bloco de trailer do setor (11)
        if (!mifareAuthA(AUTH_BLOCK, DEFAULT_KEY, g_uid)) return null
        let all: number[] = []
        for (const b of DATA_BLOCKS) {
            const data = mifareReadBlock(b)
            if (!data) return null
            all = all.concat(data)
        }
        // converter para string
        let s = ""
        for (let i = 0; i < all.length; i++) s += String.fromCharCode(all[i])
        return s
    }

    function write48(txt: string): boolean {
        if (!ensureCard()) return false
        if (!mifareAuthA(AUTH_BLOCK, DEFAULT_KEY, g_uid)) return false
        // preparar 48 bytes (preencher com espaços)
        let bytes: number[] = []
        for (let i = 0; i < txt.length && i < 48; i++) bytes.push(txt.charCodeAt(i) & 0xFF)
        while (bytes.length < 48) bytes.push(32) // espaço
        let offset = 0
        for (const b of DATA_BLOCKS) {
            const chunk = bytes.slice(offset, offset + 16)
            if (!mifareWriteBlock(b, chunk)) return false
            offset += 16
        }
        return true
    }

    // ---------- Utilidades públicas ----------

    function getUIDNumber(): number {
        if (!ensureCard()) return 0
        // monta número com até 5 bytes (compat com seu fluxo anterior)
        let a = 0
        const take = Math.min(5, g_uid.length)
        for (let i = 0; i < take; i++) {
            a = a * 256 + (g_uid[i] & 0xFF)
        }
        return a
    }

    // ---------- Blocos MakeCode (em português) ----------

    //% block="Iniciar módulo PN532 (SPI)"
    //% weight=100
    export function Init() {
        // Padrão deste código: MOSI=P13, MISO=P12, SCK=P14, CS=P15
        pins.spiPins(DigitalPin.P13, DigitalPin.P12, DigitalPin.P14)
        pins.spiFormat(8, 0)
        pins.spiFrequency(1000000) // 1 MHz recomendado
        csHigh() // CS inativo alto
        // SAMConfiguration para ativar RF e leitura de targets
        samConfiguration()
    }

    //% block="Ler ID do cartão (UID)"
    //% weight=95
    export function getID(): number {
        const id = getUIDNumber()
        return id
    }

    //% block="Ler dados do cartão (48B blocos 8–10)"
    //% weight=90
    export function read(): string {
        const s = read48()
        return s ? s : ""
    }

    //% block="Escrever dados %text (48B blocos 8–10)"
    //% text
    //% weight=85
    export function write(text: string) {
        const ok = write48(text)
        if (!ok) {
            serial.writeLine("Falha ao escrever (auth/IO).")
        } else {
            serial.writeLine("Escrita concluída.")
        }
    }

    //% block="Desligar RF"
    //% weight=80
    export function AntennaOff() {
        // Com PN532, poderíamos usar RFConfiguration ou baixar o módulo de modo (SAM), mas
        // para simplicidade, apenas imprime; se quiser, posso adicionar comando RFConfig aqui.
        serial.writeLine("RF off (placeholder).")
    }
}
