//! Minimal TLS 1.2/1.3 ClientHello → SNI extractor.
//!
//! We don't need a full TLS parser; we just walk the record header, the
//! handshake header, and the ClientHello extensions until we find the
//! `server_name` extension (type 0), then return its hostname value. Any
//! parse failure (truncated buffer, wrong record type, no SNI extension)
//! returns `None` rather than erroring — the caller logs and moves on.
//!
//! Returns the *lowercased* SNI hostname so callers comparing against
//! their CONNECT target don't have to normalise.

/// TLS record content type for a handshake.
const RECORD_HANDSHAKE: u8 = 22;
/// Handshake message type for ClientHello.
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
/// Extension type for server_name.
const EXT_SERVER_NAME: u16 = 0;
/// Name type within the server_name extension: 0 = host_name.
const SNI_NAME_TYPE_HOST: u8 = 0;

/// Parse the SNI hostname out of a buffer that should begin with a TLS
/// record carrying a ClientHello. Returns `None` if the buffer isn't a
/// TLS handshake, doesn't carry SNI, or is malformed.
pub fn extract_sni(buf: &[u8]) -> Option<String> {
    let mut p = Parser::new(buf);

    // ── TLS record header (5 bytes) ──────────────────────────────────────
    let record_type = p.u8()?;
    if record_type != RECORD_HANDSHAKE {
        return None;
    }
    let _record_version = p.u16()?;
    let record_len = p.u16()? as usize;
    if record_len + 5 > buf.len() {
        // We don't have the full record buffered — we still try, since the
        // ClientHello + server_name often fit in the first few hundred
        // bytes. If our window cuts off mid-extension, the inner parse
        // will fail safely.
    }

    // ── Handshake header (4 bytes) ───────────────────────────────────────
    let handshake_type = p.u8()?;
    if handshake_type != HANDSHAKE_CLIENT_HELLO {
        return None;
    }
    let _handshake_len = p.u24()? as usize;

    // ── ClientHello ──────────────────────────────────────────────────────
    let _legacy_version = p.u16()?;
    p.skip(32)?; // random
    let session_id_len = p.u8()? as usize;
    p.skip(session_id_len)?;
    let cipher_suites_len = p.u16()? as usize;
    p.skip(cipher_suites_len)?;
    let compression_methods_len = p.u8()? as usize;
    p.skip(compression_methods_len)?;
    let _extensions_total_len = p.u16()? as usize;

    // ── Extensions ───────────────────────────────────────────────────────
    while !p.eof() {
        let ext_type = p.u16()?;
        let ext_len = p.u16()? as usize;
        if ext_type == EXT_SERVER_NAME {
            // server_name extension wraps a list of names.
            let _list_len = p.u16()?;
            let name_type = p.u8()?;
            if name_type != SNI_NAME_TYPE_HOST {
                return None;
            }
            let name_len = p.u16()? as usize;
            let name_bytes = p.take(name_len)?;
            return std::str::from_utf8(name_bytes)
                .ok()
                .map(str::to_ascii_lowercase);
        } else {
            p.skip(ext_len)?;
        }
    }

    None
}

struct Parser<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn eof(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self) -> Option<u32> {
        let b = self.take(3)?;
        Some(u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Some(slice)
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic TLS ClientHello with a single SNI extension. Used
    /// instead of a captured-on-the-wire byte string so the test is
    /// readable and easy to maintain.
    fn build_client_hello(sni: &str) -> Vec<u8> {
        // server_name extension body: list_len(2) + name_type(1) + name_len(2) + name
        let name_bytes = sni.as_bytes();
        let mut sni_ext = Vec::new();
        let list_inner_len = 1 + 2 + name_bytes.len(); // name_type + name_len + name
        sni_ext.extend_from_slice(&(list_inner_len as u16).to_be_bytes());
        sni_ext.push(0); // host_name
        sni_ext.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name_bytes);

        // Wrap in extension envelope: type(2) + length(2) + body
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes()); // type = server_name
        extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext);

        // ClientHello body
        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]); // legacy_version = TLS 1.2
        hello.extend_from_slice(&[0u8; 32]); // random
        hello.push(0); // session id len = 0
        hello.extend_from_slice(&2u16.to_be_bytes()); // cipher suites len
        hello.extend_from_slice(&[0x13, 0x01]); // a cipher suite
        hello.push(1); // compression methods len
        hello.push(0); // null compression
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        // Handshake header
        let mut handshake = Vec::new();
        handshake.push(HANDSHAKE_CLIENT_HELLO);
        let hello_len = hello.len() as u32;
        handshake.push(((hello_len >> 16) & 0xff) as u8);
        handshake.push(((hello_len >> 8) & 0xff) as u8);
        handshake.push((hello_len & 0xff) as u8);
        handshake.extend_from_slice(&hello);

        // TLS record header
        let mut record = Vec::new();
        record.push(RECORD_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x03]); // legacy record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        record
    }

    #[test]
    fn extracts_basic_sni() {
        let buf = build_client_hello("example.com");
        assert_eq!(extract_sni(&buf), Some("example.com".to_string()));
    }

    #[test]
    fn extracts_subdomain_sni() {
        let buf = build_client_hello("api.subdomain.example.com");
        assert_eq!(
            extract_sni(&buf),
            Some("api.subdomain.example.com".to_string())
        );
    }

    #[test]
    fn lowercases_mixed_case_sni() {
        let buf = build_client_hello("API.Example.COM");
        assert_eq!(extract_sni(&buf), Some("api.example.com".to_string()));
    }

    #[test]
    fn rejects_non_tls_data() {
        // Plain HTTP request bytes.
        let buf = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(extract_sni(buf), None);
    }

    #[test]
    fn handles_truncated_buffer() {
        let buf = build_client_hello("example.com");
        // Truncate before the SNI extension.
        let truncated = &buf[..20];
        assert_eq!(extract_sni(truncated), None);
    }

    #[test]
    fn handles_empty_buffer() {
        assert_eq!(extract_sni(&[]), None);
    }

    #[test]
    fn returns_none_when_no_sni_extension_present() {
        // A minimal ClientHello with zero extensions.
        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&0u16.to_be_bytes());
        hello.push(1);
        hello.push(0);
        hello.extend_from_slice(&0u16.to_be_bytes()); // no extensions

        let mut handshake = Vec::new();
        handshake.push(HANDSHAKE_CLIENT_HELLO);
        let l = hello.len() as u32;
        handshake.push(((l >> 16) & 0xff) as u8);
        handshake.push(((l >> 8) & 0xff) as u8);
        handshake.push((l & 0xff) as u8);
        handshake.extend_from_slice(&hello);

        let mut record = vec![RECORD_HANDSHAKE, 0x03, 0x03];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        assert_eq!(extract_sni(&record), None);
    }
}
