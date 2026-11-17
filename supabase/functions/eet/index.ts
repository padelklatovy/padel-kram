// EET 2.0 – odeslání evidované tržby (rozhraní v4, SOAP 1.1 + WS-Security, XML-DSig RSA-SHA256, exc-c14n)
// Specifikace: eet.gov.cz – „Formát a struktura údajů o evidované tržbě a popis datového rozhraní…“ v1.2
// Pokladní certifikát (.p12) se nahrává z aplikace (Nastavení → EET) do tabulky eet_secret (čte jen service role).
import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2";
import forge from "npm:node-forge@1.3.1";

const ENDPOINTS = {
  playground: "https://pg.trzbyeet.gov.cz/eet/services/EETServiceSOAP/v4",
  produkce: "https://trzbyeet.gov.cz/eet/services/EETServiceSOAP/v4",
};
const NS = {
  soap: "http://schemas.xmlsoap.org/soap/envelope/",
  wsse: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
  wsu: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
  ds: "http://www.w3.org/2000/09/xmldsig#",
  tns: "http://fs.gov.cz/eet/schema/v4",
};
const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (b: unknown, s = 200) =>
  new Response(JSON.stringify(b), { status: s, headers: { ...cors, "Content-Type": "application/json" } });

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/"/g, "&quot;");

function pragueDateTime(d: Date): string {
  const parts = Object.fromEntries(
    new Intl.DateTimeFormat("en-GB", {
      timeZone: "Europe/Prague", year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23", timeZoneName: "longOffset",
    }).formatToParts(d).map((p) => [p.type, p.value]),
  );
  let off = (parts.timeZoneName as string).replace("GMT", "");
  if (!off) off = "+00:00";
  return `${parts.year}-${parts.month}-${parts.day}T${parts.hour}:${parts.minute}:${parts.second}${off}`;
}
const amount = (n: number) => {
  const v = Math.round(n * 100) / 100;
  return v.toFixed(2) === "-0.00" ? "0.00" : v.toFixed(2);
};

function parseP12(b64: string, pass: string) {
  const p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(forge.util.decode64(b64)), pass);
  const keyBag = (p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag] ?? [])[0]
    ?? (p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag] ?? [])[0];
  if (!keyBag) throw new Error("V souboru .p12 není soukromý klíč");
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] ?? [];
  const key = keyBag.key;
  const cert = certBags.map((b: any) => b.cert).find((c: any) => c.publicKey.n.equals(key.n)) ?? certBags[0]?.cert;
  if (!cert) throw new Error("V souboru .p12 není certifikát");
  return { key, cert };
}

async function loadCert(admin: any) {
  const { data } = await admin.from("eet_secret").select("*").eq("id", 1).maybeSingle();
  if (!data) throw new Error("Není nahraný pokladní certifikát (Nastavení → EET)");
  return parseP12(data.p12_b64, data.pass);
}

function tempCert(selftest: boolean) {
  if (selftest) {
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = "01";
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date(Date.now() + 86400000);
    const attrs = [{ name: "commonName", value: "CZ00000019" }];
    cert.setSubject(attrs); cert.setIssuer(attrs);
    cert.sign(keys.privateKey, forge.md.sha256.create());
    return { key: keys.privateKey, cert };
  }
  throw new Error("selftest only");
}

const sha256b64 = (s: string) => {
  const md = forge.md.sha256.create(); md.update(s, "utf8");
  return forge.util.encode64(md.digest().bytes());
};

function buildEnvelope(h: Record<string, string>, d: Record<string, string>, key: any, cert: any) {
  // Atributy v kanonickém (abecedním) pořadí – dokument je rovnou v exc-c14n tvaru
  const attrs = (o: Record<string, string>) =>
    Object.keys(o).sort().map((k) => ` ${k}="${esc(o[k])}"`).join("");
  const body =
    `<soap:Body xmlns:soap="${NS.soap}" xmlns:wsu="${NS.wsu}" wsu:Id="Body">` +
    `<tns:Trzba xmlns:tns="${NS.tns}">` +
    `<tns:Hlavicka${attrs(h)}></tns:Hlavicka>` +
    `<tns:Data${attrs(d)}></tns:Data>` +
    `</tns:Trzba></soap:Body>`;
  const signedInfo =
    `<ds:SignedInfo xmlns:ds="${NS.ds}">` +
    `<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod>` +
    `<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod>` +
    `<ds:Reference URI="#Body"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms>` +
    `<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>` +
    `<ds:DigestValue>${sha256b64(body)}</ds:DigestValue></ds:Reference></ds:SignedInfo>`;
  const md = forge.md.sha256.create(); md.update(signedInfo, "utf8");
  const sigValue = forge.util.encode64(key.sign(md));
  const certB64 = forge.util.encode64(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes());
  return `<?xml version="1.0" encoding="UTF-8"?>` +
    `<soap:Envelope xmlns:soap="${NS.soap}"><soap:Header>` +
    `<wsse:Security xmlns:wsse="${NS.wsse}" xmlns:wsu="${NS.wsu}" soap:mustUnderstand="1">` +
    `<wsse:BinarySecurityToken EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ` +
    `ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" wsu:Id="X509-cert">${certB64}</wsse:BinarySecurityToken>` +
    `<ds:Signature xmlns:ds="${NS.ds}" Id="SIG-1">${signedInfo}<ds:SignatureValue>${sigValue}</ds:SignatureValue>` +
    `<ds:KeyInfo><wsse:SecurityTokenReference><wsse:Reference URI="#X509-cert" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/></wsse:SecurityTokenReference></ds:KeyInfo>` +
    `</ds:Signature></wsse:Security></soap:Header>${body}</soap:Envelope>`;
}

function parseResponse(xml: string) {
  const attr = (el: string, a: string) => {
    const m = xml.match(new RegExp(`<[^>]*:?${el}\\b[^>]*\\s${a}="([^"]*)"`));
    return m ? m[1] : null;
  };
  const pok = attr("Potvrzeni", "pok");
  if (pok) return { ok: true, pok, test: attr("Potvrzeni", "test") === "true", varovani: [...xml.matchAll(/Varovani[^>]*kod_varov="(\d+)"[^>]*>([^<]*)</g)].map((m) => `${m[1]}: ${m[2]}`) };
  const kod = attr("Chyba", "kod");
  const txt = xml.match(/Chyba[^>]*>([^<]*)</)?.[1] ?? xml.slice(0, 300);
  return { ok: false, kod: kod ? Number(kod) : null, chyba: txt };
}

async function send(endpoint: string, envelope: string) {
  const r = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "text/xml; charset=utf-8", SOAPAction: "" },
    body: envelope,
    signal: AbortSignal.timeout(8000),
  });
  return await r.text();
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const url = Deno.env.get("SUPABASE_URL")!;
    const authHeader = req.headers.get("Authorization") ?? "";
    const userClient = createClient(url, Deno.env.get("SUPABASE_ANON_KEY")!, { global: { headers: { Authorization: authHeader } } });
    const admin = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
    const body = await req.json().catch(() => ({}));
    const { data: settings } = await admin.from("settings").select("*").single();
    const { data: isStaff } = await userClient.rpc("is_staff");
    if (!isStaff) return json({ error: "Nemáte oprávnění" }, 403);
    const { data: isAdmin } = await userClient.rpc("is_admin");

    // Test spojení a schématu na playgroundu s dočasným certifikátem
    if (body.action === "selftest") {
      const { key, cert } = tempCert(true);
      const env = buildEnvelope(
        { uuid_zpravy: crypto.randomUUID(), dat_odesl: pragueDateTime(new Date()), prvni_zaslani: "true", overeni: "true" },
        { eic_popl: settings.dic || "CZ00000019", id_jednotky: settings.eet_unit || "1", id_pokl: settings.eet_cashier || "KRAM01", porad_cis: "TEST-1", dat_trzby: pragueDateTime(new Date()), celk_trzba: "1.00" },
        key, cert);
      const raw = await send(ENDPOINTS.playground, env);
      return json({ odpoved: parseResponse(raw), raw: raw.slice(0, 2000) });
    }
    if (body.action === "upload_cert") {
      if (!isAdmin) return json({ error: "Jen pro administrátora" }, 403);
      const { cert } = parseP12(body.p12_b64, body.pass ?? "");
      const subject = cert.subject.attributes.map((a: any) => `${a.shortName}=${a.value}`).join(", ");
      await admin.from("eet_secret").upsert({ id: 1, p12_b64: body.p12_b64, pass: body.pass ?? "", uploaded_at: new Date().toISOString() });
      await admin.from("settings").update({ cert_subject: subject, cert_valid_to: cert.validity.notAfter.toISOString() }).eq("id", 1);
      return json({ ok: true, subject, platnost_do: cert.validity.notAfter });
    }
    // Ověřovací mód: zpráva s overeni=true se zkontroluje, ale tržba se NEeviduje (očekávaný výsledek: kód 0)
    if (body.action === "overeni") {
      const { key, cert } = await loadCert(admin);
      const endpoint = settings.eet_mode === "produkce" ? ENDPOINTS.produkce : ENDPOINTS.playground;
      const env = buildEnvelope(
        { uuid_zpravy: crypto.randomUUID(), dat_odesl: pragueDateTime(new Date()), prvni_zaslani: "true", overeni: "true" },
        { eic_popl: settings.dic, id_jednotky: String(settings.eet_unit || "1"), id_pokl: settings.eet_cashier, porad_cis: "OVERENI-1", dat_trzby: pragueDateTime(new Date()), celk_trzba: "1.00" },
        key, cert);
      const raw = await send(endpoint, env);
      return json({ endpoint, odpoved: parseResponse(raw) });
    }

    const saleId = body.sale_id;
    if (!saleId) return json({ error: "Chybí sale_id" }, 400);
    const { data: sale, error } = await admin.from("sales").select("*").eq("id", saleId).single();
    if (error || !sale) return json({ error: "Prodej nenalezen" }, 404);
    if (sale.eet_status === "odeslano") return json({ ok: true, pok: sale.eet_fik, already: true });
    if (settings.eet_mode === "vypnuto") {
      await admin.from("sales").update({ eet_status: "vypnuto" }).eq("id", saleId);
      return json({ ok: true, vypnuto: true });
    }
    if (!settings.eet_unit) return json({ error: "V nastavení chybí číslo evidenční jednotky (id_jednotky)" }, 400);

    const { key, cert } = await loadCert(admin);
    const h = { uuid_zpravy: crypto.randomUUID(), dat_odesl: pragueDateTime(new Date()), prvni_zaslani: sale.eet_attempts === 0 ? "true" : "false" };
    const d = {
      eic_popl: settings.dic, id_jednotky: String(settings.eet_unit), id_pokl: settings.eet_cashier,
      porad_cis: `${new Date(sale.created_at).getFullYear()}/${sale.number}`,
      dat_trzby: pragueDateTime(new Date(sale.created_at)), celk_trzba: amount(Number(sale.total)),
    };
    const endpoint = settings.eet_mode === "produkce" ? ENDPOINTS.produkce : ENDPOINTS.playground;
    let res: any;
    try {
      res = parseResponse(await send(endpoint, buildEnvelope(h, d, key, cert)));
    } catch (e) {
      res = { ok: false, kod: -1, chyba: "Nedostupné spojení: " + (e as Error).message };
    }
    const upd: Record<string, unknown> = { eet_attempts: sale.eet_attempts + 1, eet_sent_at: new Date().toISOString() };
    if (res.ok) Object.assign(upd, { eet_status: "odeslano", eet_fik: res.pok, eet_test: res.test, eet_error: res.varovani?.length ? "Varování " + res.varovani.join("; ") : null });
    else Object.assign(upd, { eet_status: "chyba", eet_error: `${res.kod ?? ""} ${res.chyba}`.trim() });
    await admin.from("sales").update(upd).eq("id", saleId);
    return json({ ...res, porad_cis: d.porad_cis });
  } catch (e) {
    return json({ error: (e as Error).message }, 500);
  }
});
