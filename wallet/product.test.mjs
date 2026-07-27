import test from "node:test"; import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { PRODUCT, requireStatus, validateUpdateManifest, assertFreshDataRoot } from "./identity.mjs";
import { evidenceView, statusView } from "../explorer/render.mjs";
const expected={chain_id:"a".repeat(64),genesis_hash:"b".repeat(64),api_version:"v1"};
const historicalDataRootEntries = [
  "617363656e742d77616c6c6574",
  "6d696e642d77616c6c6574",
  "686973746f726963616c2d636861696e2e6a736f6e",
  "6d6967726174696f6e2e6d61726b6572",
].map((hex) => Buffer.from(hex, "hex").toString("utf8"));
const productRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const productPages = ["site/index.html", "site/404.html", "explorer/index.html"];
const anchors = (html) => [...html.matchAll(/<a\b[^>]*\bhref="([^"]+)"/g)].map((match) => match[1]);
const trustedExternalLinks = new Set(["https://wwm-status.mindchain.network"]);
const isExternalLink = (href) => /^[a-z]+:\/\//i.test(href);
const readProductPage = async (page) => readFile(resolve(productRoot, page), "utf8");
test("wallet identity is side by side and exact",()=>{ assert.equal(PRODUCT.bundleId,"network.mindchain.noosphere.wallet"); assert.equal(PRODUCT.scheme,"mindchain-noos://"); assert.equal(PRODUCT.scope,"/noosphere-wallet-v1/"); assert.equal(PRODUCT.cachePrefix,"mindchain-noosphere-v1"); for (const entry of historicalDataRootEntries) assert.throws(()=>assertFreshDataRoot([entry]),/historical_overwrite_forbidden/); });
test("wallet rejects wrong chain before authorization",()=>{ assert.throws(()=>requireStatus(expected,{...expected,chain_id:"c".repeat(64)}),/wrong_protocol_identity/); });
test("update manifest binds every target dimension",()=>{ const manifest={app_id:PRODUCT.bundleId,...expected,platform:"win32",arch:"x64",version:"1.2.3",channel:"stable",artifact_sha256:"d".repeat(64),signature:"signed"}; assert.equal(validateUpdateManifest(manifest,expected,{platform:"win32",arch:"x64"}).version,"1.2.3"); assert.throws(()=>validateUpdateManifest({...manifest,arch:"arm64"},expected,{platform:"win32",arch:"x64"}),/wrong_update_target/); });
test("explorer never infers finalized and renders six dimensions",()=>{ const view=statusView({unsafe_head:{height:"12",hash:"a".repeat(64)},justified:{height:"10",hash:"b".repeat(64)}}); assert.equal(view.finalized,"UNKNOWN"); const badges=evidenceView({evidence_label:"THEORY",implementation_status:"PARTIAL",evidence_status:"MEASURED_LAB",lifecycle:"WITHDRAWN",result:"KILLED",enabled:false}); assert.equal(badges.length,6); assert.equal(badges[5].value,"DISABLED"); });
test("static product pages prevent navigation dead ends",async()=>{
  for (const page of productPages) {
    const html = await readProductPage(page);
    const links = anchors(html);
    assert.match(html, /<main\b[^>]*\bid="main"/, `${page} must expose the main landmark`);
    assert.match(html, /<a\b[^>]*class="skip"[^>]*href="#main"/, `${page} must provide a working skip link`);
    assert.match(html, /<nav\b[^>]*aria-label="Primary navigation"/, `${page} must provide labeled primary navigation`);
    assert.ok(links.some((href) => href === "index.html" || href === "../site/"), `${page} must link home`);
    assert.ok(links.filter((href) => !href.startsWith("#")).length >= 3, `${page} must offer recovery paths`);
    assert.equal(links.includes("#"), false, `${page} must not contain a placeholder link`);
    assert.deepEqual(
      links.filter(isExternalLink).filter((href) => !trustedExternalLinks.has(href)),
      [],
      `${page} must not depend on untrusted external DNS`,
    );
    if (html.includes("NOOSPHERE")) assert.match(html, /Technical provenance: NOOSPHERE research corpus/, `${page} may use NOOSPHERE only as technical provenance`);
  }
});
test("every static product link resolves to a checked-in target",async()=>{
  for (const page of productPages) {
    const html = await readProductPage(page);
    for (const href of anchors(html)) {
      if (isExternalLink(href)) {
        assert.ok(trustedExternalLinks.has(href), `${page} has untrusted external target ${href}`);
        continue;
      }
      if (href.startsWith("#")) {
        assert.match(html, new RegExp(`\\bid="${href.slice(1)}"`), `${page} has missing fragment ${href}`);
        continue;
      }
      const localPath = href.split(/[?#]/, 1)[0];
      await assert.doesNotReject(access(resolve(productRoot, dirname(page), localPath)), `${page} has missing target ${href}`);
    }
  }
});
