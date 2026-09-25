// What an edition covers, and how a package is narrowed to it. Kept apart from
// build-editions.js so the suite that checks an assembled package can state the
// same transform the build applied instead of describing it a second time.
//
// Community qualifies ChatGPT and Claude, Enterprise whatever the catalogue carries.
export const editionProviders = { community: ['chatgpt', 'claude'], enterprise: null };

// `coveredProviders` is what the runtime measures a served catalogue against: null lets
// an edition take the catalogue whole, a list makes it drop what this package carries no
// selectors for -- a served provider would otherwise get its own registered content
// script, manifest or not.
export function factoryModule(content, allowed) {
  return '// Generated from detection-factory.json by build-editions.js.\nexport const factoryCatalog=' + JSON.stringify(content)
    + ';\nexport const coveredProviders=' + JSON.stringify(allowed ?? null) + ';\n';
}

export function restrictFactory(content, allowed) {
  const providers = content.providers.filter(p => allowed.includes(p.id));
  if (providers.length !== allowed.length) {throw new Error('The factory catalogue misses a provider this edition covers');}
  return { ...content, providers };
}

// adapters.js states its catalogue as one entry per line, each preceded by the comments
// that measured it on the page. A dropped provider takes those comments with it, and the
// alias map loses every name pointing at it -- otherwise the package would still resolve
// a site it no longer knows how to read.
export function restrictAdapters(source, allowed) {
  const lines = source.split('\n');
  const open = lines.findIndex(line => line.includes('const catalog = ['));
  const close = lines.findIndex((line, i) => i > open && line.trim() === '];');
  if (open < 0 || close < 0) {throw new Error('The adapters catalogue block was not found');}
  const kept = [], domains = [];
  let comments = [];
  for (const line of lines.slice(open + 1, close)) {
    const entry = line.match(/^\s*\['([a-z]+)','([^']+)'/);
    if (!entry) { comments.push(line); continue; }
    if (allowed.includes(entry[1])) { kept.push(...comments, line); domains.push(entry[2]); }
    comments = [];
  }
  if (domains.length !== allowed.length) {throw new Error('The adapters catalogue misses a provider this edition covers');}
  lines.splice(open + 1, close - open - 1, ...kept);
  const index = lines.findIndex(line => line.includes('const aliases={'));
  if (index < 0) {throw new Error('The adapters alias map was not found');}
  const pairs = [...lines[index].matchAll(/'([^']+)':'([^']+)'/g)].filter(pair => domains.includes(pair[2]));
  lines[index] = lines[index].replace(/\{[^}]*\}/, '{' + pairs.map(pair => `'${pair[1]}':'${pair[2]}'`).join(',') + '}');
  return { source: lines.join('\n'), hosts: [...domains, ...pairs.map(pair => pair[1])] };
}

// The Community package says so on the pages it protects; the shared source ships the
// marker empty so both editions read the same file.
export function communitySignature(source) {
  const marker = "const COMMUNITY_SIGNATURE='';";
  if (source.split(marker).length !== 2) {throw new Error('Community signature marker must occur exactly once');}
  return source.replace(marker, 'const COMMUNITY_SIGNATURE="Sécurisé par Milvago Community";');
}

// A match no adapter answers for would inject the content script into a site the package
// cannot read, and claim a host permission it has no use for.
export function restrictMatches(matches, hosts) {
  const kept = matches.filter(match => hosts.some(host => match === `https://${host}/*`));
  if (kept.length !== hosts.length) {throw new Error('A covered host has no content-script match');}
  return kept;
}
