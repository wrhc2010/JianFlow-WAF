import ipaddr from "ipaddr.js";

export function isIpInCidr(ip: string, cidr: string): boolean {
  try {
    const address = ipaddr.process(ip);
    const [network, prefix] = cidr.includes("/")
      ? ipaddr.parseCIDR(cidr.trim())
      : [ipaddr.parse(cidr.trim()), ipaddr.parse(cidr.trim()).kind() === "ipv4" ? 32 : 128] as const;
    if (address.kind() !== network.kind()) return false;
    return address.match(network, prefix);
  } catch {
    return false;
  }
}

export function isUnsafeUrl(value: string): boolean {
  if (/\b(?:file|gopher|dict|ftp|tftp|ldap|jar|javascript|vbscript):|data:\s*(?:text\/html|image\/svg\+xml)/i.test(value)) return true;
  for (const match of value.matchAll(/\bhttps?:\/\/[^\s"'<>\\{}]+/gi)) {
    try {
      const url = new URL(match[0]);
      const host = url.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
      if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")
        || host.endsWith(".internal") || host === "metadata.google.internal") return true;
      if (ipaddr.isValid(host) && ipaddr.process(host).range() !== "unicast") return true;
    } catch {
      // An invalid destination URL is not safe to hand to an upstream URL fetcher.
      return true;
    }
  }
  return false;
}
