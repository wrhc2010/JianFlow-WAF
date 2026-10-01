import { existsSync } from "node:fs";
import maxmind, { type AsnResponse, type CityResponse, type Reader } from "maxmind";
import { config } from "./config.js";

export type GeoPoint = {
  country?: string | undefined;
  region?: string | undefined;
  city?: string | undefined;
  latitude?: number | undefined;
  longitude?: number | undefined;
  asn?: number | undefined;
};

export class GeoIpResolver {
  private reader: Reader<CityResponse> | undefined;
  private asnReader: Reader<AsnResponse> | undefined;

  get isReady(): boolean {
    return Boolean(this.reader);
  }

  async init(): Promise<void> {
    const databasePath = config.geoIpDatabasePath || `${config.dataDir}/geoip/GeoIP2-City.mmdb`;
    if (existsSync(databasePath)) {
      try {
        this.reader = await maxmind.open<CityResponse>(databasePath, { cache: { max: 512 } });
      } catch (error) {
        console.warn(`GeoIP city database unavailable: ${error instanceof Error ? error.message : "unknown error"}`);
      }
    }
    const asnPath = config.geoIpAsnDatabasePath || `${config.dataDir}/geoip/GeoIP2-ASN.mmdb`;
    if (existsSync(asnPath)) {
      try {
        this.asnReader = await maxmind.open<AsnResponse>(asnPath, { cache: { max: 512 } });
      } catch (error) {
        console.warn(`GeoIP ASN database unavailable: ${error instanceof Error ? error.message : "unknown error"}`);
      }
    }
  }

  lookup(ip?: string): GeoPoint {
    if (!ip) return {};
    const normalizedIp = ip.replace(/^::ffff:/i, "");
    const point: GeoPoint = {};
    try {
      const result = this.reader?.get(normalizedIp);
      if (result) {
        const subdivision = result.subdivisions?.[0]?.names?.["zh-CN"]
          ?? result.subdivisions?.[0]?.names?.en;
        Object.assign(point, {
          country: result.country?.names?.["zh-CN"] ?? result.country?.names?.en,
          region: subdivision,
          city: result.city?.names?.["zh-CN"] ?? result.city?.names?.en,
          latitude: result.location?.latitude,
          longitude: result.location?.longitude
        });
      }
    } catch {
      // A malformed or unsupported address must remain an unknown location.
    }
    try {
      const asn = this.asnReader?.get(normalizedIp);
      if (asn?.autonomous_system_number !== undefined) point.asn = asn.autonomous_system_number;
    } catch {
      // ASN is optional and must never make request handling fail.
    }
    return point;
  }
}
