import { existsSync } from "node:fs";
import { mkdir, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import maxmind, { Reader, type AsnResponse, type CityResponse } from "maxmind";
import { config } from "./config.js";
import { ValidationError } from "./errors.js";

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

  status() {
    const describe = (reader: Reader<CityResponse> | Reader<AsnResponse> | undefined) => reader ? { ready: true, databaseType: reader.metadata.databaseType, buildDate: reader.metadata.buildEpoch.toISOString() } : { ready: false };
    return { city: describe(this.reader), asn: describe(this.asnReader) };
  }

  async upload(kind: "city" | "asn", filename: string, data: Buffer): Promise<void> {
    if (!filename.toLowerCase().endsWith(".mmdb") || !data.length || data.length > 128 * 1024 * 1024) throw new ValidationError("请选择 128 MB 以内的 .mmdb 文件");
    let reader: Reader<CityResponse | AsnResponse>;
    try {
      reader = new Reader<CityResponse | AsnResponse>(data);
      if (!reader.metadata.databaseType.toLowerCase().includes(kind)) throw new Error("数据库类型不匹配");
      reader.get("1.1.1.1");
    } catch { throw new ValidationError(`无效的 MaxMind ${kind === "city" ? "City" : "ASN"} 数据库`); }
    const directory = join(config.dataDir, "geoip");
    await mkdir(directory, { recursive: true });
    const temporary = join(directory, `.${kind}-${randomUUID()}.tmp`);
    await writeFile(temporary, data, { mode: 0o600 });
    await rename(temporary, join(directory, `uploaded-${kind}.mmdb`));
    if (kind === "city") this.reader = reader as Reader<CityResponse>;
    else this.asnReader = reader as Reader<AsnResponse>;
  }

  async init(): Promise<void> {
    const uploadedCity = join(config.dataDir, "geoip", "uploaded-city.mmdb");
    const databasePath = existsSync(uploadedCity) ? uploadedCity : config.geoIpDatabasePath || `${config.dataDir}/geoip/GeoIP2-City.mmdb`;
    if (existsSync(databasePath)) {
      try {
        this.reader = await maxmind.open<CityResponse>(databasePath, { cache: { max: 512 } });
      } catch (error) {
        console.warn(`GeoIP city database unavailable: ${error instanceof Error ? error.message : "unknown error"}`);
      }
    }
    const uploadedAsn = join(config.dataDir, "geoip", "uploaded-asn.mmdb");
    const asnPath = existsSync(uploadedAsn) ? uploadedAsn : config.geoIpAsnDatabasePath || `${config.dataDir}/geoip/GeoIP2-ASN.mmdb`;
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
