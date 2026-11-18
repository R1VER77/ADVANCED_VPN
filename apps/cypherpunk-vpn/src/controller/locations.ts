// Server sites for the demo's route picker: real cloud regions' cities. In the app, a route's
// sites come from the signed device file (each hop's region, mapped to a site by a table).
import type { Hop } from './types'

export interface Site {
  id: string
  city: string
  country: string // ISO 3166 alpha-2
  numeric: string // ISO 3166 numeric, as Natural Earth's outlines are keyed
  countryName: string
  provider: string
  region: string
  lat: number
  lon: number
  continent: 'Europe' | 'Americas' | 'Asia-Pacific' | 'Africa & Middle East'
}

export const SITES: Site[] = [
  { id: 'sto', city: 'Stockholm', country: 'SE', numeric: '752', countryName: 'Sweden', provider: 'AWS', region: 'eu-north-1', lat: 59.33, lon: 18.07, continent: 'Europe' },
  { id: 'fra', city: 'Frankfurt', country: 'DE', numeric: '276', countryName: 'Germany', provider: 'OCI', region: 'eu-frankfurt-1', lat: 50.11, lon: 8.68, continent: 'Europe' },
  { id: 'ams', city: 'Amsterdam', country: 'NL', numeric: '528', countryName: 'Netherlands', provider: 'OCI', region: 'eu-amsterdam-1', lat: 52.37, lon: 4.9, continent: 'Europe' },
  { id: 'zrh', city: 'Zurich', country: 'CH', numeric: '756', countryName: 'Switzerland', provider: 'OCI', region: 'eu-zurich-1', lat: 47.38, lon: 8.54, continent: 'Europe' },
  { id: 'hel', city: 'Helsinki', country: 'FI', numeric: '246', countryName: 'Finland', provider: 'GCP', region: 'europe-north1', lat: 60.17, lon: 24.94, continent: 'Europe' },
  { id: 'osl', city: 'Oslo', country: 'NO', numeric: '578', countryName: 'Norway', provider: 'Azure', region: 'norwayeast', lat: 59.91, lon: 10.75, continent: 'Europe' },
  { id: 'rek', city: 'Reykjavik', country: 'IS', numeric: '352', countryName: 'Iceland', provider: '1984', region: 'is-rek', lat: 64.15, lon: -21.94, continent: 'Europe' },
  { id: 'par', city: 'Paris', country: 'FR', numeric: '250', countryName: 'France', provider: 'AWS', region: 'eu-west-3', lat: 48.86, lon: 2.35, continent: 'Europe' },
  { id: 'lon', city: 'London', country: 'GB', numeric: '826', countryName: 'United Kingdom', provider: 'AWS', region: 'eu-west-2', lat: 51.51, lon: -0.13, continent: 'Europe' },
  { id: 'buh', city: 'Bucharest', country: 'RO', numeric: '642', countryName: 'Romania', provider: 'Hetzner', region: 'ro-buh', lat: 44.43, lon: 26.1, continent: 'Europe' },
  { id: 'nyc', city: 'New York', country: 'US', numeric: '840', countryName: 'United States', provider: 'AWS', region: 'us-east-1', lat: 40.71, lon: -74.01, continent: 'Americas' },
  { id: 'lax', city: 'Los Angeles', country: 'US', numeric: '840', countryName: 'United States', provider: 'GCP', region: 'us-west2', lat: 34.05, lon: -118.24, continent: 'Americas' },
  { id: 'tor', city: 'Toronto', country: 'CA', numeric: '124', countryName: 'Canada', provider: 'OCI', region: 'ca-toronto-1', lat: 43.65, lon: -79.38, continent: 'Americas' },
  { id: 'sao', city: 'São Paulo', country: 'BR', numeric: '076', countryName: 'Brazil', provider: 'AWS', region: 'sa-east-1', lat: -23.55, lon: -46.63, continent: 'Americas' },
  { id: 'tyo', city: 'Tokyo', country: 'JP', numeric: '392', countryName: 'Japan', provider: 'OCI', region: 'ap-tokyo-1', lat: 35.68, lon: 139.69, continent: 'Asia-Pacific' },
  { id: 'sel', city: 'Seoul', country: 'KR', numeric: '410', countryName: 'South Korea', provider: 'OCI', region: 'ap-seoul-1', lat: 37.57, lon: 126.98, continent: 'Asia-Pacific' },
  { id: 'sin', city: 'Singapore', country: 'SG', numeric: '702', countryName: 'Singapore', provider: 'AWS', region: 'ap-southeast-1', lat: 1.35, lon: 103.82, continent: 'Asia-Pacific' },
  { id: 'syd', city: 'Sydney', country: 'AU', numeric: '036', countryName: 'Australia', provider: 'OCI', region: 'ap-sydney-1', lat: -33.87, lon: 151.21, continent: 'Asia-Pacific' },
  { id: 'bom', city: 'Mumbai', country: 'IN', numeric: '356', countryName: 'India', provider: 'AWS', region: 'ap-south-1', lat: 19.08, lon: 72.88, continent: 'Asia-Pacific' },
  { id: 'jnb', city: 'Johannesburg', country: 'ZA', numeric: '710', countryName: 'South Africa', provider: 'OCI', region: 'af-johannesburg-1', lat: -26.2, lon: 28.05, continent: 'Africa & Middle East' },
  { id: 'tlv', city: 'Tel Aviv', country: 'IL', numeric: '376', countryName: 'Israel', provider: 'GCP', region: 'me-west1', lat: 32.09, lon: 34.78, continent: 'Africa & Middle East' },
]

export const site = (id: string) => SITES.find((s) => s.id === id) ?? SITES[0]

/** A route from site ids: first = entry, last = exit, others = middle hops. */
export function routeOf(ids: string[]): Hop[] {
  return ids.map((id, i) => {
    const s = site(id)
    const hop: Hop['hop'] = i === ids.length - 1 ? 'exit' : i === 0 ? 'relay' : 'middle'
    return { hop, provider: s.provider, region: s.region, country: s.country, city: s.city, lat: s.lat, lon: s.lon }
  })
}

export const countryName = (code: string) => SITES.find((s) => s.country === code)?.countryName ?? code
export const numericOf = (code: string) => SITES.find((s) => s.country === code)?.numeric
