<script setup lang="ts">
// A real map, entirely offline: Natural Earth country outlines (public domain, via
// world-atlas) projected with d3-geo. Server positions come from the signed route; this
// computer's own location is never looked up (no geo-IP request), so it is drawn at the
// map's edge, not placed.
import { computed, onMounted, onUnmounted, ref, shallowRef, watch } from 'vue'
import { geoInterpolate, geoMercator, geoPath } from 'd3-geo'
import { feature } from 'topojson-client'
import type { Feature, FeatureCollection, Geometry } from 'geojson'
import type { GeometryCollection, Topology } from 'topojson-specification'
import world from 'world-atlas/countries-50m.json'
import { countryName, numericOf } from '../controller/locations'
import AppIcon from './AppIcon.vue'
import type { Hop, Status } from '../controller/types'

const props = defineProps<{ status: Status | null; unavailable: boolean }>()

const topo = world as unknown as Topology<{ countries: GeometryCollection }>
const countries = (feature(topo, topo.objects.countries) as FeatureCollection).features as Feature<Geometry, { name: string }>[]


// The whole inhabited world: the overview, and the base every route view zooms into.
const WORLD: Feature<Geometry> = {
  type: 'Feature', properties: {},
  geometry: { type: 'MultiPoint', coordinates: [[-168, -56], [179, 76]] },
}
const CARD = 176 // room kept for the details card at the bottom

const host = ref<HTMLElement | null>(null)
const size = ref({ w: 460, h: 600 })
let observer: ResizeObserver | null = null
onMounted(() => {
  observer = new ResizeObserver(([e]) => {
    size.value = { w: Math.max(200, e.contentRect.width), h: Math.max(200, e.contentRect.height) }
  })
  if (host.value) observer.observe(host.value)
})
onUnmounted(() => observer?.disconnect())

// The base projection fits Europe into the space above the card; country paths are
// computed once per size and then only transformed.
const projection = computed(() =>
  geoMercator().fitExtent([[16, 16], [size.value.w - 16, size.value.h - CARD]], WORLD),
)
const paths = computed(() => {
  const path = geoPath(projection.value)
  return countries.map((c, i) => ({ key: i, id: String(c.id ?? ''), d: path(c) ?? '' }))
})

const enrolled = computed(() => !!props.status?.enrolled)
const chain = computed<Hop[]>(() => (enrolled.value ? (props.status?.chain ?? []) : []))
const mode = computed(() => {
  const s = props.status
  if (props.unavailable || !s || s.protection === 'unknown') return 'unknown'
  if (s.state === 'connected') return s.protection === 'protected' ? 'live' : 'unknown'
  if (['connecting', 'reconnecting', 'locked'].includes(s.state)) return 'building'
  if (s.state === 'cleartext_allowed') return 'exposed'
  if (!s.enrolled) return 'none'
  return 'blocked'
})
const highlighted = computed(() => new Set(chain.value.map((h) => numericOf(h.country)).filter(Boolean)))

// View: k (zoom) and x, y (pan) applied to the projected map. Overview = Europe;
// route = zoomed onto the servers.
type View = { k: number; x: number; y: number }
// Longitudes are "unwrapped" along the route (each step at most 180 degrees), so a route
// across the date line stays continuous: Tokyo (139.7) then Los Angeles (-118.2) becomes
// 139.7 then 241.8. The map is then drawn again one world-width to the side where needed.
const norm = (lon: number) => ((((lon + 180) % 360) + 360) % 360) - 180
const unwrap = (lon: number, prev: number) => {
  let l = lon
  while (l - prev > 180) l -= 360
  while (l - prev < -180) l += 360
  return l
}
const worldWidth = computed(() => 2 * Math.PI * projection.value.scale())
/** Base-projection position of an unwrapped longitude. */
function at(lon: number, lat: number): [number, number] {
  const p = projection.value([norm(lon), lat]) ?? [0, 0]
  return [p[0] + Math.round((lon - norm(lon)) / 360) * worldWidth.value, p[1]]
}

// Route points: each hop, then each leg's great-circle samples, all unwrapped in order.
const geo = computed(() => {
  const hops: [number, number][] = []
  const legs: [number, number][][] = []
  chain.value.forEach((h, i) => {
    const lon = i === 0 ? h.lon : unwrap(h.lon, hops[i - 1][0])
    if (i > 0) {
      const [a, b] = [hops[i - 1], [lon, h.lat] as [number, number]]
      const f = geoInterpolate(a, b)
      let prev = a[0]
      legs.push(
        Array.from({ length: 49 }, (_, k) => {
          const [x, y] = f(k / 48)
          prev = k === 0 ? a[0] : unwrap(x, prev)
          return [prev, y] as [number, number]
        }),
      )
    }
    hops.push([lon, h.lat])
  })
  return { hops, legs }
})

// Copies of the map needed beside the main one (-1: west, +1: east of the date line).
const copies = computed(() => {
  const lons = [...geo.value.hops, ...geo.value.legs.flat()].map((p) => p[0])
  const out = [0]
  if (lons.some((l) => l < -180)) out.unshift(-1)
  if (lons.some((l) => l > 180)) out.push(1)
  return out
})

function target(): View {
  const pts = [...geo.value.hops, ...geo.value.legs.flat()].map(([lon, lat]) => at(lon, lat))
  if (!pts.length) return { k: 1, x: 0, y: 0 }
  const xs = pts.map((p) => p[0])
  const ys = pts.map((p) => p[1])
  const [w, h] = [size.value.w, size.value.h - CARD]
  const dx = Math.max(55, Math.max(...xs) - Math.min(...xs))
  const dy = Math.max(60, Math.max(...ys) - Math.min(...ys))
  // Leave room on the left for "This computer" and on the right for labels.
  const k = Math.max(.65, Math.min(5.5, Math.min((w * 0.48) / dx, (h * 0.50) / dy)))
  const cx = (Math.max(...xs) + Math.min(...xs)) / 2
  const cy = (Math.max(...ys) + Math.min(...ys)) / 2
  return { k, x: w * 0.57 - cx * k, y: h * 0.56 - cy * k }
}

const view = shallowRef<View>({ k: 1, x: 0, y: 0 })
let raf = 0
function animateTo(to: View, ms = 1100) {
  cancelAnimationFrame(raf)
  if (matchMedia('(prefers-reduced-motion: reduce)').matches) { view.value = to; return }
  const from = view.value
  const t0 = performance.now()
  const ease = (t: number) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2)
  // Zoom out a little on the way when travelling far (a fly-to), so the move reads as travel.
  const far = Math.hypot(to.x - from.x, to.y - from.y) > size.value.w * 0.8
  const step = (now: number) => {
    const t = Math.min(1, (now - t0) / ms)
    const e = ease(t)
    const dip = far ? 1 - 0.35 * Math.sin(Math.PI * t) : 1
    const k = (from.k + (to.k - from.k) * e) * dip
    // Keep the view centred on the interpolated centre while the zoom dips.
    const [w, h] = [size.value.w, size.value.h - CARD]
    const fc = [(w * 0.57 - from.x) / from.k, (h * 0.56 - from.y) / from.k]
    const tc = [(w * 0.57 - to.x) / to.k, (h * 0.56 - to.y) / to.k]
    const c = [fc[0] + (tc[0] - fc[0]) * e, fc[1] + (tc[1] - fc[1]) * e]
    view.value = { k, x: w * 0.57 - c[0] * k, y: h * 0.56 - c[1] * k }
    if (t < 1) raf = requestAnimationFrame(step)
  }
  raf = requestAnimationFrame(step)
}
// Watch the route's contents, not its identity: every status poll delivers a fresh copy,
// and restarting the animation on each one kept it from ever settling.
const routeKey = computed(() => chain.value.map((h) => `${h.lon},${h.lat}`).join('|'))
watch([routeKey, () => size.value.w, () => size.value.h], () => animateTo(target()), { immediate: true })
if (import.meta.env.DEV) (window as unknown as { __map: unknown }).__map = { target, geo, at, view }
onUnmounted(() => cancelAnimationFrame(raf))

// Screen positions (constant-size pins and labels over the transformed map).
const toScreen = ([x, y]: [number, number]) => [x * view.value.k + view.value.x, y * view.value.k + view.value.y] as const
const pins = computed(() => {
  const occupied: { x: number; y: number; w: number; h: number }[] = []
  return chain.value.map((h, i) => {
    const point = toScreen(at(...geo.value.hops[i]))
    const width = Math.max(88, h.city.length * 7 + 12)
    const candidates = [[point[0] + 17, point[1] - 17], [point[0] - width - 17, point[1] - 17], [point[0] + 17, point[1] + 35], [point[0] - width - 17, point[1] + 35]]
    const label = candidates.find(([x, y]) => x > 12 && x + width < size.value.w - 12 && y > 55 && y < size.value.h - CARD + 15 && !occupied.some((r) => x < r.x + r.w && x + width > r.x && y - 14 < r.y + r.h && y + 18 > r.y)) ?? candidates[0]
    const lx = Math.max(15, Math.min(size.value.w - width - 15, label[0]))
    const ly = Math.max(68, Math.min(size.value.h - CARD + 15, label[1]))
    occupied.push({ x: lx - 8, y: ly - 15, w: width + 16, h: 38 })
    return { ...h, at: point, label: [lx, ly], labelWidth: width, role: chain.value.length === 1 ? 'single' : i === 0 ? 'entry' : i === chain.value.length - 1 ? 'exit' : 'middle' }
  })
})
const you = computed(() => [Math.max(68, size.value.w * .16), (size.value.h - CARD) * .76] as const)
const countryLabels = [
  ['SWEDEN', 15, 64], ['NORWAY', 8, 62], ['FINLAND', 27, 64], ['UNITED KINGDOM', -3, 55], ['FRANCE', 2, 46], ['GERMANY', 10.8, 51], ['POLAND', 20, 52], ['SPAIN', -4, 40], ['ITALY', 12.5, 42], ['UKRAINE', 31, 49], ['ROMANIA', 25, 46], ['TURKEY', 35, 39], ['UNITED STATES', -100, 39], ['CANADA', -103, 58], ['BRAZIL', -52, -13], ['AUSTRALIA', 134, -25], ['CHINA', 105, 35], ['INDIA', 79, 22], ['RUSSIA', 85, 61], ['SOUTH AFRICA', 25, -29], ['ARGENTINA', -65, -37], ['JAPAN', 138, 37], ['ALGERIA', 3, 28], ['SAUDI ARABIA', 44, 24],
] as const
const visibleCountryLabels = computed(() => countryLabels.map(([name, lon, lat]) => ({ name, at: toScreen(at(lon, lat)) })).filter(({ at: [x, y] }) => x > 25 && x < size.value.w - 25 && y > 70 && y < size.value.h - CARD + 30 && !pins.value.some((p) => Math.hypot(p.at[0] - x, p.at[1] - y) < 50 || (x > p.label[0] - 30 && x < p.label[0] + p.labelWidth + 30 && Math.abs(y - p.label[1]) < 35))))
function zoom(factor: number) {
  const k = Math.max(.65, Math.min(12, view.value.k * factor))
  const cx = size.value.w / 2, cy = (size.value.h - CARD) / 2
  animateTo({ k, x: cx - (cx - view.value.x) * k / view.value.k, y: cy - (cy - view.value.y) * k / view.value.k }, 320)
}
const copied = ref(false)
async function copyIp() {
  if (mode.value !== 'live' || !props.status?.exit_ip) return
  try { await navigator.clipboard.writeText(props.status.exit_ip); copied.value = true; window.setTimeout(() => { copied.value = false }, 1800) } catch { copied.value = false }
}
const countryRoute = computed(() => [...new Set(chain.value.map((h) => countryName(h.country)))].join(' → '))

function curve(a: readonly [number, number], b: readonly [number, number], bend = 0.18) {
  const [mx, my] = [(a[0] + b[0]) / 2, (a[1] + b[1]) / 2]
  const [nx, ny] = [-(b[1] - a[1]) * bend, (b[0] - a[0]) * bend]
  return `M ${a[0]} ${a[1]} Q ${mx + nx} ${my + ny} ${b[0]} ${b[1]}`
}
const route = computed(() => {
  if (!pins.value.length) return ''
  let d = curve(you.value, pins.value[0].at, 0.25)
  for (const leg of geo.value.legs) {
    leg.forEach(([lon, lat], k) => {
      const p = toScreen(at(lon, lat))
      d += `${k === 0 ? ' M' : ' L'} ${p[0]} ${p[1]}`
    })
  }
  return d
})

</script>

<template>
  <section ref="host" class="map" :class="mode" aria-label="Map of your route">
    <div class="map-heading"><span class="map-icon"><AppIcon :name="chain.length ? 'route' : 'globe'" :size="16" /></span><div><strong>{{ chain.length ? 'Your private route' : 'Privacy has no borders.' }}</strong><span>{{ chain.length ? countryRoute : 'Your connection. On your terms.' }}</span></div></div>
    <div class="map-controls"><button class="icon-button" aria-label="Fit route" title="Fit route" @click="animateTo(target(), 500)"><AppIcon name="locate" :size="17" /></button><span /><button class="icon-button" aria-label="Zoom in" title="Zoom in" @click="zoom(1.35)"><AppIcon name="plus" :size="17" /></button><button class="icon-button" aria-label="Zoom out" title="Zoom out" @click="zoom(1 / 1.35)"><AppIcon name="minus" :size="17" /></button></div>
    <svg class="art" :viewBox="`0 0 ${size.w} ${size.h}`" :width="size.w" :height="size.h" role="img" aria-label="Offline map showing the signed server route; your location is not requested">
      <defs><radialGradient id="exitGlow"><stop offset="0%" stop-color="var(--primary)" stop-opacity=".18" /><stop offset="100%" stop-color="var(--primary)" stop-opacity="0" /></radialGradient></defs>
      <g :transform="`translate(${view.x},${view.y}) scale(${view.k})`"><g v-for="n in copies" :key="n" :transform="`translate(${n * worldWidth},0)`"><path v-for="c in paths" :key="c.key" :d="c.d" class="land" :class="{ hl: highlighted.has(c.id) }" /></g></g>
      <text v-for="label in visibleCountryLabels" :key="label.name" :x="label.at[0]" :y="label.at[1]" class="country-label" text-anchor="middle">{{ label.name }}</text>
      <template v-if="pins.length">
        <path :d="route" class="route" />
        <path v-if="mode === 'building'" :d="route" class="route building" />
        <path v-if="mode === 'live'" :d="route" class="route live" />
        <g v-for="(p, i) in pins" :key="i" :class="['pin', p.role]">
          <g :transform="`translate(${p.at[0]},${p.at[1]})`"><circle v-if="(p.role === 'exit' || p.role === 'single') && mode === 'live'" r="39" fill="url(#exitGlow)" /><circle v-if="mode === 'live'" class="pin-ring" r="17" /><circle r="6" class="dot" /><circle r="2" class="pin-center" /></g>
          <g :transform="`translate(${p.label[0]},${p.label[1]})`"><rect x="-9" y="-14" :width="p.labelWidth + 15" height="37" rx="6" class="label-bg" /><text class="tag">{{ p.city }}</text><text y="15" class="tag small">{{ { entry: 'Entry server', exit: 'Exit server', middle: 'Middle server', single: 'VPN server' }[p.role] }}</text></g>
        </g>
      </template>
      <g :transform="`translate(${you[0]},${you[1]})`" class="you"><circle r="18" class="halo" /><circle r="11" class="device-bg" /><path d="M-5-4H5v7H-5Z M-3 6H3 M0 3V6" class="computer-icon" /><text x="0" y="35" text-anchor="middle" class="tag strong">Your device</text><text x="0" y="49" text-anchor="middle" class="tag small">Location not requested</text></g>
    </svg>
    <div v-if="enrolled" class="card">
      <div class="card-heading"><span class="eyebrow">Connection details</span><span class="connection-badge" :class="{ verified: mode === 'live', warning: mode === 'unknown' }"><AppIcon :name="mode === 'live' ? 'shield' : mode === 'unknown' ? 'info' : 'lock'" :size="11" />{{ mode === 'live' ? 'Verified' : mode === 'unknown' ? 'Status unknown' : 'Traffic blocked' }}</span></div>
      <div class="ip-row"><div><span class="ip-label">Exit IP address</span><div class="ip-value" :class="{ inactive: mode !== 'live' }">{{ mode === 'live' ? status?.exit_ip : mode === 'unknown' ? 'Unavailable' : 'Not connected' }}</div></div><button v-if="mode === 'live'" class="icon-button" :aria-label="copied ? 'IP address copied' : 'Copy exit IP address'" :title="copied ? 'Copied' : 'Copy address'" @click="copyIp"><AppIcon :name="copied ? 'check' : 'copy'" :size="16" /></button></div>
      <div class="card-bottom"><div><span>Protocol</span><strong>WireGuard · Hybrid TLS</strong></div><div><span>Route</span><strong>{{ chain.length }} {{ chain.length === 1 ? 'server' : 'servers' }} · {{ mode === 'live' ? 'Connected' : 'Configured' }}</strong></div></div>
    </div>
    <div v-else class="map-intro"><span class="intro-line" /><span>Less exposed.<br>More in control.</span><p>Built for privacy. Designed for you.</p></div>
    <div class="map-attribution">OFFLINE MAP <span>·</span> NATURAL EARTH</div>
  </section>
</template>
<style scoped>
.map { position: relative; flex: 1; min-width: 0; overflow: hidden; background: var(--bg); }
.art { position: absolute; inset: 0; display: block; }
.map-heading { position: absolute; top: 22px; left: 24px; display: flex; align-items: center; gap: 10px; z-index: 1; pointer-events: none; }
.map-icon { display: grid; place-items: center; width: 31px; height: 31px; background: var(--panel); border: 1px solid var(--line); border-radius: 8px; color: var(--primary); }
.map-heading strong { display: block; font-size: 12px; font-weight: 550; }
.map-heading div > span { display: block; color: var(--muted); font-size: 10px; margin-top: 4px; }
.map-controls { position: absolute; top: 24px; right: 20px; padding: 3px; background: var(--panel); border: 1px solid var(--line); border-radius: 8px; display: flex; align-items: center; box-shadow: 0 2px 8px #17102604; z-index: 2; }
.map-controls .icon-button { width: 25px; height: 25px; }
.map-controls > span { width: 1px; height: 12px; background: var(--line); margin: 0 3px; }
.land { fill: var(--map-land); stroke: var(--map-border); stroke-width: .8; vector-effect: non-scaling-stroke; transition: fill .6s ease; }
.land.hl { fill: var(--map-highlight); }
.country-label { fill: var(--map-text); font-size: 8px; font-weight: 550; letter-spacing: 1.1px; }
.route { fill: none; stroke: var(--faint); stroke-width: 1.5; stroke-dasharray: 3 5; stroke-linecap: round; }
.live .route { stroke: var(--primary); opacity: .35; stroke-dasharray: none; }
.route.building { stroke: var(--warn); stroke-dasharray: 4 9; animation: march 1.8s linear infinite; }
.route.live { opacity: .9; stroke: var(--primary); stroke-dasharray: 2 18; stroke-width: 2; animation: march 2s linear infinite; }
@keyframes march { to { stroke-dashoffset: -40; } }
.pin .dot { fill: var(--panel); stroke: var(--primary); stroke-width: 2; }
.pin-center { fill: var(--primary); }
.pin-ring { fill: none; stroke: var(--primary); stroke-width: .7; opacity: .25; }
.exit .pin-ring, .single .pin-ring { transform-box: fill-box; transform-origin: center; animation: pulse 3s ease-out infinite; }
.blocked .pin .dot, .unknown .pin .dot { stroke: var(--faint); }
.blocked .pin-center, .unknown .pin-center { fill: var(--faint); }
@keyframes pulse { from { transform: scale(.7); opacity: .5; } to { transform: scale(1.5); opacity: 0; } }
.label-bg { fill: var(--panel); opacity: .94; }
.tag { fill: var(--text); font-size: 12px; font-weight: 600; }
.tag.small { font-size: 10px; font-weight: 400; fill: var(--muted); }
.you .halo { fill: var(--line); }
.device-bg { fill: var(--panel); stroke: var(--faint); stroke-width: .8; }
.computer-icon { fill: none; stroke: var(--muted); stroke-width: .9; stroke-linecap: round; stroke-linejoin: round; }
.live .you .halo { fill: var(--primary-soft); }
.live .device-bg { stroke: var(--primary); }
.live .computer-icon { stroke: var(--primary); }
.card { position: absolute; bottom: 33px; left: 24px; right: 24px; max-width: 460px; margin-inline: auto; background: var(--panel); border: 1px solid var(--line); border-radius: 11px; box-shadow: var(--shadow); padding: 16px 20px 14px; }
.card-heading { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
.connection-badge { display: inline-flex; align-items: center; gap: 4px; border-radius: 5px; background: var(--bg); color: var(--muted); padding: 4px 7px; font-size: 10px; }
.connection-badge.verified { background: var(--ok-soft); color: var(--ok-text); }
.connection-badge.warning { color: var(--warn); background: var(--warn-soft); }
.ip-row { display: flex; align-items: center; justify-content: space-between; margin: 13px 0 15px; }
.ip-label { display: block; font-size: 10px; color: var(--muted); margin-bottom: 5px; }
.ip-value { font-family: ui-monospace, 'DejaVu Sans Mono', monospace; font-size: 20px; letter-spacing: -.5px; user-select: all; }
.ip-value.inactive { font-family: inherit; color: var(--muted); font-size: 17px; letter-spacing: -.3px; }
.card-bottom { display: grid; grid-template-columns: 1.1fr 1fr; gap: 15px; border-top: 1px solid var(--line); padding-top: 11px; }
.card-bottom span, .card-bottom strong { display: block; }
.card-bottom span { color: var(--muted); font-size: 10px; }
.card-bottom strong { font-size: 11px; font-weight: 500; margin-top: 5px; }
.map-attribution { position: absolute; bottom: 10px; right: 18px; font-size: 7px; letter-spacing: .8px; color: var(--faint); }
.map-attribution > span { padding: 0 5px; }
.map-intro { position: absolute; left: 36px; bottom: 60px; }
.map-intro > span:not(.intro-line) { display: block; font-size: 30px; font-weight: 500; letter-spacing: -1px; line-height: 1.35; }
.intro-line { display: block; width: 30px; height: 3px; background: var(--primary); border-radius: 4px; margin-bottom: 16px; }
.map-intro p { font-size: 12px; color: var(--muted); }
@media (max-width: 840px) { .map-controls { right: 14px; } .map-heading { left: 16px; } .map-heading strong { font-size: 11px; } .map-heading div > span { font-size: 8px; } .map-controls .icon-button { width: 21px; } .map-icon { display: none; } .card { left: 16px; right: 16px; } }
</style>
