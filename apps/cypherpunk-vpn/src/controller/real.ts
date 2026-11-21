import { invoke } from '@tauri-apps/api/core'
import type { ActionPlan, ActionRequest, AutoconnectPolicy, MultihopPresets, Operation, ProviderSearchPage, SetupBranch, SetupSnapshot, Status, StreamingEligibility } from './types'

const MAX_RESPONSE = 256 * 1024

async function read<T>(command: string, args: Record<string, unknown> = {}): Promise<T> {
  const raw = await invoke<string>(command, args)
  if (typeof raw !== 'string' || raw.length > MAX_RESPONSE) throw new Error('invalid_controller_response')
  const value: unknown = JSON.parse(raw)
  if (!value || typeof value !== 'object' || (value as { schema?: number }).schema !== 1) throw new Error('invalid_controller_schema')
  return value as T
}

export const controller = {
  async providers(query: string, cursor: string | null = null): Promise<ProviderSearchPage> {
    const page = await read<ProviderSearchPage>('provider_search', { query, cursor, filter: 'all' })
    if (!Array.isArray(page.results) || page.results.length > 50 || page.returned !== page.results.length
      || !Number.isSafeInteger(page.total_matches) || page.total_matches < page.returned
      || (page.next_cursor !== null && (typeof page.next_cursor !== 'string' || page.next_cursor.length > 512))
      || page.results.some(row => !row || typeof row.id !== 'string' || row.id.length > 257)) throw new Error('invalid_provider_page')
    return page
  },
  async snapshot(): Promise<Status> {
    const status = await read<Status>('get_snapshot')
    if (!Number.isFinite(status.observed_at) || !Array.isArray(status.chain) || status.chain.length > 3
      || !['protected', 'blocked', 'unprotected', 'unknown'].includes(status.protection)
      || !['applications', 'whole-device', 'none', 'unknown'].includes(status.scope)) throw new Error('invalid_controller_status')
    if (status.protection === 'protected' && (status.state !== 'connected' || status.kill_switch !== 'active'
      || !['applications', 'whole-device'].includes(status.scope))) throw new Error('contradictory_controller_status')
    return status
  },
  setup: (branch: SetupBranch) => read<SetupSnapshot>('get_setup', { branch }),
  preview: (request: ActionRequest) => read<ActionPlan>('preview_action', { request: JSON.stringify(request) }),
  apply: (id: string) => read<Operation>('apply_action', { id }),
  operation: (id: string) => read<Operation>('get_operation', { id }),
  cancel: (id: string) => read<Operation>('cancel_operation', { id }),
  async streamingEligibility(): Promise<StreamingEligibility> {
    const table = await read<StreamingEligibility>('streaming_eligibility')
    if (!Array.isArray(table.rows) || table.rows.length > 200
      || table.rows.some(row => !row || !['measured', 'class-knowledge'].includes(row.kind)
        || typeof row.service !== 'string' || row.service.length > 64)) throw new Error('invalid_eligibility_table')
    return table
  },
  async multihopPresets(): Promise<MultihopPresets> {
    const presets = await read<MultihopPresets>('multihop_presets')
    if (!Array.isArray(presets.presets) || presets.presets.length === 0 || presets.presets.length > 8
      || !Number.isSafeInteger(presets.ceiling) || presets.ceiling !== 3
      || presets.presets.some(p => !p || ![1, 2, 3].includes(p.hops))) throw new Error('invalid_presets')
    return presets
  },
  async autoconnectPolicy(): Promise<AutoconnectPolicy> {
    const policy = await read<AutoconnectPolicy>('autoconnect_policy')
    if (typeof policy.enabled !== 'boolean' || typeof policy.wired_trusted !== 'boolean'
      || !Number.isSafeInteger(policy.trusted_ssids_count) || policy.trusted_ssids_count < 0
      || policy.trusted_ssids_count > 1000) throw new Error('invalid_autoconnect_policy')
    return policy
  },
}
