import { invoke } from '@tauri-apps/api/core'
import type { ActionPlan, ActionRequest, Operation, SetupBranch, SetupSnapshot, Status } from './types'

const MAX_RESPONSE = 256 * 1024

async function read<T>(command: string, args: Record<string, unknown> = {}): Promise<T> {
  const raw = await invoke<string>(command, args)
  if (typeof raw !== 'string' || raw.length > MAX_RESPONSE) throw new Error('invalid_controller_response')
  const value: unknown = JSON.parse(raw)
  if (!value || typeof value !== 'object' || (value as { schema?: number }).schema !== 1) throw new Error('invalid_controller_schema')
  return value as T
}

export const controller = {
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
}
