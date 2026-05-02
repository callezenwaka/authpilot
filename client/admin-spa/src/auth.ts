import { UserManager } from 'oidc-auth-client'

declare global {
  interface Window { __FURNACE__?: { apiKey?: string; sessionHashKey?: string } }
}

const authority = import.meta.env.VITE_OIDC_AUTHORITY as string | undefined
// Runtime key injected by the server takes precedence over build-time env var.
const apiKey: string | undefined = window.__FURNACE__?.apiKey ?? import.meta.env.VITE_API_KEY

export const oidcEnabled = !!authority

export const userManager = oidcEnabled
  ? new UserManager({
      authority,
      client_id: 'furnace-admin',
      redirect_uri: window.location.origin + '/admin/callback',
      scope: 'openid profile',
      automaticSilentRenew: true,
    })
  : null

async function getAccessToken(): Promise<string | null> {
  if (!userManager) return null
  const user = await userManager.getUser()
  return user?.access_token ?? null
}

export async function apiFetch(url: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers)
  const token = await getAccessToken()
  if (token) {
    headers.set('Authorization', `Bearer ${token}`)
  } else if (apiKey) {
    headers.set('X-Furnace-Api-Key', apiKey)
  }
  return fetch(url, { ...init, headers })
}
