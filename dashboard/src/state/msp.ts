/**
 * MSP "acting in a customer" state (zustand), see docs/MSP.md.
 *
 * While an MSP user is inside a customer, `acting` holds the short-lived
 * customer-scoped token returned by POST /v1/msp/customers/{id}/switch.
 * api/client.ts sends THAT token instead of the MSP session token, so every
 * page works unchanged against the customer's data; "Back to MSP" simply drops
 * it. The MSP session token in state/auth.ts is never touched.
 *
 * The token lives in sessionStorage (per tab, gone when the tab closes) rather
 * than localStorage: it is a bearer credential into a customer, and it expires
 * in minutes anyway. All storage access is wrapped in try/catch.
 *
 * While acting, the in-memory principal role is replaced by the grant role so
 * role-gated controls match what the server will allow; the original is
 * restored on exit. (The server is authoritative either way.)
 */

import { create } from "zustand";
import type { SwitchResult, GrantRole } from "../api/msp";
import { useAuth } from "./auth";
import type { AuthUser } from "../api/types";

const SS_KEY = "paddock.msp.acting.v1";

export interface Acting {
  token: string;
  customer: { id: string; slug: string; name: string };
  msp: { slug: string; name: string };
  role: GrantRole;
  /** epoch ms when the token stops working. */
  expiresAt: number;
  /** The MSP user's own principal, restored on exit. */
  home: AuthUser | null;
}

function load(): Acting | null {
  try {
    const raw = sessionStorage.getItem(SS_KEY);
    if (!raw) return null;
    const a = JSON.parse(raw) as Acting;
    if (!a?.token || !a.customer?.id || a.expiresAt <= Date.now()) {
      sessionStorage.removeItem(SS_KEY);
      return null;
    }
    return a;
  } catch {
    return null;
  }
}

function persist(a: Acting | null): void {
  try {
    if (a) sessionStorage.setItem(SS_KEY, JSON.stringify(a));
    else sessionStorage.removeItem(SS_KEY);
  } catch {
    /* in-memory state is still authoritative for this tab */
  }
}

/** Show the grant role (not the MSP role) while inside a customer. */
function applyRole(a: Acting | null): void {
  const auth = useAuth.getState();
  if (a && auth.user) {
    useAuth.setState({ user: { ...auth.user, role: a.role } });
  }
}

interface MspState {
  acting: Acting | null;
  /** Enter a customer with the token from the switch exchange. */
  enter: (sw: SwitchResult) => void;
  /** Drop the customer token and return to the MSP session. */
  exit: () => void;
}

const initial = load();
if (initial) applyRole(initial);

export const useMsp = create<MspState>((set, get) => ({
  acting: initial,
  enter: (sw) => {
    const home = get().acting?.home ?? useAuth.getState().user;
    const a: Acting = {
      token: sw.access_token,
      customer: sw.customer,
      msp: sw.msp,
      role: sw.role,
      expiresAt: Date.now() + sw.expires_in * 1000,
      home,
    };
    persist(a);
    set({ acting: a });
    applyRole(a);
  },
  exit: () => {
    const a = get().acting;
    persist(null);
    set({ acting: null });
    if (a?.home) useAuth.setState({ user: a.home });
  },
}));

// Signing out of the MSP session (or a 401 clearing it) also leaves the customer.
useAuth.subscribe((s) => {
  if (!s.token && useMsp.getState().acting) {
    persist(null);
    useMsp.setState({ acting: null });
  }
});

/** The customer token while acting (and not expired), else null. */
export function actingToken(): string | null {
  const a = useMsp.getState().acting;
  if (!a) return null;
  if (a.expiresAt <= Date.now()) {
    useMsp.getState().exit();
    return null;
  }
  return a.token;
}
