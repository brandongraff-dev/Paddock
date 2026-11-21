/**
 * Topbar indicator while an MSP user is acting inside a customer: which
 * customer, in which role, and a one-click way back. Rendered next to the
 * classification pill, in the same quiet style (see styles/msp.css). Renders
 * nothing outside a customer.
 */

import { useEffect, useRef } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { useMsp } from "../state/msp";
import "../styles/msp.css";

export default function MspIndicator() {
  const acting = useMsp((s) => s.acting);
  const exit = useMsp((s) => s.exit);
  const qc = useQueryClient();
  const nav = useNavigate();
  const prev = useRef<string | null>(acting?.customer.id ?? null);

  // However we left (button, expiry, revoked grant, 401), never keep the
  // previous tenant's cached data around.
  useEffect(() => {
    const now = acting?.customer.id ?? null;
    if (prev.current !== now) {
      qc.clear();
      prev.current = now;
    }
  }, [acting, qc]);

  if (!acting) return null;
  const back = () => {
    exit();
    qc.clear();
    nav("/msp");
  };
  return (
    <span
      className="msp-pill"
      role="status"
      aria-label={`Acting in customer ${acting.customer.name}`}
      title={`You are acting inside ${acting.customer.name} as ${acting.msp.name} (${acting.role}). Every action is recorded in the customer's audit log.`}
    >
      <i aria-hidden="true" />
      <span>Acting in</span>
      <span className="msp-pill-name">{acting.customer.name}</span>
      <span className="msp-pill-role">· {acting.role}</span>
      <button type="button" onClick={back} aria-label="Back to MSP console">
        Back to MSP
      </button>
    </span>
  );
}
