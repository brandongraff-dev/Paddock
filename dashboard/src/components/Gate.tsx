/**
 * Role gate (governance §B). Wraps a cluster of mutate controls and disables
 * everything inside when the current principal lacks the capability — without
 * rebuilding the page. It uses a native <fieldset disabled>, which disables
 * every descendant form control (buttons, inputs, selects, textareas) per the
 * HTML spec regardless of layout, so `display: contents` keeps the surrounding
 * grid/flex intact. Disabled buttons already dim via `button:disabled`.
 *
 *   <Gate need="triage"> … analyst-or-admin controls … </Gate>
 *   <Gate need="admin">  … admin-only controls …      </Gate>
 */

import type { ReactNode } from "react";
import { useCan, type Capability } from "../state/auth";

interface Props {
  need: Capability;
  children: ReactNode;
  /** Hover hint shown while the cluster is read-only. */
  title?: string;
}

const DEFAULT_TITLE: Record<Capability, string> = {
  triage: "Read-only — your role can't triage",
  admin: "Admin-only — your role can't change this",
};

export default function Gate({ need, children, title }: Props) {
  const can = useCan(need);
  return (
    <fieldset
      className="mutate-gate"
      disabled={!can}
      aria-disabled={!can}
      data-cap={need}
      title={can ? undefined : (title ?? DEFAULT_TITLE[need])}
    >
      {children}
    </fieldset>
  );
}
