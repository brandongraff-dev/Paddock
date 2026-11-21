import type { Severity } from "../api/types";

interface Props {
  severity: Severity | string;
  compact?: boolean;
}

export default function SeverityChip({ severity, compact }: Props) {
  const label = compact ? severity.slice(0, 4).toUpperCase() : severity.toUpperCase();
  return <span className={`chip chip-sev-${severity}`}>{label}</span>;
}
