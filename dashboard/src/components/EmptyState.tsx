import type { ReactNode } from "react";

interface Props {
  title: string;
  hint?: ReactNode;
  icon?: ReactNode;
}

export default function EmptyState({ title, hint, icon }: Props) {
  return (
    <div className="empty">
      <div className="icon" aria-hidden>
        {icon ?? "·"}
      </div>
      <div style={{ color: "var(--text-1)", fontWeight: 500 }}>{title}</div>
      {hint && <div style={{ fontSize: 12 }}>{hint}</div>}
    </div>
  );
}
