import { Link, useInRouterContext } from "react-router-dom";

/** Entry point from Reports to the trust-page manager (/reports/trust). */
export default function TrustShareLink() {
  const inRouter = useInRouterContext();
  const label = "Share trust page";
  const style = {
    display: "inline-flex",
    alignItems: "center",
    padding: "5px 12px",
    border: "1px solid var(--border)",
    borderRadius: 6,
    color: "var(--text-1)",
    fontSize: 13,
    textDecoration: "none",
  } as const;
  return inRouter ? (
    <Link to="/reports/trust" style={style}>{label}</Link>
  ) : (
    <a href="/reports/trust" style={style}>{label}</a>
  );
}
