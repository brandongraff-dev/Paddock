import { useEffect } from "react";
import { Link } from "react-router-dom";
import HorseMark from "../brand/HorseMark";
import Wordmark from "../brand/Wordmark";
import "../styles/landing.css";

export default function NotFound() {
  useEffect(() => {
    document.title = "Page not found · Paddock";
    const m = document.createElement("meta");
    m.name = "robots";
    m.content = "noindex";
    document.head.appendChild(m);
    return () => { m.remove(); document.title = "Paddock"; };
  }, []);
  return (
    <main className="lp-404">
      <Link to="/welcome" className="lp-brand"><HorseMark size={30} /><Wordmark height={22} /></Link>
      <div>
        <p className="mono">404</p>
        <h1>This path leads nowhere.</h1>
        <p className="lp-404-sub">The page you asked for doesn&apos;t exist, or has moved.</p>
        <Link to="/welcome" className="lp-run lp-404-btn">Back to Paddock <span aria-hidden="true">→</span></Link>
      </div>
    </main>
  );
}
