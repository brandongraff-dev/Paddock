import { useEffect, useState } from "react";

const REPO = "brandongraff-dev/cybersec";
const KEY = "paddock.stars.v1";

function fmt(n: number): string {
  if (n >= 1000) return `${(n / 1000).toFixed(n >= 10000 ? 0 : 1).replace(/\.0$/, "")}k`;
  return String(n);
}

/** GitHub mark + live star count + star. The count is fetched once an hour; with no data (or 0) it just says "Star". */
export default function GitHubStars() {
  const [stars, setStars] = useState<number | null>(null);

  useEffect(() => {
    try {
      const raw = localStorage.getItem(KEY);
      if (raw) {
        const c = JSON.parse(raw) as { n: number; t: number };
        setStars(c.n);
        if (Date.now() - c.t < 3_600_000) return;
      }
    } catch { /* storage unavailable */ }
    if (typeof fetch !== "function") return;
    let live = true;
    fetch(`https://api.github.com/repos/${REPO}`)
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (!live || !d || typeof d.stargazers_count !== "number") return;
        setStars(d.stargazers_count);
        try { localStorage.setItem(KEY, JSON.stringify({ n: d.stargazers_count, t: Date.now() })); } catch { /* ignore */ }
      })
      .catch(() => undefined);
    return () => { live = false; };
  }, []);

  return (
    <a className="lp-stars" href={`https://github.com/${REPO}`} target="_blank" rel="noreferrer" aria-label={stars ? `Star on GitHub, ${stars} stars` : "Star on GitHub"}>
      <svg width="20" height="20" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
        <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.6 7.6 0 0 1 4 0c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z" />
      </svg>
      {stars ? <span className="lp-stars-n">{fmt(stars)}</span> : <span className="lp-stars-n">Star</span>}
      <svg className="lp-stars-star" width="15" height="15" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
        <path d="M8 .25a.75.75 0 0 1 .67.42l1.88 3.8 4.2.61a.75.75 0 0 1 .42 1.28l-3.04 2.96.72 4.18a.75.75 0 0 1-1.09.79L8 12.31l-3.76 1.98a.75.75 0 0 1-1.09-.79l.72-4.18L.83 6.36a.75.75 0 0 1 .42-1.28l4.2-.61 1.88-3.8A.75.75 0 0 1 8 .25Z" />
      </svg>
    </a>
  );
}
