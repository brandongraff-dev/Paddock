import { FAQ } from "./faqData";

/** Plain <details> accordion: no JS, keyboard friendly, and the answers stay in the DOM for search engines. */
export default function Faq() {
  return (
    <section className="lp-faq" id="faq">
      <div className="lp-section-head">
        <span className="lp-eyebrow mono">Questions</span>
        <h2>Straight answers.</h2>
      </div>
      <div className="lp-faq-list">
        {FAQ.map(([q, a]) => (
          <details key={q}>
            <summary>{q}<i aria-hidden="true" /></summary>
            <p>{a}</p>
          </details>
        ))}
      </div>
    </section>
  );
}
