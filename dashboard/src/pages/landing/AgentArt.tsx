import { useEffect, useState } from "react";
import DigitHorse from "../../brand/DigitHorse";

/** Painted art for an agent card. Falls back to the digit-horse plate until the illustration file exists. */
export default function AgentArt({ name, plate }: { name: string; plate: number }) {
  const src = `/agents/${name.toLowerCase()}.webp`;
  const [ok, setOk] = useState<boolean | null>(null);
  useEffect(() => {
    let live = true;
    const im = new Image();
    im.onload = () => live && setOk(true);
    im.onerror = () => live && setOk(false);
    im.src = src;
    return () => { live = false; };
  }, [src]);
  if (ok) return <img className="lp-card-art" src={src} alt="" loading="lazy" decoding="async" />;
  return <DigitHorse still={plate} strays={false} body={0.5} />;
}
