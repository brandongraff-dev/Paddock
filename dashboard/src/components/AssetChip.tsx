import type { Asset, AssetKind } from "../api/types";
import { kindColor } from "../lib/color";
import { useStore } from "../state/store";
import { ClassificationChip } from "./Classification";

interface Props {
  asset?: Partial<Asset> & { id?: string; kind: AssetKind; value: string };
  onClick?: (id?: string) => void;
  dense?: boolean;
}

export default function AssetChip({ asset, onClick, dense }: Props) {
  const openDrawer = useStore((s) => s.openDrawer);
  if (!asset) return null;
  const color = kindColor(asset.kind);
  const handle = (ev: React.MouseEvent) => {
    ev.stopPropagation();
    if (onClick) return onClick(asset.id);
    if (asset.id) openDrawer({ kind: "asset", id: asset.id });
  };
  return (
    <button
      type="button"
      className="asset-chip"
      onClick={handle}
      style={dense ? { padding: "1px 6px" } : undefined}
      title={`${asset.kind} — ${asset.value}`}
    >
      <span className="dot" style={{ background: color }} />
      <span className="label">{asset.kind}</span>
      <span className="value">{asset.value}</span>
      {asset.classification && (
        <ClassificationChip c={asset.classification} compact />
      )}
    </button>
  );
}
