// IPFS pinning. v1 stub: when IPFS_API is unset, we return an empty CID and
// the full bundle is still available on-chain via the BundleStored event.
// Wire a real pinning service (kubo / Pinata / web3.storage) by setting
// IPFS_API in .env and implementing pinBundle().

import { config } from "./config.js";

export interface PinnedBundle {
  cid: string; // empty string = not pinned
  pinned: boolean;
}

export async function pinBundle(_bundle: string): Promise<PinnedBundle> {
  if (!config.ipfsApi) {
    return { cid: "", pinned: false };
  }
  // TODO: real pinning (POST to config.ipfsApi). Left as a stub so the
  // pipeline runs end-to-end without an IPFS node; the on-chain event still
  // carries the full bundle, so verification works without IPFS.
  return { cid: "", pinned: false };
}
