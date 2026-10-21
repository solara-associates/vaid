/**
 * One plain-English sentence per vaid-mint reason code. No jargon, no reason
 * codes shown without this translation alongside them.
 */
import { VaidVerdict, ChainVerification } from 'vaid-mint';

export function translateVerdict(verdict: string): string {
  switch (verdict) {
    case VaidVerdict.Valid:
      return 'This credential is genuine and has not expired.';
    case VaidVerdict.Unparseable:
      return "This isn't a VAID credential at all. The text doesn't have the fields one needs.";
    case VaidVerdict.UnsupportedSigVersion:
      return 'This credential uses a signature format this page does not recognize.';
    case VaidVerdict.MalformedTrustDomain:
      return "The issuer's name on this credential is not a validly formed domain.";
    case VaidVerdict.IssuerMismatch:
      return 'This credential names a different key than the one you provided, so it cannot be checked against it.';
    case VaidVerdict.LineageInconsistent:
      return "This credential's record of who it came from does not add up.";
    case VaidVerdict.Inauthentic:
      return 'The signature does not match. Either this credential was altered after it was signed, or it was never signed by the key you provided.';
    case VaidVerdict.Expired:
      return 'This credential is genuine, but its validity window has passed.';
    case VaidVerdict.UnknownScopeKind:
      return 'This credential describes its permissions in a way this page does not recognize, so it refuses to guess.';
    case VaidVerdict.Revoked:
      return 'This credential has been withdrawn by its issuer.';
    case VaidVerdict.Indeterminate:
      return 'Whether this credential is still in good standing could not be determined here.';
    default:
      return `Unrecognized result: ${verdict}.`;
  }
}

export function translateChain(result: string): string {
  switch (result) {
    case ChainVerification.Attenuated:
      return 'Every step in this chain is genuine, and each one only narrows what the one before it allowed.';
    case ChainVerification.Inauthentic:
      return 'At least one credential in this chain is not genuine: altered, or not signed by the key you provided.';
    case ChainVerification.Unverifiable:
      return "This chain is missing a link. A credential refers to a parent that wasn't included, so the chain can't be fully checked.";
    case ChainVerification.NotAttenuated:
      return 'Somewhere in this chain, a credential grants itself more than the one that created it was allowed to hand out.';
    case ChainVerification.Expired:
      return "An earlier credential in this chain has passed its own expiry date, so the authority it passed down no longer stands, even though nothing was forged.";
    case ChainVerification.ConsentExpired:
      return 'A cross-organization handoff in this chain is genuine but its approval window has lapsed.';
    default:
      return `Unrecognized result: ${result}.`;
  }
}
