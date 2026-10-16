import type { Env } from '../types';
import { jsonResponse } from '../utils/response';

// GET /api/account/billing/vnext/subscription
//
// Official Bitwarden Android 2026.9.1 hits this endpoint after every vault
// unlock to render the premium/billing UI. Self-hosted servers without Stripe
// integration have no subscription to return; the official server answers
// 404 in that case and the SDK maps that to "free user" via recoverCatching
// in BillingServiceImpl.getSubscription. NodeWarden's pre-existing 404 was
// being recorded as a retrofit2.HttpException error in flight recorders, which
// confused on-call operators. We respond 200 with a minimal-but-valid
// BitwardenSubscriptionResponseJson (status: active, zero-cost cart, all
// lifecycle dates null) so the SDK has nothing to choke on and the user
// remains a fully unlocked premium user — matching the rest of NodeWarden
// where profile.premium is unconditionally true.
//
// Shape reference:
//   bitwarden/server — src/Api/Billing/Controllers/VNext/AccountBillingVNextController.cs
//   bitwarden/android — network/.../BitwardenSubscriptionResponseJson.kt
//
// ponytail: static self-hosted "premium-equivalent" subscription. Upgrade path
// is to introduce a license-file flow that stores a real subscription record
// and serves it here; the response shape stays identical.
export function handleGetBillingSubscription(_request: Request, _env: Env): Response {
  void _request;
  void _env;
  return jsonResponse({
    status: 'active',
    cart: {
      passwordManager: {
        seats: {
          translationKey: '',
          quantity: 1,
          cost: 0,
        },
      },
      cadence: 'annually',
      estimatedTax: 0,
    },
    storage: null,
    cancelAt: null,
    canceled: null,
    nextCharge: null,
    suspension: null,
    gracePeriod: null,
  });
}
