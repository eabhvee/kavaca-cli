import Stripe from "stripe";

// PLANTED VULN: a live Stripe secret key hard-coded into the source.
// This should be read from process.env, never committed.
const stripe = new Stripe("sk_live_FAKEfixturekey1234");

export async function charge(amount: number) {
  return stripe.paymentIntents.create({ amount, currency: "usd" });
}
