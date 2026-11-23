# Swiper Orbs, Trading, and Competitive Scoring

## Orb catalog (Supabase-managed)

Orb definitions are read dynamically from these public, read-only tables:

- `public.swiper_orb_rarities`
  - `name`: unique rarity label
  - `level`: positive, unique rarity tier; higher levels receive a stronger luck multiplier
  - `default_chance`: positive relative weight for the rarity
  - `color`: six-digit hex accent used in the UI
  - `effect`: visual effect key
  - `active`: disable a rarity without deleting it
- `public.swiper_orbs`
  - `name`: unique display name
  - `rarity`: references `swiper_orb_rarities.name`
  - `image_url`: HTTPS image/texture URL
  - `custom_chance`: optional positive relative weight; NULL uses the rarity's default weight
  - `active`: disable an orb without deleting its inventory history

### Add a rarity

Run this in the Supabase SQL editor:

```sql
insert into public.swiper_orb_rarities
  (name, level, default_chance, color, effect)
values
  ('Abyssal', 16, 0.0000002, '#7864c9', 'abyssal');
```

Use a new unused `level`. The `default_chance` values are relative weights, not percentages that must sum to 100.

### Add an orb

Upload an image to a public HTTPS location (for example, a public Supabase Storage bucket), then run:

```sql
insert into public.swiper_orbs
  (name, rarity, image_url, custom_chance)
values
  ('Abyssal Core', 'Abyssal',
   'https://YOUR_PROJECT.supabase.co/storage/v1/object/public/orbs/abyssal-core.webp',
   null);
```

No `index.html` edit is required. Active orb definitions are fetched dynamically.

### Drop calculation

For every active orb, its base weight is:

- `custom_chance`, when present; otherwise
- `rarity.default_chance / active_orb_count_for_that_rarity`

Pack luck multiplies that weight by:

`luck_multiplier ^ ((rarity.level - 1) / 3)`

The database normalizes by the sum of all active weights and selects the reward server-side. The pack row is locked and marked opened in the same transaction that increments the owner's orb inventory. A pack cannot award twice.

## Buying and opening packs

The Orbs screen lets a signed-in player buy one pack at a time and choose a luck multiplier from 1× to 100×. It uses the existing `swiper_shop_buy_pack(p_quantity, p_luck)` wallet transaction; the current price is `ceil(luck × 10)` coins. Pack purchases create the existing `item_pack` crate rows, which are opened through the orb reward function.

## Inventory and equipment

- `swiper_orb_inventory` stores each account's quantity and trade-reserved quantity.
- `swiper_equipped_orbs` stores up to six persistent equipped orb slots.
- Inventory and equipped rows are readable only by the owning non-anonymous account.
- Clients cannot insert, update, or delete inventory/equipment rows directly. Use `swiper_orb_equip` and `swiper_orb_unequip`.
- Pack opening uses `swiper_orb_open_pack`; the legacy `swiper_shop_open_crate` endpoint now routes to the orb reward path.

## Trading

The Trade screen uses these server-owned tables:

- `swiper_trades`
- `swiper_trade_items`
- `swiper_trade_notifications`

Use the RPCs rather than writing those tables directly:

- `swiper_trade_send_request(p_username)`
- `swiper_trade_respond(p_trade_id, p_accept)`
- `swiper_trade_set_offer(p_trade_id, p_orb_id, p_quantity)` — use quantity 0 to remove an offer
- `swiper_trade_confirm(p_trade_id)`
- `swiper_trade_cancel(p_trade_id)`
- `swiper_trade_cleanup_expired()`

Offers reserve inventory. Both participants must offer at least one orb and confirm the same offer state. The final confirmation locks both players' inventory rows in deterministic order, revalidates reserved quantities, transfers both sides in one transaction, and writes notifications. Equipped orbs cannot be offered; reserved orbs cannot be equipped. Active trades expire after ten minutes and release their reservations.

## Competitive online scores

Competitive match score is calculated from the server-side `score_started_at` clock; the client-provided `p_score` argument is ignored. The first heartbeat after the shared lobby countdown anchors the scoring clock to the in-game countdown. The server records one `swipe_scores` row per user/room and one `swipe_match_results` row per participant when the match is completed.

- Direct client writes to `swipe_room_players` and `swipe_rooms` are revoked.
- Direct `quick` leaderboard inserts are rejected; Practice and Bot submissions retain their existing path.
- Competitive clients cannot pause or restart a live match.
- A disconnect or manual leave ends the match as `no_contest`; it does not award a win.
- Normal elimination compares the server-recorded survival scores by team.

## Verification

The database routines were exercised inside rollback-only test transactions for pack award/equip/duplicate protection, two-party trade completion, trade expiry/reservation release, and server-derived competitive scoring. Those tests left no test inventory, packs, trades, or match rows behind.

The frontend scripts were syntax-checked after the update. A real-device browser session is still needed to verify visual behavior, live account-to-account trades, and multiplayer animation timing.
