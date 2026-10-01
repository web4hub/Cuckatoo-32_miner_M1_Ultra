# View an Account

- **Method:** `GET`
- **Path:** `/accounts/{walletid}`
- **Operation ID:** `getStats`
- **Tags:** accounts

## Effective servers

- `https://ethw.2miners.com/api`
- `https://solo-ethw.2miners.com/api`
- `https://etc.2miners.com/api`
- `https://solo-etc.2miners.com/api`
- `https://kas.2miners.com/api`
- `https://solo-kas.2miners.com/api`
- `https://erg.2miners.com/api`
- `https://solo-erg.2miners.com/api`
- `https://nexs.2miners.com/api`
- `https://solo-nexa.2miners.com/api`
- `https://zec.2miners.com/api`
- `https://solo-zec.2miners.com/api`
- `https://btg.2miners.com/api`
- `https://solo-btg.2miners.com/api`
- `https://zeph.2miners.com/api`
- `https://solo-zeph.2miners.com/api`
- `https://rvn.2miners.com/api`
- `https://solo-rvn.2miners.com/api`
- `https://neox.2miners.com/api`
- `https://solo-neox.2miners.com/api`
- `https://xna.2miners.com/api`
- `https://solo-xna.2miners.com/api`
- `https://grin.2miners.com/api`
- `https://solo-grin.2miners.com/api`
- `https://mwc.2miners.com/api`
- `https://solo-mwc.2miners.com/api`
- `https://ctxc.2miners.com/api`
- `https://solo-ctxc.2miners.com/api`
- `https://ae.2miners.com/api`
- `https://solo-ae.2miners.com/api`
- `https://beam.2miners.com/api`
- `https://solo-beam.2miners.com/api`
- `https://ckb.2miners.com/api`
- `https://solo-ckb.2miners.com/api`
- `https://bch.2miners.com/api`
- `https://solo-bch.2miners.com/api`
- `https://quaisha.2miners.com/api`
- `https://solo-quaisha.2miners.com/api`

## Path parameters

- **`walletid` (required)**: `string`

  id of the wallet

## Responses

### 200 Returns the account info

**Content type:** `application/json`

schema: `AccountReturnModel`

- **`24hnumreward`**: `integer`, format: `int64`
- **`24hreward`**: `integer`, format: `int64`
- **`charts`**: `object`

  Charts data by algorithm (non-apiVersion:200 coins like AE, GRIN, MWC, BEAM). Keys are algorithm numbers.

  **Additional properties:**

  **Array of:**

  schema: `AccountChartModel`

  Chart data point for account hashrate history (non-apiVersion:200 coins like AE, GRIN, MWC, BEAM)
  - **`minerHash`**: `number`, format: `float`

    Miner hashrate
  - **`minerLargeHash`**: `number`, format: `float`

    Miner large hashrate (average)
  - **`timeFormat`**: `string`

    Formatted time string
  - **`workerOnline`**: `string`

    Number of online workers
  - **`x`**: `integer`, format: `int64`

    Unix timestamp
- **`currentHashrate`**: `number`, format: `float`

  Current hashrate (apiVersion:200 coins)
- **`currentHashrates`**: `object`

  Current hashrates by algorithm (non-apiVersion:200 coins like AE, GRIN, MWC, BEAM). Keys are algorithm numbers.

  **Additional properties:**

  `number`, format: `float`
- **`currentLuck`**: `string`
- **`hashrate`**: `number`, format: `float`

  Average hashrate (apiVersion:200 coins)
- **`hashrates`**: `object`

  Average hashrates by algorithm (non-apiVersion:200 coins like AE, GRIN, MWC, BEAM). Keys are algorithm numbers.

  **Additional properties:**

  `number`, format: `float`
- **`pageSize`**: `integer`, format: `int64`
- **`payments`**: `array`

  **Items:**

  schema: `PaymentModel`
  - **`amount`**: `integer`, format: `int64`
  - **`timestamp`**: `integer`, format: `int64`
  - **`tx`**: `string`
  - **`txFee`**: `integer`, format: `int64`

    Transaction fee
  - **`txKernelExcess`**: `string`

    Transaction kernel excess (coins like AE, GRIN, MWC, BEAM)
- **`paymentsTotal`**: `integer`, format: `int64`
- **`rewards`**: `array`

  **Items:**

  schema: `RewardsModel`
  - **`blockhash`**: `string`
  - **`blockheight`**: `integer`, format: `int64`
  - **`currentLuck`**: `number`, format: `float`
  - **`immature`**: `boolean`, default: `false`
  - **`orphan`**: `boolean`, default: `false`

    Whether the block is orphaned (non-apiVersion:200 coins like AE, GRIN, MWC, BEAM)
  - **`percent`**: `number`, format: `float`
  - **`reward`**: `integer`, format: `int64`
  - **`timestamp`**: `integer`, format: `int64`
  - **`uncle`**: `boolean`, default: `false`
- **`roundShares`**: `integer`, format: `int64`
- **`shares`**: `array of string`
- **`stats`**: `object`, schema: `StatsModel`
  - **`balance`**: `integer`, format: `int64`
  - **`blocksFound`**: `integer`, format: `int64`
  - **`immature`**: `integer`, format: `int64`
  - **`lastShare`**: `integer`, format: `int64`
  - **`paid`**: `integer`, format: `int64`
  - **`pending`**: `boolean`, default: `false`
- **`sumrewards`**: `array`

  **Items:**

  schema: `SumrewardsModel`
  - **`inverval`**: `integer`, format: `int64`
  - **`name`**: `string`
  - **`numreward`**: `integer`, format: `int64`
  - **`offset`**: `integer`, format: `int64`
  - **`reward`**: `integer`, format: `int64`
- **`workers`**: `object`, schema: `WorkerModel`
  - **`workerGroup`**: `object`, schema: `WorkerGroupModel`
    - **`hr`**: `number`, format: `float`
    - **`hr2`**: `number`, format: `float`
    - **`lastBeat`**: `string`
    - **`offline`**: `boolean`, default: `false`
- **`workersOffline`**: `integer`, format: `int64`
- **`workersOnline`**: `integer`, format: `int64`
- **`workersTotal`**: `integer`, format: `int64`

**Example:**

```json
{
  "currentHashrate": 1,
  "currentHashrates": {
    "additionalProperty": 1
  },
  "currentLuck": "",
  "hashrate": 1,
  "hashrates": {
    "additionalProperty": 1
  },
  "charts": {
    "additionalProperty": []
  },
  "pageSize": 1,
  "payments": [],
  "paymentsTotal": 1,
  "rewards": [],
  "roundShares": 1,
  "shares": [
    ""
  ],
  "stats": null,
  "sumrewards": [],
  "workers": null,
  "workersOffline": 1,
  "workersOnline": 1,
  "workersTotal": 1,
  "24hreward": 1,
  "24hnumreward": 1
}
```

**Content type:** `application/xml`

*Schema `AccountReturnModel` is shown above.*

**Example:**

Unable to generate an XML example.

## Schemas

- `SumrewardsModel` — shown above.
- `WorkerGroupModel` — shown above.
- `AccountReturnModel` — shown above.
- `PaymentModel` — shown above.
- `StatsModel` — shown above.
- `RewardsModel` — shown above.
- `WorkerModel` — shown above.
- `AccountChartModel` — shown above.

  # Get all Blocks

- **Method:** `GET`
- **Path:** `/blocks`
- **Operation ID:** `getStats`
- **Tags:** blocks

## Effective servers

- `https://ethw.2miners.com/api`
- `https://solo-ethw.2miners.com/api`
- `https://etc.2miners.com/api`
- `https://solo-etc.2miners.com/api`
- `https://kas.2miners.com/api`
- `https://solo-kas.2miners.com/api`
- `https://erg.2miners.com/api`
- `https://solo-erg.2miners.com/api`
- `https://nexs.2miners.com/api`
- `https://solo-nexa.2miners.com/api`
- `https://zec.2miners.com/api`
- `https://solo-zec.2miners.com/api`
- `https://btg.2miners.com/api`
- `https://solo-btg.2miners.com/api`
- `https://zeph.2miners.com/api`
- `https://solo-zeph.2miners.com/api`
- `https://rvn.2miners.com/api`
- `https://solo-rvn.2miners.com/api`
- `https://neox.2miners.com/api`
- `https://solo-neox.2miners.com/api`
- `https://xna.2miners.com/api`
- `https://solo-xna.2miners.com/api`
- `https://grin.2miners.com/api`
- `https://solo-grin.2miners.com/api`
- `https://mwc.2miners.com/api`
- `https://solo-mwc.2miners.com/api`
- `https://ctxc.2miners.com/api`
- `https://solo-ctxc.2miners.com/api`
- `https://ae.2miners.com/api`
- `https://solo-ae.2miners.com/api`
- `https://beam.2miners.com/api`
- `https://solo-beam.2miners.com/api`
- `https://ckb.2miners.com/api`
- `https://solo-ckb.2miners.com/api`
- `https://bch.2miners.com/api`
- `https://solo-bch.2miners.com/api`
- `https://quaisha.2miners.com/api`
- `https://solo-quaisha.2miners.com/api`

## Responses

### 200 Returns a list of all Block

**Content type:** `application/json`

schema: `BlockReturnModel`

- **`candidates`**: `array`

  **Items:**

  schema: `CandidatesModel`
  - **`difficulty`**: `number`, format: `float`
  - **`finder`**: `string`
  - **`hash`**: `string`
  - **`height`**: `integer`, format: `int64`
  - **`orphan`**: `boolean`, default: `false`
  - **`reward`**: `integer`, format: `int64`
  - **`shares`**: `number`, format: `float`
  - **`timestamp`**: `integer`, format: `int64`
  - **`uncle`**: `boolean`, default: `false`
  - **`uncleHeight`**: `integer`, format: `int64`
- **`candidatesTotal`**: `integer`, format: `int64`
- **`immature`**: `array`

  **Items:**

  schema: `ImMaturedModel`
  - **`difficulty`**: `number`, format: `float`
  - **`finder`**: `string`
  - **`hash`**: `string`
  - **`height`**: `integer`, format: `int64`
  - **`orphan`**: `boolean`, default: `false`
  - **`reward`**: `integer`, format: `int64`
  - **`shares`**: `number`, format: `float`
  - **`timestamp`**: `integer`, format: `int64`
  - **`uncle`**: `boolean`, default: `false`
  - **`uncleHeight`**: `integer`, format: `int64`
- **`immatureTotal`**: `integer`, format: `int64`
- **`luck`**: `object`, schema: `LuckModel`
  - **`luckNumber`**: `object`, schema: `LuckNumberModel`
    - **`luck`**: `number`, format: `float`
    - **`orphanRate`**: `number`, format: `double`
- **`matured`**: `array`

  **Items:**

  schema: `MaturedModel`
  - **`difficulty`**: `number`, format: `float`
  - **`finder`**: `string`
  - **`hash`**: `string`
  - **`height`**: `integer`, format: `int64`
  - **`orphan`**: `boolean`, default: `false`
  - **`reward`**: `integer`, format: `int64`
  - **`shares`**: `number`, format: `float`
  - **`timestamp`**: `integer`, format: `int64`
  - **`uncle`**: `boolean`, default: `false`
  - **`uncleHeight`**: `integer`, format: `int64`
- **`maturedTotal`**: `integer`, format: `int64`

**Example:**

```json
{
  "candidates": [],
  "candidatesTotal": 1,
  "immature": [],
  "immatureTotal": 1,
  "luck": null,
  "matured": [],
  "maturedTotal": 1
}
```

**Content type:** `application/xml`

*Schema `BlockReturnModel` is shown above.*

**Example:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<BlockReturnModel>
  <candidatesTotal>1</candidatesTotal>
  <immatureTotal>1</immatureTotal>
  <luck xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="true"/>
  <maturedTotal>1</maturedTotal>
</BlockReturnModel>
```

## Schemas

- `LuckModel` — shown above.
- `CandidatesModel` — shown above.
- `ImMaturedModel` — shown above.
- `MaturedModel` — shown above.
- `BlockReturnModel` — shown above.
- `LuckNumberModel` — shown above.

# Get all Miners

- **Method:** `GET`
- **Path:** `/miners `
- **Operation ID:** `getMiner`
- **Tags:** miners&#x20;

## Effective servers

- `https://ethw.2miners.com/api`
- `https://solo-ethw.2miners.com/api`
- `https://etc.2miners.com/api`
- `https://solo-etc.2miners.com/api`
- `https://kas.2miners.com/api`
- `https://solo-kas.2miners.com/api`
- `https://erg.2miners.com/api`
- `https://solo-erg.2miners.com/api`
- `https://nexs.2miners.com/api`
- `https://solo-nexa.2miners.com/api`
- `https://zec.2miners.com/api`
- `https://solo-zec.2miners.com/api`
- `https://btg.2miners.com/api`
- `https://solo-btg.2miners.com/api`
- `https://zeph.2miners.com/api`
- `https://solo-zeph.2miners.com/api`
- `https://rvn.2miners.com/api`
- `https://solo-rvn.2miners.com/api`
- `https://neox.2miners.com/api`
- `https://solo-neox.2miners.com/api`
- `https://xna.2miners.com/api`
- `https://solo-xna.2miners.com/api`
- `https://grin.2miners.com/api`
- `https://solo-grin.2miners.com/api`
- `https://mwc.2miners.com/api`
- `https://solo-mwc.2miners.com/api`
- `https://ctxc.2miners.com/api`
- `https://solo-ctxc.2miners.com/api`
- `https://ae.2miners.com/api`
- `https://solo-ae.2miners.com/api`
- `https://beam.2miners.com/api`
- `https://solo-beam.2miners.com/api`
- `https://ckb.2miners.com/api`
- `https://solo-ckb.2miners.com/api`
- `https://bch.2miners.com/api`
- `https://solo-bch.2miners.com/api`
- `https://quaisha.2miners.com/api`
- `https://solo-quaisha.2miners.com/api`

## Responses

### 200 Returns a list of all Miners

**Content type:** `application/json`

schema: `MinerReturnModel`

- **`hashrate`**: `number`, format: `float`
- **`miners`**: `object`, schema: `MinerModel`
  - **`minerUid`**: `object`, schema: `MinerUidModel`
    - **`height`**: `integer`, format: `int64`
    - **`lastBeat`**: `integer`, format: `int64`
    - **`offline`**: `boolean`, default: `false`
- **`minersTotal`**: `integer`, format: `int64`
- **`now`**: `integer`, format: `int64`

**Example:**

```json
{
  "hashrate": 1,
  "miners": null,
  "minersTotal": 1,
  "now": 1
}
```

**Content type:** `application/xml`

*Schema `MinerReturnModel` is shown above.*

**Example:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<MinerReturnModel>
  <hashrate>1</hashrate>
  <miners xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="true"/>
  <minersTotal>1</minersTotal>
  <now>1</now>
</MinerReturnModel>
```

## Schemas

- `MinerReturnModel` — shown above.
- `MinerModel` — shown above.
- `MinerUidModel` — shown above.

# Get all Payments

- **Method:** `GET`
- **Path:** `/payments`
- **Operation ID:** `getStats`
- **Tags:** payments

## Effective servers

- `https://ethw.2miners.com/api`
- `https://solo-ethw.2miners.com/api`
- `https://etc.2miners.com/api`
- `https://solo-etc.2miners.com/api`
- `https://kas.2miners.com/api`
- `https://solo-kas.2miners.com/api`
- `https://erg.2miners.com/api`
- `https://solo-erg.2miners.com/api`
- `https://nexs.2miners.com/api`
- `https://solo-nexa.2miners.com/api`
- `https://zec.2miners.com/api`
- `https://solo-zec.2miners.com/api`
- `https://btg.2miners.com/api`
- `https://solo-btg.2miners.com/api`
- `https://zeph.2miners.com/api`
- `https://solo-zeph.2miners.com/api`
- `https://rvn.2miners.com/api`
- `https://solo-rvn.2miners.com/api`
- `https://neox.2miners.com/api`
- `https://solo-neox.2miners.com/api`
- `https://xna.2miners.com/api`
- `https://solo-xna.2miners.com/api`
- `https://grin.2miners.com/api`
- `https://solo-grin.2miners.com/api`
- `https://mwc.2miners.com/api`
- `https://solo-mwc.2miners.com/api`
- `https://ctxc.2miners.com/api`
- `https://solo-ctxc.2miners.com/api`
- `https://ae.2miners.com/api`
- `https://solo-ae.2miners.com/api`
- `https://beam.2miners.com/api`
- `https://solo-beam.2miners.com/api`
- `https://ckb.2miners.com/api`
- `https://solo-ckb.2miners.com/api`
- `https://bch.2miners.com/api`
- `https://solo-bch.2miners.com/api`
- `https://quaisha.2miners.com/api`
- `https://solo-quaisha.2miners.com/api`

## Responses

### 200 Returns the list of Payments

**Content type:** `application/json`

schema: `PaymentReturnModel`

- **`payments`**: `array`

  **Items:**

  schema: `PaymentsModel`
  - **`amount`**: `integer`, format: `int64`
  - **`timestamp`**: `integer`, format: `int64`
  - **`totalPayees`**: `integer`, format: `int64`
  - **`tx`**: `string`
- **`paymentsTotal`**: `integer`, format: `int64`

**Example:**

```json
{
  "payments": [],
  "paymentsTotal": 1
}
```

**Content type:** `application/xml`

*Schema `PaymentReturnModel` is shown above.*

**Example:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<PaymentReturnModel>
  <paymentsTotal>1</paymentsTotal>
</PaymentReturnModel>
```

## Schemas

- `PaymentReturnModel` — shown above.
- `PaymentsModel` — shown above.

# Get all Stats

- **Method:** `GET`
- **Path:** `/stats`
- **Operation ID:** `getStats`
- **Tags:** stats

## Effective servers

- `https://ethw.2miners.com/api`
- `https://solo-ethw.2miners.com/api`
- `https://etc.2miners.com/api`
- `https://solo-etc.2miners.com/api`
- `https://kas.2miners.com/api`
- `https://solo-kas.2miners.com/api`
- `https://erg.2miners.com/api`
- `https://solo-erg.2miners.com/api`
- `https://nexs.2miners.com/api`
- `https://solo-nexa.2miners.com/api`
- `https://zec.2miners.com/api`
- `https://solo-zec.2miners.com/api`
- `https://btg.2miners.com/api`
- `https://solo-btg.2miners.com/api`
- `https://zeph.2miners.com/api`
- `https://solo-zeph.2miners.com/api`
- `https://rvn.2miners.com/api`
- `https://solo-rvn.2miners.com/api`
- `https://neox.2miners.com/api`
- `https://solo-neox.2miners.com/api`
- `https://xna.2miners.com/api`
- `https://solo-xna.2miners.com/api`
- `https://grin.2miners.com/api`
- `https://solo-grin.2miners.com/api`
- `https://mwc.2miners.com/api`
- `https://solo-mwc.2miners.com/api`
- `https://ctxc.2miners.com/api`
- `https://solo-ctxc.2miners.com/api`
- `https://ae.2miners.com/api`
- `https://solo-ae.2miners.com/api`
- `https://beam.2miners.com/api`
- `https://solo-beam.2miners.com/api`
- `https://ckb.2miners.com/api`
- `https://solo-ckb.2miners.com/api`
- `https://bch.2miners.com/api`
- `https://solo-bch.2miners.com/api`
- `https://quaisha.2miners.com/api`
- `https://solo-quaisha.2miners.com/api`

## Responses

### 200 Returns a list of all Stats

**Content type:** `application/json`

schema: `StatsReturnModel`

- **`candidatesTotal`**: `integer`, format: `int64`
- **`charts`**: `object`

  Pool charts by algorithm (non-apiVersion:200 coins like AE, GRIN, MWC, BEAM). Keys are algorithm numbers.

  **Additional properties:**

  **Array of:**

  schema: `PoolChartsModel`
  - **`netdiff`**: `number`, format: `float`
  - **`nethr`**: `number`, format: `float`
  - **`timeFormat`**: `string`
  - **`x`**: `integer`, format: `int64`
  - **`y`**: `number`, format: `float`
- **`hashrate`**: `number`, format: `float`

  Pool hashrate (apiVersion:200 coins)
- **`hashrates`**: `object`

  Pool hashrates by algorithm (non-apiVersion:200 coins like AE, GRIN, MWC, BEAM). Keys are algorithm numbers.

  **Additional properties:**

  `number`, format: `float`
- **`immatureTotal`**: `integer`, format: `int64`
- **`luck`**: `number`, format: `float`
- **`maturedTotal`**: `integer`, format: `int64`
- **`minersTotal`**: `integer`, format: `int64`
- **`nodes`**: `array`

  **Items:**

  schema: `NodeModel`
  - **`avgBlockTime`**: `string`
  - **`blockReward`**: `string`

    Block reward (present for AE and some other coins)
  - **`difficulty`**: `string`
  - **`height`**: `string`
  - **`lastBeat`**: `string`
  - **`minDiff`**: `string`

    Minimum difficulty (non-apiVersion:200 coins like AE, GRIN, MWC, BEAM)
  - **`name`**: `string`
  - **`networkhashps`**: `string`
  - **`primaryWeight31`**: `string`

    Primary weight for algorithm 31 (MWC)
  - **`primaryWeight32`**: `string`

    Primary weight for algorithm 32 (GRIN)
- **`now`**: `integer`, format: `int64`
- **`paymentsTotal`**: `integer`, format: `int64`
- **`poolCharts`**: `array`

  Pool charts (apiVersion:200 coins)

  **Items:**

  *Schema `PoolChartsModel` is shown above.*
- **`stats`**: `object`
  - **`eu_sessions`**: `integer`, format: `int64`

    Number of active EU sessions
  - **`lastBlockFound`**: `integer`, format: `int64`
  - **`nShares`**: `integer`, format: `int64`
  - **`roundShares`**: `number`, format: `float`
- **`workersTotal`**: `integer`, format: `int64`

  Total number of workers across all miners

**Example:**

```json
{
  "candidatesTotal": 1,
  "hashrate": 1,
  "hashrates": {
    "additionalProperty": 1
  },
  "charts": {
    "additionalProperty": []
  },
  "immatureTotal": 1,
  "luck": 1,
  "maturedTotal": 1,
  "minersTotal": 1,
  "nodes": [],
  "now": 1,
  "paymentsTotal": 1,
  "poolCharts": [],
  "stats": {
    "lastBlockFound": 1,
    "roundShares": 1,
    "nShares": 1,
    "eu_sessions": 1
  },
  "workersTotal": 1
}
```

**Content type:** `application/xml`

*Schema `StatsReturnModel` is shown above.*

**Example:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<StatsReturnModel>
  <candidatesTotal>1</candidatesTotal>
  <hashrate>1</hashrate>
  <hashrates>
    <additionalProperty>1</additionalProperty>
  </hashrates>
  <charts/>
  <immatureTotal>1</immatureTotal>
  <luck>1</luck>
  <maturedTotal>1</maturedTotal>
  <minersTotal>1</minersTotal>
  <now>1</now>
  <paymentsTotal>1</paymentsTotal>
  <stats>
    <lastBlockFound>1</lastBlockFound>
    <roundShares>1</roundShares>
    <nShares>1</nShares>
    <eu_sessions>1</eu_sessions>
  </stats>
  <workersTotal>1</workersTotal>
</StatsReturnModel>
```

## Schemas

- `StatsReturnModel` — shown above.
- `NodeModel` — shown above.
- `PoolChartsModel` — shown above.
# Get Worker Stats by Range

- **Method:** `GET`
- **Path:** `/workers/{walletid}/{workerid}/{range}`
- **Operation ID:** `getWorkerRange`
- **Tags:** workers

Returns hashrate data for a specific worker within a given time range. Available for apiVersion:200 coins (ETC, KAS, RVN, ZEC, ETHW, etc.).

## Effective servers

- `https://ethw.2miners.com/api`
- `https://solo-ethw.2miners.com/api`
- `https://etc.2miners.com/api`
- `https://solo-etc.2miners.com/api`
- `https://kas.2miners.com/api`
- `https://solo-kas.2miners.com/api`
- `https://erg.2miners.com/api`
- `https://solo-erg.2miners.com/api`
- `https://nexs.2miners.com/api`
- `https://solo-nexa.2miners.com/api`
- `https://zec.2miners.com/api`
- `https://solo-zec.2miners.com/api`
- `https://btg.2miners.com/api`
- `https://solo-btg.2miners.com/api`
- `https://zeph.2miners.com/api`
- `https://solo-zeph.2miners.com/api`
- `https://rvn.2miners.com/api`
- `https://solo-rvn.2miners.com/api`
- `https://neox.2miners.com/api`
- `https://solo-neox.2miners.com/api`
- `https://xna.2miners.com/api`
- `https://solo-xna.2miners.com/api`
- `https://grin.2miners.com/api`
- `https://solo-grin.2miners.com/api`
- `https://mwc.2miners.com/api`
- `https://solo-mwc.2miners.com/api`
- `https://ctxc.2miners.com/api`
- `https://solo-ctxc.2miners.com/api`
- `https://ae.2miners.com/api`
- `https://solo-ae.2miners.com/api`
- `https://beam.2miners.com/api`
- `https://solo-beam.2miners.com/api`
- `https://ckb.2miners.com/api`
- `https://solo-ckb.2miners.com/api`
- `https://bch.2miners.com/api`
- `https://solo-bch.2miners.com/api`
- `https://quaisha.2miners.com/api`
- `https://solo-quaisha.2miners.com/api`

## Path parameters

- **`walletid` (required)**: `string`

  id of the wallet
- **`workerid` (required)**: `string`

  id of the worker
- **`range` (required)**: `string`, possible values: `"5m", "30m", "6h"`

  time range for data

## Responses

### 200 Returns worker hashrate data for the specified range

**Content type:** `application/json`

schema: `WorkerRangeReturnModel`

Worker statistics for a specific time range (apiVersion:200 coins)

- **`charts`**: `object`

  Worker charts by algorithm. Keys are algorithm numbers.

  **Additional properties:**

  **Array of:**

  schema: `AccountChartModel`

  Chart data point for account hashrate history (non-apiVersion:200 coins like AE, GRIN, MWC, BEAM)
  - **`minerHash`**: `number`, format: `float`

    Miner hashrate
  - **`minerLargeHash`**: `number`, format: `float`

    Miner large hashrate (average)
  - **`timeFormat`**: `string`

    Formatted time string
  - **`workerOnline`**: `string`

    Number of online workers
  - **`x`**: `integer`, format: `int64`

    Unix timestamp
- **`currentHashrates`**: `object`

  Current worker hashrates by algorithm. Keys are algorithm numbers.

  **Additional properties:**

  `number`, format: `float`
- **`hashrates`**: `object`

  Average worker hashrates by algorithm. Keys are algorithm numbers.

  **Additional properties:**

  `number`, format: `float`

**Example:**

```json
{
  "charts": {
    "additionalProperty": []
  },
  "currentHashrates": {
    "additionalProperty": 1
  },
  "hashrates": {
    "additionalProperty": 1
  }
}
```

**Content type:** `application/xml`

*Schema `WorkerRangeReturnModel` is shown above.*

**Example:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<WorkerRangeReturnModel>
  <charts/>
  <currentHashrates>
    <additionalProperty>1</additionalProperty>
  </currentHashrates>
  <hashrates>
    <additionalProperty>1</additionalProperty>
  </hashrates>
</WorkerRangeReturnModel>
```

## Schemas

- `AccountChartModel` — shown above.
- `WorkerRangeReturnModel` — shown above.

