# Migrating to another relaychain - A complete guide

Document origin: https://github.com/zeitgeistpm/migration-guide

Author: [M.Sc. Harald Heckmann](https://github.com/sea212) (also known as [sea212](https://github.com/sea212))  
Mail: harald@zeitgeist.pm, mail@haraldheckmann.de

Reviewers: [B.Sc. Christopher Altmann](https://github.com/Chralt98) (chris@zeitgeist.pm), [Dr. Malte Kliemann](https://github.com/maltekliemann) (malte@zeitgeist.pm)

KILT has already proven in October 2022 that an almost [seamless migration of a parachain from Kusama to Polkadot](https://polkadot.network/blog/first-parachain-successfully-migrates-from-kusama-to-polkadot) (and any other Polkadot-like runtime) is possible.

> On October 3rd, KILT Protocol made history by becoming the first parachain to accomplish a full migration from the Kusama relaychain to the Polkadot Relay Chain.

KILT also provided some hints in regards to the process from a [technical perspective](https://medium.com/kilt-protocol/kilt-migration-to-polkadot-technical-overview-ebc8c1700750). Unfortunately there is no complete and precise documentation of the conceptual overview, the technical process in detail and the pitfalls associated to it. In this document, all of those elements are elaborated on and means to verify that the process succeeds in a close-to-production simulation before actually applying the migration on a production network are supplied. In addition, solutions to ensure a recovery in case of failure are presented. As Zeitgeist prepares to migrate from Kusama to Polkadot, this seems like the right time to document all of those steps for parachains that want to migrate in the future.

## Conceptual overview of the migration process
The starting position is that one parachain, the live parachain, would like to migrate from one relaychain to another. On the other relaychain another parachain, the shell parachain, awaits to be replaced by the live parachain:

![Starting position](img/overview.png)

*Figure: Starting position [(source)](img/source/overview.puml)*

The migration process is split into three parts:
1. A new chainspec (ideally within a client) is provided that's adjusted for the new relaychain.
2. The live parachain (migrate from) is prepared for migration (adjusted runtime) and halted.
3. After the live parachain halted, the shell parachain (migrate to) is instructed to inherit the logic and data from the live parachain.

It is assumed that the entity behind the migration already owns a live parachain and a shell parachain. The shell parachain includes some access to root (i.e. governance or ideally sudo) and the [`solo-to-para`](https://github.com/paritytech/cumulus/blob/e23a0f2dfbeda62b96c1bd88d83126e0d5770f9c/pallets/solo-to-para) pallet.
The first step is to provide a new chain specification file to all node operators, such that they can start to prepare the migration as early as possible on their side. The technical chapter describes all details.

Ideally this chain specification file is already compiled within a new client, that node operators can start to run simultaneously alongside the client that operates the live parachain to sync the potentially big chain data of the relaychain that handles the shell parachain. It is also possible to fetch a snapshot for the Polkadot chain data, however, that process is only recommended when the parachain uses the same version for the dependencies as the relaychain. Alternatively, the team can synchronize the relaychain data using the new chain specification and the client that should be used after migration and then provide it as a snapshot to all node operators.


Once the preparations from the node perspective were made, the preparation of the migration on the live parachain can be started. The preparation of the live parachain is depicted in the following figure.

![Preparing the parachain that should be migrated](img/prepare_migration_on_live_parachain.png)

*Figure: Preparing the parachain that should be migrated [(source)](img/source/prepare_migration_on_live_parachain.puml)*

To avoid forks and the need to blacklist blocks, it is mandatory that the live parachain is halted. This condition should enable anyone who is responsible for that process to experience an alien level of respect. The respect comes from the fact that should the migration fail and leave behind two broken parachains, the operation of the whole parachain is halted for at least two weeks, should the Fellowship (OpenGov, Gov2) or the Technical Committee (Gov1) not decide to fast track the repairing of the broken parachain. To avoid running into this situation, the manager account of the live parachain is unlocked, effectively granting the manager account all the privileges necessary to do the recovery. In rare circumstances halting the chain requires the transferral of slot swap leases. In that case a third parachain, the recovery parachain is introduced.

Before starting to interact with the parachain, the adjusted runtime has to be deployed. It will ensure proper operation after the migration and prevent potential error cases. More details are presented later in the technical section.

The first step of the migration is to unlock the parachain. This is achieved by instructing the live parachain to signal the command to unlock the parachain to the relaychain via an XCM. Only if the successful unlocking has be verified, the next steps should be taken.
After the unlocking, a case distinctions happens. Should the live parachain have a different `parachain_id` or `MqcHeads` than the shell parachain and the `MqcHeads` differ between the old and the new parachain id on the live parachain, *case A* can be executed (it is free, whereas *case B* requires funds). In that case, adjusting those values in the live parachain halts the chain. It can be recovered directly and no recovery parachain is necessary. Should the condition not be met, *case B* is the choice: Halting the live parachain by swapping the slot leases. In that case a recovery `parachain_id` and a associated recovery parathread have to be registered on the relaychain on which the live parachain operates on.

#### Case A: Different `parachain_id` or `MqcHeads` and `MqcHeads` differ between the old and new parachain id on the live parachain
When the `parachain_id` or `MqcHeads` differ between the live and shell parachain, adjustment of those values on the live parachain to equal those on the shell parachain is required, because the shell parachain will be overwritten by the live parachain. The `MqcHeads` must differ between both parachain ids on the live parachain to also effectively halt the parachain. However, it still is a parachain and has valid slot leases, thus it potentially can be recovered directly, given the prerequisite is met that the parachain was unlocked before halting it and thus allowing the manager account to overwrite the wasm code and head to a previous block at which the chain was still operational.

#### Case B: Equal `parachain_id` and `MqcHeads` or `MqcHeads` are equal between the old and new parachain id on the live parachain
When the `parachain_id` or `MqcHeads` are equal between the shell and the live parachain or the `MqcHeads` are equal between both parachain ids on the live parachain, there is no obvious way to halt the live parachain before the migration while ensuring at the same time that after the migration the migrated chain will be able to operate properly. The logical consequence of this is to withdraw the privilege to produce blocks from the live parachain chain. This is achieved by instructing the live parachain to signal the command to swap slot leases with another parathread, the recovery parathread, via XCM to the associated relaychain. It is important that the recovery parathread was provided with a functional genesis wasm and head to be able to recover the parachain in case of failure of the migration. Once the relaychain executes the instructions contained within the XCM, the slot leases are transferred from the live parachain to the recovery parathread. This effectively downgrades the live parachain to a parathread and upgrades the recovery parathread to a parachain, which from that point on will be capable to produce blocks if an operational genesis head and wasm were supplied during registration. On the other hand, the live parathread won't produce blocks anymore, unless block production time is explicitly bought. However, at the time of writing, the feature to buy execution time as a parathread is not available.
<br></br>

It is important that in either case, the halting instructions are only executed once it can be ensured that collators have had enough time to obtain the chain data of the relaychain that handles the shell parachain. In addition to that, both cases potentially have another constraint that has to be respected. Should the live parachain use the author-inherent pallet from the Nimbus framework, a storage element (`HighestSlotSeen`) has to be reset (condition: relaychain block number most increase) in the last block of the live parachain.
Now that the live parachain is halted, the migration to another relaychain can happen.

To execute the migration, the current [validation code (runtime)](https://docs.substrate.io/fundamentals/runtime-development/) and the current [head](https://substrate.stackexchange.com/a/7323/49) have to be extracted from the halted live parachain (that is a parathread now). Once those are available, they can be injected into the shell parachain, as described in the following figure.

![Replace shell parachain](img/solo-to-para-upgrade.png)

*Figure: Overwriting the runtime and head in the shell parachain with solo-to-para pallet [(source)](img/source/solo-to-para-upgrade.puml)*

The figure shows how the [`solo-to-para`](https://github.com/paritytech/cumulus/blob/e23a0f2dfbeda62b96c1bd88d83126e0d5770f9c/pallets/solo-to-para) pallet is utilized to apply the current [validation code (runtime)](https://docs.substrate.io/fundamentals/runtime-development/) and the current [head](https://substrate.stackexchange.com/a/7323/49) of the halted live parachain (which is a parathread by now) to the shell parachain. The shell parachain signals the relaychain that it wants to upgrade the current [validation code (runtime)](https://docs.substrate.io/fundamentals/runtime-development/) and the current [head](https://substrate.stackexchange.com/a/7323/49). Once the right time has come (which depends on the configuration of the relaychain), those upgrades are applied. At least one collator must remain active on the shell parachain until the runtime upgrade period passed and the runtime upgrade was finalized.

On Polkadot the upgrade delay is approximately 1 hour. During that time, every node operator should replace the shell chain data with the live chain data. Once the upgrade has been applied, operation should continue as expected. The following figure depicts the migration of the live parachain data.

![Node folder migration](img/node_folder_migration.png)

*Figure: Node folder migration [(source)](img/source/node_folder_migration.puml)*

Once the migration is completed and the migrated parachain produces blocks, the production runtime can be deployed after a runtime upgrade cool down period that is enforced by the relaychain.

## Technical subtleties
To prepare a mostly seamless migration from the perspective of a node operator, an adjusted chain specification file that ideally is compiled into a client should be provided. It should be ensured that the node operators have enough time to sync the relaychain that the shell parachain (migrate to) is attached to. The three main changes are:

1. A new and unused `protocolId`, such that the new network does not try to connect to peers in the old network.
2. A new `paraId` or `parachain_id` that matches the one on the shell parachain.
3. A new `relayChain` or `relay_chain`, that represents the name of the relaychain the shell parachain is attached to.

The following json file represents the Zeitgeist chain specification of the live parachain, which will be used as an example to highlight the necessary changes:


<pre><code>{
  "name": "Zeitgeist",
  "id": "zeitgeist",
  "chainType": "Live",
  "bootNodes": [
    --snip--
  ],
  <mark>"protocolId": "zeitgeist",</mark>
  "properties": {
      ---snip---
  },
  <mark>"parachain_id": 2101,</mark>
  <mark>"relay_chain": "kusama",</mark>
  "consensusEngine": null,
  "codeSubstitutes": {},
  "genesis": {
      --snip--
  }
}</code></pre>

The adjusted chain specification file that is used to synchronize the target relaychain looks like that:
<pre><code>{
  "name": "Zeitgeist",
  "id": "zeitgeist",
  "chainType": "Live",
  "bootNodes": [
    --snip--
  ],
  <mark>"protocolId": "zeitgeist-polkadot-v1",</mark>
  "properties": {
      ---snip---
  },
  <mark>"parachain_id": 2092,</mark>
  <mark>"relay_chain": "polkadot",</mark>
  "consensusEngine": null,
  "codeSubstitutes": {},
  "genesis": {
      --snip--
  }
}</code></pre>
At this point, all node operators and affected partners, such as block indexer service providers, RPC node providers, centralized exchanges, etc. should be contacted such that they have enough time to prepare the migration on their side.
<br></br>
The runtime that is going to be deployed on the live chain before the migration is executed must fulfill the following requirements to ensure a flawless migration:

- The `spec_version` within the `RuntimeVersion` struct must be greater than the `spec_version` of the runtime that is going to be replaced.
- The parachain runtime should accept that the relaychain blocks do not have to strictly increase. To achieve this, the following configuration within the `parchain_system` pallet has to be set:
```rust
type CheckAssociatedRelayNumber = cumulus_pallet_parachain_system::AnyRelayNumber;
```
- Use a proper `NetworkId` in XCM configuration.
- Include the [`utility`](https://github.com/paritytech/substrate/tree/ece32a72e934f6fe6705a7d418bbf3e71b4931ad/frame/utility) pallet to batch migration calls together.
- (If `MqcHeads` differ) Ensure that `system.kill_storage` is not call-filtered if the parachain received or sent XCM.
- (If `MqcHeads` or `parachain_id` differ) ensure that `system.set_storage` is not call-filtered if the `parachain_id` differs between the live and the shell parachain.
- Ensure that no of the required calls are call-filtered.
- (Case dependent) Consider any hooks that have an increased computational demand based on the interval between the timestamp of two blocks.
- Apply a call-filter to filter token transfers. This ensures that deposits to and withdrawals from centralized exchanges do fail shortly before the migration. It also ensures that no value was exchanged in case reverting blocks during a recovery is necessary. Using `pallet-balances`, `orml-tokens` and `orml-currencies`, the call filter can look like that:

```rust
#[derive(scale_info::TypeInfo)]
pub struct IsCallable;

impl Contains<Call> for IsCallable {
    fn contains(call: &Call) -> bool {
        match call {
            Call::Balances(_) => false,
            Call::Currencies(_) => false, 
            Call::Tokens(_) => false,
            _ => true,
        }
    }
}

impl frame_system::Config for Runtime {
    // --snip--
    type BaseCallFilter = IsCallable;
    // --snip--
}
```

The runtime that is going to be deployed on the shell chain before the migration is executed must fulfill the following requirements to ensure a flawless migration:
- It must include the [`solo-to-para`](https://github.com/paritytech/cumulus/blob/e23a0f2dfbeda62b96c1bd88d83126e0d5770f9c/pallets/solo-to-para) pallet.
- It must include the [`sudo`](https://github.com/paritytech/substrate/tree/ece32a72e934f6fe6705a7d418bbf3e71b4931ad/frame/sudo) pallet and use a sudo key that the entity responsible for the migration owns.

Once those prerequisites are met, the migration can be started. First, the migration runtime (that contains the [`solo-to-para`](https://github.com/paritytech/cumulus/blob/e23a0f2dfbeda62b96c1bd88d83126e0d5770f9c/pallets/solo-to-para) and [`sudo`](https://github.com/paritytech/substrate/tree/ece32a72e934f6fe6705a7d418bbf3e71b4931ad/frame/sudo) pallet) should be deployed on the shell parachain. Now the shell parachain is subject to a runtime upgrade cool down period defined by the associated relaychain. The runtime upgrade delay defined by the relaychain should be respected, as a new runtime is deployed on the shell parachain during the migration. To avoid unnecessary downtime, the cool down on the shell parachain should already have passed before continuing with the next steps.

Next, the live parachain is prepared. It is highly encouraged to use governance proposals that outline all the steps that are about to be taken, such that the ecosystem has enough time to review, discuss and finally approve or reject the procedure.

In any case, the first step is to unlock the manager account. This is the call data for the Zeitgeist parachain: 
```
0x7a000101000210000400000000070010a5d4e81300000000070010a5d4e8010700bca0650106000300943577184604350800000d010004000101007061726135080000000000000000000000000000000000000000000000000000
```
[(Decode)](https://polkadot.js.org/apps/?rpc=wss%3A%2F%2Fzeitgeist-rpc.dwellir.com#/extrinsics/decode/0x7a000101000210000400000000070010a5d4e81300000000070010a5d4e8010700bca0650106000300943577184604350800000d010004000101007061726135080000000000000000000000000000000000000000000000000000)

- Change the first two bytes of the calldata to represent the pallet index of `polkadot-xcm` and the following two bytes to represent the `send` call inside your runtime.
- Change the calldata within the `Transact` XCM instruction, it looks like that: [`0x460435080000`](https://polkadot.js.org/apps/?rpc=wss%3A%2F%2Fkusama-rpc.polkadot.io#/extrinsics/decode/0x460435080000). The `para` field within the call should represent the `parachain_id` from the live parachain. If the migration should happen from Kusama to another relaychain, the [Kusama websocket endpoint](https://polkadot.js.org/apps/?rpc=wss%3A%2F%2Fkusama-rpc.polkadot.io#/extrinsics) can be utilized to achieve that (decode calldata, modify, copy new calldata).
- Change the `AccountId` within the `DepositAsset` instruction to the address of your sovereign account. You can use [Moonbeams xcm-tools](https://github.com/PureStake/xcm-tools) to retrieve that address: `ts-node calculate-sovereign-account.ts  --para-id <live_para_id> --relay <relay-of-live-para>`
- Should the relaychain associated to the live parachain have a number of decimal fractional places for their native token that differs from 12, the balances in the call also have to be adjusted accordingly. In this example it is assumed that Kusama is used and 1 KSM is available in the parachain sovereign account.

*Note: The calldata starts with a pallet index and call index. Those can change, should the call index or the call index have changed during an update*

After the unlocking of the parachain was verified, the next step is deploy the runtime on the live parachain that is used during the migration. This is achieved by the standard procedure of upgrading a runtime on a parachain by invoking `parachainSystem.authorizeUpgrade` followed by `parachainSystem.enactAuthorizedUpgrade`.

Once the migration runtime was deployed, the potential adjustment of crucial storage values and the halting of the live parachain can happen on a case-by-case basis. Should the live parachain use the [`author-inherent`](https://github.com/PureStake/nimbus/blob/982b24fe292f11d6b79f476380c896b9c663a5e4/pallets/author-inherent/src/lib.rs#L98) pallet from the Nimbus framework, the storage `HighestSlotSeen` within it has to be reset (condition: relaychain block number has to increase) at exactly the same block at which the chain is halted, since this value is set at every new block. Ignoring this will result in a failed migration and a migrated parachain that does not produce blocks. `System.kill_storage` can be used to reset the value. The call should be batched in an all-or-nothing transaction using `Utility.batch_all`. This is the calldata to reset `AuthorInherent::HighestSlotSeen` (note that it changes when your instance of the pallet has a different name in the runtime):
```
0x00060480ab2a8d5eca218f218c6fda6b1d22bb926bc171ab77f6a731a6e80c34ee1eda19
```
[(Decode)](https://polkadot.js.org/apps/?rpc=wss%3A%2F%2Fzeitgeist-rpc.dwellir.com#/extrinsics/decode/0x00060480ab2a8d5eca218f218c6fda6b1d22bb926bc171ab77f6a731a6e80c34ee1eda19)
- Change the first two bytes of the calldata to represent the pallet index of `system` and the call index of `kill_storage` inside your runtime.
- Change the second tuple value to the scale-encoded `HighestSlotSeen` storage value within the `author-inherent` pallet on the live parachain.

#### Case A: Different `parachain_id` or `MqcHeads` and `MqcHeads` differ between the old and new parachain id on the live parachain
In this case, the `parachain_id` and/or the `MqcHeads` are set to appropriate values used on the shell parachain.

Set `ParachainInfo::parachain_id` to the one used in 
the shell parachain: 
```
0x000504800d715f2646c8f85767b5d2764bb2782604a74d81251e398fd8a0a4d55023bb3f102c080000
```
[(Decode)](https://polkadot.js.org/apps/?rpc=wss%3A%2F%2Fzeitgeist-rpc.dwellir.com#/extrinsics/decode/0x000504800d715f2646c8f85767b5d2764bb2782604a74d81251e398fd8a0a4d55023bb3f102c080000)
- Change the first two bytes of the calldata to represent the pallet index of `system` and the call index of `set_storage` inside your runtime.
- Change the second tuple value to the scale-encoded `parachain_id` of your shell parachain. It can be retrieved by querying the raw key `0x0d715f2646c8f85767b5d2764bb2782604a74d81251e398fd8a0a4d55023bb3f` on the shell parachain (assuming the correct `parachain_id` is already set there).

Reset `MqcHeads`: 
```
0x0006088045323df7cc47150b3930e2666b0aa313911a5dd3f1155f5b7d0c5aa102a757f98045323df7cc47150b3930e2666b0aa3133dca42deb008c6559ee789c9b9f70a2c
```
[(Decode)](https://polkadot.js.org/apps/?rpc=wss%3A%2F%2Fzeitgeist-rpc.dwellir.com#/extrinsics/decode/0x0006088045323df7cc47150b3930e2666b0aa313911a5dd3f1155f5b7d0c5aa102a757f98045323df7cc47150b3930e2666b0aa3133dca42deb008c6559ee789c9b9f70a2c)
- Change the first two bytes of the calldata to represent the pallet index of `system` and the call index of `kill_storage` inside your runtime.
- In this example the storage for `parachainSystem.lastDmqMqcHead` and `parachainSystem.lastHrmpMqcHeads` are reset. In case the shell parachain already received or sent XCM, those must be set to the values the relaychain of the shell parachain holds.

Both extrinsics **must be executed together in the same block**, as either one of them will halt the live parachain. The `utility.batch_all` dispatchable call can be utilized to achieve this.

#### Case B: Equal `parachain_id` and `MqcHeads` or `MqcHeads` are equal between the old and new parachain id on the live parachain
The first step is to reserve a `parachain_id` on the same relaychain that the live parachain is using by invoking the `registrar.reserve` and `registrar.register` dispatchable call. It must be ensured that a working genesis state and a working genesis wasm is included that contains `XCM` functionality and the `Sudo` pallet.

The second step is to instruct the relaychain to swap slot leases on behalf of the recovery parathread by invoking `registrar.swap` using the manager account. `id` should contain the `parachain_id` of the recovery parathread and `other` should contain the `parachain_id` of the live parachain.

The third step is to fund the parachain sovereign account. It has to be ensured that the parachain sovereign account is funded on the relaychain of the live parachain, such that the parachain can pay the execution of the instructions contained within the XCM. [Moonbeam's xcm-tools](https://github.com/PureStake/xcm-tools) can be used to retrieve the address of the parachain sovereign account: `ts-node calculate-sovereign-account.ts  --para-id <live_para_id> --relay <relay-of-live-para>`

If the `parachain_id` and/or `MqcHeads` have to be set as well, because they differ between the live parachain and the shell parachain, they have to be set **before** executing the slot lease swap. It is recommended to the batch those calls with the instruction to swap slot leases. Requesting a slot lease swap with another parachain is achieved by instructing the relaychain to swap slot leases on behalf of the live parachain by utilizing XCM. This is the calldata:

```
0x7a000101000210000400000000070010a5d4e81300000000070010a5d4e8010700bca0650106000300943577284603e7070000400800000d0100040001010070617261e7070000000000000000000000000000000000000000000000000000
```
[(Decode)](0x7a000101000210000400000000070010a5d4e81300000000070010a5d4e8010700bca0650106000300943577284603e7070000400800000d0100040001010070617261e7070000000000000000000000000000000000000000000000000000)
- Change the first two bytes of the calldata to represent the pallet index of `polkadot-xcm` and the following two bytes to represent the `send` call inside your runtime.
- Change the calldata within the `Transact` XCM instruction, it looks like that: [`0x4603e707000040080000`](https://polkadot.js.org/apps/?rpc=wss%3A%2F%2Fkusama-rpc-tn.dwellir.com#/extrinsics/decode/0x4603e707000040080000). The `id` field within the call should represent the `parachain_id` of the live parachain. The `other` field should represent the parachain of the recovery parachain. If the migration should happen from Kusama to another relaychain, the [Kusama websocket endpoint](https://polkadot.js.org/apps/?rpc=wss%3A%2F%2Fkusama-rpc.polkadot.io#/extrinsics) can be utilized to achieve that (decode calldata, modify, copy new calldata).
- Change the `AccountId` within the `DepositAsset` instruction to the address of the sovereign account that's associated to the live parachain. [Moonbeam's xcm-tools](https://github.com/PureStake/xcm-tools) can be used to retrieve the address of the parachain sovereign account: `ts-node calculate-sovereign-account.ts  --para-id <live_para_id> --relay <relay-of-live-para>`
- Should the relaychain associated to the live parachain have a number of decimal fractional places for their native token that differs from 12, the balances in the call also have to be adjusted accordingly. In this example it is assumed that Kusama is used and 1 KSM is available in the parachain sovereign account.
<br></br>

Once successfully executed, the live parachain should halt in any case and if *Case B* is executed, additionally the live parachain should be downgraded to a parathread and the recovery parathread should be upgraded to a parachain and start producing blocks. Now the actual migration of the chain data and wasm code to the shell parachain can begin.
<br></br>

The last step is to overwrite the head and runtime from the shell parachain with the head data and latest runtime of the halted live parachain. The latest runtime should be ready at a know place. The latest head data from the halted live parachain can be fetched from the associated relaychain by querying the chain storage at `paras.heads(parachain_id)`, whereat `parachain_id` is the parachain id that was registered on and retrieved from the relaychain, i.e. the previous parachain id within `ParachainInfo::parachain_id` that was overwritten.

Finally, the invocation of `soloToPara.schedule_migration(code, head_data)` on the shell parachain will schedule the migration. `code` represents the latest runtime of the live parachain, while `head_data` represents the latest head data from the live parachain. Relaychains have an upgrade delay, on Polkadot it is 1 hour as of writing this document. Exactly one block before the hour has passed, the head data is overwritten and in the next block the active runtime will also be overwritten. At this point in time, all the node operators should have replaced their parachain chain data with the latest chain data from the live parachain after it halted and also have the relaychain data of the relaychain that is associated to the shell parachain ready. The new client utilizes this data and nodes should start to synchronize blocks starting from the halted block of the live parachain in a separated network.

Finally, the migration runtime can be replaced by a proper production runtime once the runtime upgrade cool down period has passed.

## Testing the migration
It is immensely important that the migration is tested before applying it to a production network to ensure familiarity with the process and to verify that the suggested approach is also applicable to the given context.

There are multiple approaches that can be pursued to test the migration. In any case, it should be ensured that the parachain and the relaychain both are as close to production as possible. Whatever approach is selected, those steps should be included:

1. Clone the state from all the (migration) parachains and relaychains that are involved in the migration.
2. Verify the migration in a simulated environment.

The second approach can happen manually, semi-automatic or fully automatic. Those tools can be utilized to achieve that:
1. [Zombienet](https://github.com/paritytech/zombienet)
2. [Chopsticks](https://github.com/AcalaNetwork/chopsticks)

Both have their pros and cons, evaluating those is not within the scope of this section.

Once the migration was successful within the simulated environment, the migration can be executed in the production environment. If a testnet parachain exists that uses a custom relaychain, it is recommended to execute the migration from the custom relaychain to Rococo first for the testnet.

## Recovery
The recovery process is case-dependent, just as the migration process is.

#### Case A: Different `parachain_id` or `MqcHeads`
In this case the live parachain had to be halted by providing an invalid pallet configuration in the given context of a relaychain, the following approach has to be applied to recover the parachain.  
It is impossible to provide a proper chain configuration after the latest block, since the block production is halted and thus no state changes can be introduced. Consequently, the chain has to be reverted back to a previous functioning state.  
The revert should incorporate the least number of blocks possible while offering enough time to cancel any scheduled operations related to the migration. At the same time, the revert should not surpass the block at which the migration runtime was deployed that filters calls to transfer any tokens, otherwise value might have already been exchanged for tokens that are returned to the sender after the revert.  
The client of the parachain should offer a `revert` subcommand, however, this command does not revert finalized blocks. In this case, the finalized block equals the best block. As a consequence, no blocks can be reverted using that approach. Instead, a new chain specification file that forks off a new network and excludes the blocks that should be reverted has to be provided to the network. At last the associated relaychain must overwrite the latest head of the live parachain. The recovery can be achieved following those steps:
1. Use the latest chainspec from the live parachain and
    1. Exclude the first block of a series of blocks that should be reverted by using the [badBlocks](https://substrate.stackexchange.com/a/435/49) feature.
    2. Copy the chainspec resulting from step 1.1 and change the `protocol_id`, i.e. `zeitgeist_v1` -> `zeitgeist_v2`.
2. Instruct the bootnode providers to delete the chain data of the live parachain and to use the chainspec created at step 1.1 to sync the live parachain excluding all `badBlocks`. At least one bootnode should maintain the chain data of the halted chain during that process.
3. After the bootnodes synchronized the live parachain and excluded the reverted blocks, they have to replace the chainspec that is used with the one generated in step 1.2.
4. The chainspec generated in step 1.2 should be distributed to every node operator now, ideally in form of a new client that automatically uses it.
5. Now the head of the live parachain has to be adjusted on the associated relaychain. It must represent the head of the latest block in the fork that does exclude the reverted blocks. The head of the latest block can be retrieved by using [a custom subcommand](https://github.com/zeitgeistpm/zeitgeist/blob/1f7ea6192eb9ad5921a99ad959e14d9065d8ca09/node/src/command.rs#L283-L298). After retrieval of the head, the manager account of the live parachain has to invoke [`registrar.set_current_head`](https://github.com/paritytech/polkadot/blob/5a43bc733024b6f2d4f1164db8991a393c8e14cb/runtime/common/src/paras_registrar.rs#L399-L407) to overwrite the head on the relaychain.
6. After the head was overwritten, the live parachain should continue to produce blocks. The governance body should cancel any scheduled calls that are part of the migration before any of those executes.
7. At last, after proper operation and cancellation of any migration related calls have been verified, the manager account should lock the parachain again by calling [`registar.add_lock`](https://github.com/paritytech/polkadot/blob/5a43bc733024b6f2d4f1164db8991a393c8e14cb/runtime/common/src/paras_registrar.rs#L373-L377). This removes the privileges of the manager account to act on behalf on the parachain. Should any problems occur now that halt the chain, the governance body of the associated relaychain has to be consulted to resolve the issues. Thus, this step should only be executed once absolute certain that the recovery was properly executed and succeeded.

#### Case B: Equal `parachain_id` and `MqcHeads`
This is the most forgiving case. Since the halting of the live parachain was not introduced by providing an invalid pallet configuration in the given context of a relaychain, but rather by just passing on the privilege to produce blocks, it is only necessary to return the slot leases and thus the privilege to produce blocks to the live parathread:
1. Run the last used live parachain chainspec using a `--base-path` that points to a backup of the live chain folder.
2. Send an XCM from the recovery parachain to the associated relaychain to unlock the manager account (see technical chapter for calldata).
3. Only if step 2. succeeds, send an XCM from the recovery parachain to the associated relaychain to instruct swapping slot leases with the live parathread (see technical chapter for calldata).
4. Use the manager account of the live parathread to instruct the associated relaychain to swap slot leases with the recovery parachain.

That should transfer the slot leases back to the live parathread from the recovery parachain, which downgrades the recovery parachain to a parathread and upgrades the live parathread back to a parachain, effectively granting it the privilege to produce blocks.
