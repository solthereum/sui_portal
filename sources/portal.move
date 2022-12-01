module portal::portal {
        use sui::ecdsa;
        use std::vector;
        use sui::coin::{Self, Coin};
        use sui::object::{Self, UID};
        use sui::transfer;
        use sui::tx_context::{Self, TxContext};
        use sui::dynamic_object_field;
        use portal::cursor::{Self, Cursor};
        use portal::lock::{Self, TreasuryLock};
        //use portal::wpETH;//::{Self, WPETH};
        use sui::event;

        const Guardian_address: address = @0x6e7BEa5B3247138621E5693ceb0e6b25ebc48Fc9;

        struct Payload has store {
                time: u64,
                who: address,
                amount: u64,
                to: address,
        }

        struct BAA has store, key {
                id: UID,
                guardian: address,
                sig_len: u64,
                payload: Payload,
                tx: vector<u8>,
                tx_id: u128,
                messageHash: vector<u8>,
                signature: vector<u8>,
                confirm: bool
        }

        struct PoolBAA has key {
                id: UID,
        }

        struct EmitBAA<phantom T> has copy, drop {
                _sender: address,
                _amount: u64,
                _to: address,
        }

        fun init(_: &mut TxContext) {}

        public entry fun create_pool(ctx: &mut TxContext) {
                let pool = PoolBAA {
                        id: object::new(ctx),
                };
                transfer::share_object(pool);
        }

        public fun deserialize_u64(cur: &mut Cursor<u8>, length: u64): u64 {
                let res: u64 = 0;
                let i = 0;
                while (i < length) {
                        let b = cursor::poke(cur);
                        res = (res << 8) + (b as u64);
                        i = i + 1;
                };
                res
        }

        public fun deserialize_u128(cur: &mut Cursor<u8>, length: u64): u128 {
                let res: u128 = 0;
                let i = 0;
                while (i < length) {
                        let b = cursor::poke(cur);
                        res = (res << 8) + (b as u128);
                        i = i + 1;
                };
                res
        }

        public fun ecrecover_to_eth_address(signature: vector<u8>, hashed_msg: vector<u8>, guardian: address): bool {
                let v = vector::borrow_mut(&mut signature, 64);
                if (*v == 27) {
                        *v = 0;
                } else if (*v == 28) {
                        *v = 1;
                } else if (*v > 35) {
                        *v = (*v - 1) % 2;
                };

                let pubkey = ecdsa::ecrecover(&signature, &hashed_msg);
                let uncompressed = ecdsa::decompress_pubkey(&pubkey);
                let uncompressed_64 = vector::empty<u8>();
                let i = 1;
                while (i < 65) {
                        let value = vector::borrow(&uncompressed, i);
                        vector::push_back(&mut uncompressed_64, *value);
                        i = i + 1;
                };
                let hashed = ecdsa::keccak256(&uncompressed_64);
                let addr = vector::empty<u8>();
                let i = 12;
                while (i < 32) {
                        let value = vector::borrow(&hashed, i);
                        vector::push_back(&mut addr, *value);
                        i = i + 1;
                };

                let guardian_address = object::address_from_bytes(addr);
                assert!(guardian_address == guardian, 13);
                guardian_address == guardian
        }

        public entry fun verifyBAA<WPETH>(pool: &mut PoolBAA, lock: &mut TreasuryLock<WPETH>, baa: vector<u8>, ctx: &mut TxContext) {
                let guardian_bytes = vector::empty<u8>();
                let i = 0;
                while (i < 20) {
                        let value = vector::borrow(&baa, i);
                        vector::push_back(&mut guardian_bytes, *value);
                        i = i + 1;
                };
                let guardian = object::address_from_bytes(guardian_bytes);

                let sig_len_cur = vector::empty<u8>();
                let i = 23;
                while (i < 24) {
                        let value = vector::borrow(&baa, i);
                        vector::push_back(&mut sig_len_cur, *value);
                        i = i + 1;
                };
                let cur = cursor::create(sig_len_cur);
                let sig_len = deserialize_u64(&mut cur, vector::length(&sig_len_cur));
                cursor::destroy_empty(cur);

                let payload_un = vector::empty<u8>();
                let i = 24;
                while (i < 106) {
                        let value = vector::borrow(&baa, i);
                        vector::push_back(&mut payload_un, *value);
                        i = i + 1;
                };

                let messageHash = vector::empty<u8>();
                let i = 106;
                while (i < 138) {
                        let value = vector::borrow(&baa, i);
                        vector::push_back(&mut messageHash, *value);
                        i = i + 1;
                };

                let signature = vector::empty<u8>();
                let i = 138;
                while (i < vector::length(&baa)) {
                        let value = vector::borrow(&baa, i);
                        vector::push_back(&mut signature, *value);
                        i = i + 1;
                };

                let time_cur = vector::empty<u8>();
                let i = 0;
                while (i < 5) {
                        let value = vector::borrow(&payload_un, i);
                        vector::push_back(&mut time_cur, *value);
                        i = i + 1;
                };
                let cur = cursor::create(time_cur);
                let time = deserialize_u64(&mut cur, vector::length(&time_cur));
                cursor::destroy_empty(cur);

                let who_bytes = vector::empty<u8>();
                let i = 5;
                while (i < 25) {
                        let value = vector::borrow(&payload_un, i);
                        vector::push_back(&mut who_bytes, *value);
                        i = i + 1;
                };
                let who = object::address_from_bytes(who_bytes);


                let amount_cur = vector::empty<u8>();
                let i = 25;
                while (i < 30) {
                        let value = vector::borrow(&payload_un, i);
                        vector::push_back(&mut amount_cur, *value);
                        i = i + 1;
                };
                let cur = cursor::create(amount_cur);
                let amount = deserialize_u64(&mut cur, vector::length(&amount_cur));
                cursor::destroy_empty(cur);

                let to_bytes = vector::empty<u8>();
                let i = 30;
                while (i < 50) {
                        let value = vector::borrow(&payload_un, i);
                        vector::push_back(&mut to_bytes, *value);
                        i = i + 1;
                };
                let to = object::address_from_bytes(to_bytes);

                let tx_cur = vector::empty<u8>();
                let i = 50;
                while (i < 80) {
                        let value = vector::borrow(&payload_un, i);
                        vector::push_back(&mut tx_cur, *value);
                        i = i + 1;
                };
                let cur = cursor::create(tx_cur);
                let tx_id = deserialize_u128(&mut cur, vector::length(&tx_cur));
                cursor::destroy_empty(cur);

                let payload = Payload {
                        time: time,
                        who: who,
                        amount: amount,
                        to: to,
                };

                let confirm: bool = ecrecover_to_eth_address(signature, messageHash, Guardian_address);

                let baa = BAA {
                        id: object::new(ctx),
                        guardian: guardian,
                        sig_len: sig_len,
                        payload: payload,
                        tx: tx_cur,
                        tx_id: tx_id,
                        messageHash: messageHash,
                        signature: signature,
                        confirm: confirm,
                };

                assert!(!dynamic_object_field::exists_with_type<u128, BAA>(&pool.id, tx_id), 1);
                dynamic_object_field::add(&mut pool.id, tx_id, baa);
                lock::mint_and_transfer<WPETH>(lock, amount, to, ctx);
        }

        public entry fun createBAA<WPETH>(lock: &mut TreasuryLock<WPETH>, c: Coin<WPETH>, _to: address, ctx: &mut TxContext){
                event::emit(EmitBAA<WPETH> {
                        _sender: tx_context::sender(ctx),
                        _amount: coin::value(&c),
                        _to: _to,
                });
                lock::burn<WPETH>(lock, c, ctx);
        }

        

}

#[test_only]
module portal::test {
        /*use portal::portal::{Self, PoolBAA};
        const ADMIN: address = @0x6e7BEa5B3247138621E5693ceb0e6b25ebc48Fc9;
        #[test]
        fun verifyBAA() {
                use sui::test_scenario;
                let scenario_val = test_scenario::begin(ADMIN);
                let scenario = &mut scenario_val;
                portal::create_pool(test_scenario::ctx(scenario));
                test_scenario::next_tx(scenario, ADMIN);
                let pool = test_scenario::take_shared<PoolBAA>(scenario);
                let poolMut = &mut pool;
                portal::verifyBAA(poolMut, x"6e7BEa5B3247138621E5693ceb0e6b25ebc48Fc900000084006386feda6e7BEa5B3247138621E5693ceb0e6b25ebc48Fc904e3b2920012c68650c8ae861cbbe81a2916de32454afbc141b7b63bfa7e9a2c228f9f61e15346e5a61606051c48d46638d56aae766ce619e0c15a6dc78b417d82404805eb6ec74af4f2bf8c37f42fbb97197cbbb6e175c55d14f35bc243ff15d7a6fa7b299371f0dd5faeb922480412939c20fbf965ed40462c9a8b349acaaa525fbf258f4eccd2f372b176762545472e82e8d039b5bfd3091b", test_scenario::ctx(scenario));
                test_scenario::return_shared(pool);
                test_scenario::end(scenario_val);
        }*/
}