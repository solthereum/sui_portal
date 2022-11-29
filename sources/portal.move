module portal::portal {
        use sui::ecdsa;
        use std::vector;
        use sui::object::{Self, UID};
        use sui::transfer;
        use sui::tx_context::{Self, TxContext};
        use std::debug;

        struct Payload has store, key {
                id: UID,
                time: vector<u8>,
                who: vector<u8>,
                amount: vector<u8>,
                to: vector<u8>,
        }

        struct BAA has store, key {
                id: UID,
                guardian: vector<u8>,
                sig_len: vector<u8>,
                payload: Payload,
                messageHash: vector<u8>,
                signature: vector<u8>,
                confirm: bool
        }

        struct PoolBAA has key {
                id: UID,
        }

        fun init(_: address, ctx: &mut TxContext) {
                let pool = PoolBAA {
                        id: object::new(ctx),
                };
                transfer::share_object(pool);
        }

        public fun ecrecover_to_eth_address(signature: vector<u8>, hashed_msg: vector<u8>, addres: vector<u8>): bool {
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

                (addr == addres)

        }

        public entry fun verifyBAA(baa: vector<u8>, ctx: &mut TxContext) {
                let guardian = vector::empty<u8>();
                let i = 0;
                while (i < 20) {
                        let value = vector::borrow(&baa, i);
                        vector::push_back(&mut guardian, *value);
                        i = i + 1;
                };

                let sig_len = vector::empty<u8>();
                let i = 23;
                while (i < 24) {
                        let value = vector::borrow(&baa, i);
                        vector::push_back(&mut sig_len, *value);
                        i = i + 1;
                };

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

                let time = vector::empty<u8>();
                let i = 0;
                while (i < 5) {
                        let value = vector::borrow(&payload_un, i);
                        vector::push_back(&mut time, *value);
                        i = i + 1;
                };

                let who = vector::empty<u8>();
                let i = 5;
                while (i < 25) {
                        let value = vector::borrow(&payload_un, i);
                        vector::push_back(&mut who, *value);
                        i = i + 1;
                };

                let amount = vector::empty<u8>();
                let i = 25;
                while (i < 30) {
                        let value = vector::borrow(&payload_un, i);
                        vector::push_back(&mut amount, *value);
                        i = i + 1;
                };

                let to = vector::empty<u8>();
                let i = 30;
                while (i < 50) {
                        let value = vector::borrow(&payload_un, i);
                        vector::push_back(&mut to, *value);
                        i = i + 1;
                };

                let tx = vector::empty<u8>();
                let i = 50;
                while (i < 80) {
                        let value = vector::borrow(&payload_un, i);
                        vector::push_back(&mut tx, *value);
                        i = i + 1;
                };

                let payload = Payload {
                        id: object::new(ctx),
                        time: time,
                        who: who,
                        amount: amount,
                        to: to,
                };
                let confirm: bool = ecrecover_to_eth_address(signature, messageHash, guardian);

                let baa = BAA {
                        id: object::new(ctx),
                        guardian: guardian,
                        sig_len: sig_len,
                        payload: payload,
                        messageHash: messageHash,
                        signature: signature,
                        confirm: confirm,
                };
                transfer::transfer(baa, tx_context::sender(ctx));
        }


}

#[test_only]
module portal::test {
        use portal::portal::{Self};

        const ADMIN: address = @0x6e7BEa5B3247138621E5693ceb0e6b25ebc48Fc9;
        #[test]
        fun verify_baa() {
                use sui::test_scenario;
                let scenario_val = test_scenario::begin(ADMIN);
                let scenario = &mut scenario_val;
                portal::verify_baa(x"6e7BEa5B3247138621E5693ceb0e6b25ebc48Fc900000084006385942b6e7BEa5B3247138621E5693ceb0e6b25ebc48Fc904e3b2920012c68650c8ae861cbbe81a2916de32454afbc141b7b63bfa7e9a2c228f9f61e15346e5a61606051c48d46638d56aae766ce619e01634706f76b32b932b266e6f7e7c4922e117fcf6fdf2fcd601a79a9700edf5bd62a20e9ed8cd0bdbec818bcf34a83e62b5d9258046e1f2ac65e31b03b6b3d0d776ef88478989fae5d312b9b12b315139dffb984f87c00f1cc196dd75b365952d1c", test_scenario::ctx(scenario));
                test_scenario::end(scenario_val);
        }
}