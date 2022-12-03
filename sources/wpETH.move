module portal::wpETH {
    use sui::tx_context::{TxContext};
    use sui::coin;
    use std::option;
    use sui::transfer;
    use portal::lock::creator_lock;

    struct WPETH has drop {

    }

    fun init(witness: WPETH, ctx: &mut TxContext) {

        let (treasury, metadata) = coin::create_currency(witness, 8, b"wpETH", b"", b"", option::none(), ctx);
        transfer::freeze_object(metadata);
        creator_lock<WPETH>(treasury, ctx)
    }
}