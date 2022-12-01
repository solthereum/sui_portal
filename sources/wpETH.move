module portal::wpETH {
    use sui::tx_context::{TxContext};
    use sui::coin;
    use portal::lock::creator_lock;

    struct WPETH has drop {

    }

    fun init(witness: WPETH, ctx: &mut TxContext) {
        let treasury_cap = coin::create_currency(
                witness,
                8,
                ctx
        );
        creator_lock(treasury_cap, ctx)
    }
}