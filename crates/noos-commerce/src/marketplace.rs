//! Immutable unique-asset identity, ownership, royalty, and marketplace laws.
//!
//! One canonical asset can have at most one owner and one active listing.
//! Purchases move an existing payment balance atomically among seller, royalty
//! recipient, and treasury; no sale mints value. Listing cancellation, expiry,
//! direct transfer, replay, and price substitution are explicit transitions.

use crate::{domain_hash, Hash32};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_ROYALTY_BPS: u16 = 1_500;
pub const MAX_PROTOCOL_FEE_BPS: u16 = 500;
pub const MAX_UNIQUE_ASSETS: usize = 1_000_000;
pub const MAX_MARKET_LISTINGS: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarketplaceError {
    InvalidPolicy,
    InvalidAsset,
    DuplicateAsset,
    UnknownAsset,
    InvalidListing,
    DuplicateListing,
    UnknownListing,
    AlreadyListed,
    NotOwner,
    Unauthorized,
    ListingInactive,
    ListingExpired,
    PriceChanged,
    InsufficientBalance,
    TooManyRecords,
    ArithmeticOverflow,
    ConservationFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarketplacePolicy {
    pub treasury: Hash32,
    pub protocol_fee_bps: u16,
    pub maximum_price: u128,
    pub maximum_listing_blocks: u64,
}

impl MarketplacePolicy {
    pub fn validate(self) -> Result<(), MarketplaceError> {
        if self.treasury == [0; 32]
            || self.protocol_fee_bps > MAX_PROTOCOL_FEE_BPS
            || self.maximum_price == 0
            || self.maximum_listing_blocks == 0
        {
            return Err(MarketplaceError::InvalidPolicy);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UniqueAsset {
    pub asset_id: Hash32,
    pub publisher: Hash32,
    pub collection_root: Hash32,
    pub content_root: Hash32,
    pub metadata_root: Hash32,
    pub serial: u64,
    pub royalty_recipient: Hash32,
    pub royalty_bps: u16,
    pub owner: Hash32,
    pub ownership_nonce: u64,
}

impl UniqueAsset {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        publisher: Hash32,
        collection_root: Hash32,
        content_root: Hash32,
        metadata_root: Hash32,
        serial: u64,
        royalty_recipient: Hash32,
        royalty_bps: u16,
        owner: Hash32,
    ) -> Result<Self, MarketplaceError> {
        if [
            publisher,
            collection_root,
            content_root,
            metadata_root,
            royalty_recipient,
            owner,
        ]
        .contains(&[0; 32])
            || serial == 0
            || royalty_bps > MAX_ROYALTY_BPS
        {
            return Err(MarketplaceError::InvalidAsset);
        }
        let asset_id = unique_asset_id(&publisher, &collection_root, &content_root, serial);
        Ok(Self {
            asset_id,
            publisher,
            collection_root,
            content_root,
            metadata_root,
            serial,
            royalty_recipient,
            royalty_bps,
            owner,
            ownership_nonce: 1,
        })
    }

    fn validate(&self) -> Result<(), MarketplaceError> {
        if self.asset_id
            != unique_asset_id(
                &self.publisher,
                &self.collection_root,
                &self.content_root,
                self.serial,
            )
            || [
                self.publisher,
                self.collection_root,
                self.content_root,
                self.metadata_root,
                self.royalty_recipient,
                self.owner,
            ]
            .contains(&[0; 32])
            || self.serial == 0
            || self.royalty_bps > MAX_ROYALTY_BPS
            || self.ownership_nonce == 0
        {
            return Err(MarketplaceError::InvalidAsset);
        }
        Ok(())
    }
}

#[must_use]
pub fn unique_asset_id(
    publisher: &Hash32,
    collection_root: &Hash32,
    content_root: &Hash32,
    serial: u64,
) -> Hash32 {
    domain_hash(
        "NOOS/UNIQUE-ASSET/ID/V1",
        &[
            publisher,
            collection_root,
            content_root,
            &serial.to_le_bytes(),
        ],
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListingStatus {
    Active,
    Sold,
    Cancelled,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarketListing {
    pub listing_id: Hash32,
    pub asset_id: Hash32,
    pub seller: Hash32,
    pub ownership_nonce: u64,
    pub payment_asset: Hash32,
    pub price: u128,
    pub created_height: u64,
    pub expires_height: u64,
    pub status: ListingStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnershipTransition {
    pub asset_id: Hash32,
    pub from: Hash32,
    pub to: Hash32,
    pub prior_nonce: u64,
    pub next_nonce: u64,
    pub listing_id: Option<Hash32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SaleSettlement {
    pub listing_id: Hash32,
    pub asset_id: Hash32,
    pub payment_asset: Hash32,
    pub buyer: Hash32,
    pub seller: Hash32,
    pub gross_price: u128,
    pub seller_proceeds: u128,
    pub royalty_recipient: Hash32,
    pub royalty_amount: u128,
    pub treasury: Hash32,
    pub protocol_fee: u128,
    pub ownership: OwnershipTransition,
}

impl SaleSettlement {
    pub fn validate(self) -> Result<(), MarketplaceError> {
        let distributed = self
            .seller_proceeds
            .checked_add(self.royalty_amount)
            .and_then(|value| value.checked_add(self.protocol_fee))
            .ok_or(MarketplaceError::ArithmeticOverflow)?;
        if distributed != self.gross_price
            || [
                self.listing_id,
                self.asset_id,
                self.payment_asset,
                self.buyer,
                self.seller,
                self.royalty_recipient,
                self.treasury,
            ]
            .contains(&[0; 32])
            || self.buyer == self.seller
            || self.ownership.asset_id != self.asset_id
            || self.ownership.from != self.seller
            || self.ownership.to != self.buyer
            || self.ownership.listing_id != Some(self.listing_id)
        {
            return Err(MarketplaceError::ConservationFailure);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentConservation {
    pub payment_asset: Hash32,
    pub external_inflows: u128,
    pub external_outflows: u128,
    pub internal_balances: u128,
}

impl PaymentConservation {
    pub fn validate(self) -> Result<(), MarketplaceError> {
        if self.payment_asset == [0; 32]
            || self.external_inflows
                != self
                    .external_outflows
                    .checked_add(self.internal_balances)
                    .ok_or(MarketplaceError::ArithmeticOverflow)?
        {
            return Err(MarketplaceError::ConservationFailure);
        }
        Ok(())
    }
}

pub struct Marketplace {
    policy: MarketplacePolicy,
    assets: BTreeMap<Hash32, UniqueAsset>,
    listings: BTreeMap<Hash32, MarketListing>,
    active_listing_by_asset: BTreeMap<Hash32, Hash32>,
    ownership_history: BTreeMap<Hash32, Vec<OwnershipTransition>>,
    balances: BTreeMap<(Hash32, Hash32), u128>,
    external_inflows: BTreeMap<Hash32, u128>,
    external_outflows: BTreeMap<Hash32, u128>,
}

impl Marketplace {
    pub fn new(policy: MarketplacePolicy) -> Result<Self, MarketplaceError> {
        policy.validate()?;
        Ok(Self {
            policy,
            assets: BTreeMap::new(),
            listings: BTreeMap::new(),
            active_listing_by_asset: BTreeMap::new(),
            ownership_history: BTreeMap::new(),
            balances: BTreeMap::new(),
            external_inflows: BTreeMap::new(),
            external_outflows: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn asset(&self, asset_id: &Hash32) -> Option<&UniqueAsset> {
        self.assets.get(asset_id)
    }

    #[must_use]
    pub fn listing(&self, listing_id: &Hash32) -> Option<&MarketListing> {
        self.listings.get(listing_id)
    }

    #[must_use]
    pub fn ownership_history(&self, asset_id: &Hash32) -> &[OwnershipTransition] {
        self.ownership_history
            .get(asset_id)
            .map_or(&[], Vec::as_slice)
    }

    #[must_use]
    pub fn balance(&self, account: Hash32, payment_asset: Hash32) -> u128 {
        *self.balances.get(&(account, payment_asset)).unwrap_or(&0)
    }

    pub fn deposit(
        &mut self,
        account: Hash32,
        payment_asset: Hash32,
        amount: u128,
    ) -> Result<(), MarketplaceError> {
        if account == [0; 32] || payment_asset == [0; 32] || amount == 0 {
            return Err(MarketplaceError::InvalidAsset);
        }
        self.payment_conservation(payment_asset)?.validate()?;
        let next_balance = self
            .balance(account, payment_asset)
            .checked_add(amount)
            .ok_or(MarketplaceError::ArithmeticOverflow)?;
        let next_inflow = self
            .external_inflows
            .get(&payment_asset)
            .copied()
            .unwrap_or(0)
            .checked_add(amount)
            .ok_or(MarketplaceError::ArithmeticOverflow)?;
        self.balances.insert((account, payment_asset), next_balance);
        self.external_inflows.insert(payment_asset, next_inflow);
        Ok(())
    }

    pub fn withdraw(
        &mut self,
        account: Hash32,
        payment_asset: Hash32,
        amount: u128,
    ) -> Result<(), MarketplaceError> {
        if account == [0; 32] || payment_asset == [0; 32] || amount == 0 {
            return Err(MarketplaceError::InvalidAsset);
        }
        self.payment_conservation(payment_asset)?.validate()?;
        let next_balance = self
            .balance(account, payment_asset)
            .checked_sub(amount)
            .ok_or(MarketplaceError::InsufficientBalance)?;
        let next_outflow = self
            .external_outflows
            .get(&payment_asset)
            .copied()
            .unwrap_or(0)
            .checked_add(amount)
            .ok_or(MarketplaceError::ArithmeticOverflow)?;
        self.balances.insert((account, payment_asset), next_balance);
        self.external_outflows.insert(payment_asset, next_outflow);
        Ok(())
    }

    pub fn register(&mut self, asset: UniqueAsset) -> Result<Hash32, MarketplaceError> {
        asset.validate()?;
        let id = asset.asset_id;
        if self.assets.contains_key(&id) {
            return Err(MarketplaceError::DuplicateAsset);
        }
        if self.assets.len() >= MAX_UNIQUE_ASSETS {
            return Err(MarketplaceError::TooManyRecords);
        }
        self.assets.insert(id, asset);
        self.ownership_history.insert(id, Vec::new());
        Ok(id)
    }

    pub fn transfer(
        &mut self,
        asset_id: Hash32,
        owner: Hash32,
        recipient: Hash32,
    ) -> Result<OwnershipTransition, MarketplaceError> {
        if recipient == [0; 32] || recipient == owner {
            return Err(MarketplaceError::InvalidAsset);
        }
        if self.active_listing_by_asset.contains_key(&asset_id) {
            return Err(MarketplaceError::AlreadyListed);
        }
        self.transfer_internal(asset_id, owner, recipient, None)
    }

    pub fn list(
        &mut self,
        asset_id: Hash32,
        seller: Hash32,
        payment_asset: Hash32,
        price: u128,
        created_height: u64,
        expires_height: u64,
    ) -> Result<Hash32, MarketplaceError> {
        if payment_asset == [0; 32]
            || price == 0
            || price > self.policy.maximum_price
            || expires_height <= created_height
            || expires_height.saturating_sub(created_height) > self.policy.maximum_listing_blocks
        {
            return Err(MarketplaceError::InvalidListing);
        }
        let asset = self
            .assets
            .get(&asset_id)
            .ok_or(MarketplaceError::UnknownAsset)?;
        if asset.owner != seller {
            return Err(MarketplaceError::NotOwner);
        }
        if self.active_listing_by_asset.contains_key(&asset_id) {
            return Err(MarketplaceError::AlreadyListed);
        }
        if self.listings.len() >= MAX_MARKET_LISTINGS {
            return Err(MarketplaceError::TooManyRecords);
        }
        let listing_id = listing_id(
            &asset_id,
            &seller,
            asset.ownership_nonce,
            &payment_asset,
            price,
            expires_height,
        );
        if self.listings.contains_key(&listing_id) {
            return Err(MarketplaceError::DuplicateListing);
        }
        let listing = MarketListing {
            listing_id,
            asset_id,
            seller,
            ownership_nonce: asset.ownership_nonce,
            payment_asset,
            price,
            created_height,
            expires_height,
            status: ListingStatus::Active,
        };
        self.listings.insert(listing_id, listing);
        self.active_listing_by_asset.insert(asset_id, listing_id);
        Ok(listing_id)
    }

    pub fn cancel(&mut self, listing_id: Hash32, seller: Hash32) -> Result<(), MarketplaceError> {
        let listing = self
            .listings
            .get_mut(&listing_id)
            .ok_or(MarketplaceError::UnknownListing)?;
        if listing.seller != seller {
            return Err(MarketplaceError::Unauthorized);
        }
        if listing.status != ListingStatus::Active {
            return Err(MarketplaceError::ListingInactive);
        }
        listing.status = ListingStatus::Cancelled;
        self.active_listing_by_asset.remove(&listing.asset_id);
        Ok(())
    }

    pub fn expire(
        &mut self,
        listing_id: Hash32,
        current_height: u64,
    ) -> Result<(), MarketplaceError> {
        let listing = self
            .listings
            .get_mut(&listing_id)
            .ok_or(MarketplaceError::UnknownListing)?;
        if listing.status != ListingStatus::Active || current_height <= listing.expires_height {
            return Err(MarketplaceError::ListingInactive);
        }
        listing.status = ListingStatus::Expired;
        self.active_listing_by_asset.remove(&listing.asset_id);
        Ok(())
    }

    pub fn buy(
        &mut self,
        listing_id: Hash32,
        buyer: Hash32,
        expected_payment_asset: Hash32,
        maximum_price: u128,
        current_height: u64,
    ) -> Result<SaleSettlement, MarketplaceError> {
        let listing = *self
            .listings
            .get(&listing_id)
            .ok_or(MarketplaceError::UnknownListing)?;
        if listing.status != ListingStatus::Active {
            return Err(MarketplaceError::ListingInactive);
        }
        if current_height > listing.expires_height {
            return Err(MarketplaceError::ListingExpired);
        }
        if buyer == [0; 32] || buyer == listing.seller {
            return Err(MarketplaceError::InvalidListing);
        }
        if expected_payment_asset != listing.payment_asset || maximum_price < listing.price {
            return Err(MarketplaceError::PriceChanged);
        }
        let asset = self
            .assets
            .get(&listing.asset_id)
            .ok_or(MarketplaceError::UnknownAsset)?;
        if asset.owner != listing.seller || asset.ownership_nonce != listing.ownership_nonce {
            return Err(MarketplaceError::NotOwner);
        }
        if self.active_listing_by_asset.get(&listing.asset_id) != Some(&listing_id)
            || !self.ownership_history.contains_key(&listing.asset_id)
        {
            return Err(MarketplaceError::InvalidListing);
        }
        let royalty_recipient = asset.royalty_recipient;
        let next_ownership_nonce = asset
            .ownership_nonce
            .checked_add(1)
            .ok_or(MarketplaceError::ArithmeticOverflow)?;
        let royalty = mul_bps(listing.price, asset.royalty_bps)?;
        let protocol_fee = mul_bps(listing.price, self.policy.protocol_fee_bps)?;
        let seller_proceeds = listing
            .price
            .checked_sub(royalty)
            .and_then(|value| value.checked_sub(protocol_fee))
            .ok_or(MarketplaceError::ArithmeticOverflow)?;
        self.payment_conservation(listing.payment_asset)?
            .validate()?;

        let mut payment_changes = [([0; 32], 0_u128, 0_u128); 4];
        let mut payment_change_count = 0_usize;
        for (account, debit, credit) in [
            (buyer, listing.price, 0),
            (listing.seller, 0, seller_proceeds),
            (royalty_recipient, 0, royalty),
            (self.policy.treasury, 0, protocol_fee),
        ] {
            if let Some(index) = payment_changes[..payment_change_count]
                .iter()
                .position(|change| change.0 == account)
            {
                payment_changes[index].1 = payment_changes[index]
                    .1
                    .checked_add(debit)
                    .ok_or(MarketplaceError::ArithmeticOverflow)?;
                payment_changes[index].2 = payment_changes[index]
                    .2
                    .checked_add(credit)
                    .ok_or(MarketplaceError::ArithmeticOverflow)?;
            } else {
                payment_changes[payment_change_count] = (account, debit, credit);
                payment_change_count += 1;
            }
        }
        let mut next_balances = [([0; 32], 0_u128); 4];
        for (index, (account, debit, credit)) in payment_changes[..payment_change_count]
            .iter()
            .copied()
            .enumerate()
        {
            let next_balance = self
                .balance(account, listing.payment_asset)
                .checked_sub(debit)
                .ok_or(MarketplaceError::InsufficientBalance)?
                .checked_add(credit)
                .ok_or(MarketplaceError::ArithmeticOverflow)?;
            next_balances[index] = (account, next_balance);
        }

        let ownership = OwnershipTransition {
            asset_id: listing.asset_id,
            from: listing.seller,
            to: buyer,
            prior_nonce: listing.ownership_nonce,
            next_nonce: next_ownership_nonce,
            listing_id: Some(listing_id),
        };
        let settlement = SaleSettlement {
            listing_id,
            asset_id: listing.asset_id,
            payment_asset: listing.payment_asset,
            buyer,
            seller: listing.seller,
            gross_price: listing.price,
            seller_proceeds,
            royalty_recipient,
            royalty_amount: royalty,
            treasury: self.policy.treasury,
            protocol_fee,
            ownership,
        };
        settlement.validate()?;

        let asset = self
            .assets
            .get_mut(&listing.asset_id)
            .ok_or(MarketplaceError::UnknownAsset)?;
        let history = self
            .ownership_history
            .get_mut(&listing.asset_id)
            .ok_or(MarketplaceError::UnknownAsset)?;
        let stored = self
            .listings
            .get_mut(&listing_id)
            .ok_or(MarketplaceError::UnknownListing)?;
        asset.owner = buyer;
        asset.ownership_nonce = next_ownership_nonce;
        history.push(ownership);
        stored.status = ListingStatus::Sold;
        self.active_listing_by_asset.remove(&listing.asset_id);
        for (account, balance) in next_balances[..payment_change_count].iter().copied() {
            self.balances
                .insert((account, listing.payment_asset), balance);
        }
        Ok(settlement)
    }

    pub fn payment_conservation(
        &self,
        payment_asset: Hash32,
    ) -> Result<PaymentConservation, MarketplaceError> {
        let internal_balances = self
            .balances
            .iter()
            .filter(|((_, asset), _)| *asset == payment_asset)
            .try_fold(0_u128, |total, (_, balance)| {
                total
                    .checked_add(*balance)
                    .ok_or(MarketplaceError::ArithmeticOverflow)
            })?;
        Ok(PaymentConservation {
            payment_asset,
            external_inflows: *self.external_inflows.get(&payment_asset).unwrap_or(&0),
            external_outflows: *self.external_outflows.get(&payment_asset).unwrap_or(&0),
            internal_balances,
        })
    }

    pub fn validate(&self) -> Result<(), MarketplaceError> {
        self.policy.validate()?;
        for (id, asset) in &self.assets {
            asset.validate()?;
            if id != &asset.asset_id {
                return Err(MarketplaceError::InvalidAsset);
            }
            let active = self.active_listing_by_asset.get(id);
            if let Some(listing_id) = active {
                let listing = self
                    .listings
                    .get(listing_id)
                    .ok_or(MarketplaceError::UnknownListing)?;
                if listing.asset_id != *id || listing.status != ListingStatus::Active {
                    return Err(MarketplaceError::InvalidListing);
                }
            }
        }
        let payment_assets = self
            .external_inflows
            .keys()
            .chain(self.external_outflows.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        for payment_asset in payment_assets {
            self.payment_conservation(payment_asset)?.validate()?;
        }
        Ok(())
    }

    fn transfer_internal(
        &mut self,
        asset_id: Hash32,
        owner: Hash32,
        recipient: Hash32,
        listing_id: Option<Hash32>,
    ) -> Result<OwnershipTransition, MarketplaceError> {
        let asset = self
            .assets
            .get_mut(&asset_id)
            .ok_or(MarketplaceError::UnknownAsset)?;
        if asset.owner != owner {
            return Err(MarketplaceError::NotOwner);
        }
        let prior_nonce = asset.ownership_nonce;
        let next_nonce = prior_nonce
            .checked_add(1)
            .ok_or(MarketplaceError::ArithmeticOverflow)?;
        let history = self
            .ownership_history
            .get_mut(&asset_id)
            .ok_or(MarketplaceError::UnknownAsset)?;
        let transition = OwnershipTransition {
            asset_id,
            from: owner,
            to: recipient,
            prior_nonce,
            next_nonce,
            listing_id,
        };
        asset.owner = recipient;
        asset.ownership_nonce = next_nonce;
        history.push(transition);
        Ok(transition)
    }
}

#[must_use]
pub fn listing_id(
    asset_id: &Hash32,
    seller: &Hash32,
    ownership_nonce: u64,
    payment_asset: &Hash32,
    price: u128,
    expires_height: u64,
) -> Hash32 {
    domain_hash(
        "NOOS/UNIQUE-ASSET/LISTING/V1",
        &[
            asset_id,
            seller,
            &ownership_nonce.to_le_bytes(),
            payment_asset,
            &price.to_le_bytes(),
            &expires_height.to_le_bytes(),
        ],
    )
}

fn mul_bps(value: u128, bps: u16) -> Result<u128, MarketplaceError> {
    value
        .checked_mul(u128::from(bps))
        .and_then(|product| product.checked_div(u128::from(10_000_u16)))
        .ok_or(MarketplaceError::ArithmeticOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn market() -> Marketplace {
        Marketplace::new(MarketplacePolicy {
            treasury: h(90),
            protocol_fee_bps: 250,
            maximum_price: 1_000_000,
            maximum_listing_blocks: 100,
        })
        .unwrap()
    }

    fn asset(owner: Hash32) -> UniqueAsset {
        UniqueAsset::new(h(1), h(2), h(3), h(4), 1, h(5), 1_000, owner).unwrap()
    }

    #[test]
    fn sale_moves_one_owner_and_conserves_price_with_royalty() {
        let mut market = market();
        let seller = h(10);
        let buyer = h(11);
        let payment = h(12);
        let asset_id = market.register(asset(seller)).unwrap();
        market.deposit(buyer, payment, 100_000).unwrap();
        let listing = market
            .list(asset_id, seller, payment, 100_000, 10, 100)
            .unwrap();
        let sale = market.buy(listing, buyer, payment, 100_000, 50).unwrap();
        assert_eq!(sale.royalty_amount, 10_000);
        assert_eq!(sale.protocol_fee, 2_500);
        assert_eq!(sale.seller_proceeds, 87_500);
        assert_eq!(market.asset(&asset_id).unwrap().owner, buyer);
        assert_eq!(market.balance(seller, payment), 87_500);
        assert_eq!(market.balance(h(5), payment), 10_000);
        assert_eq!(market.balance(h(90), payment), 2_500);
        assert_eq!(market.balance(buyer, payment), 0);
        assert_eq!(
            market.listing(&listing).unwrap().status,
            ListingStatus::Sold
        );
        market.validate().unwrap();
    }

    #[test]
    fn duplicate_identity_unauthorized_transfer_and_price_substitution_reject() {
        let mut market = market();
        let seller = h(10);
        let buyer = h(11);
        let payment = h(12);
        let unique = asset(seller);
        let mut collision = unique.clone();
        collision.owner = h(77);
        let asset_id = market.register(unique).unwrap();
        assert_eq!(
            market.register(collision),
            Err(MarketplaceError::DuplicateAsset)
        );
        assert_eq!(market.asset(&asset_id).unwrap().owner, seller);
        assert_eq!(
            market.transfer(asset_id, h(99), buyer),
            Err(MarketplaceError::NotOwner)
        );
        let listing = market
            .list(asset_id, seller, payment, 100_000, 10, 100)
            .unwrap();
        market.deposit(buyer, payment, 100_000).unwrap();
        assert_eq!(
            market.buy(listing, buyer, h(13), 100_000, 50),
            Err(MarketplaceError::PriceChanged)
        );
        assert_eq!(
            market.buy(listing, buyer, payment, 99_999, 50),
            Err(MarketplaceError::PriceChanged)
        );
        assert_eq!(market.asset(&asset_id).unwrap().owner, seller);
    }

    #[test]
    fn listing_cancel_expiry_and_direct_transfer_are_explicit() {
        let mut market = market();
        let seller = h(10);
        let buyer = h(11);
        let asset_id = market.register(asset(seller)).unwrap();
        let first = market.list(asset_id, seller, h(12), 100, 10, 20).unwrap();
        assert_eq!(
            market.cancel(first, h(99)),
            Err(MarketplaceError::Unauthorized)
        );
        market.cancel(first, seller).unwrap();
        let transition = market.transfer(asset_id, seller, buyer).unwrap();
        assert_eq!(transition.prior_nonce, 1);
        assert_eq!(transition.next_nonce, 2);

        let second = market.list(asset_id, buyer, h(12), 100, 30, 40).unwrap();
        assert_eq!(
            market.expire(second, 40),
            Err(MarketplaceError::ListingInactive)
        );
        market.expire(second, 41).unwrap();
        assert_eq!(
            market.listing(&second).unwrap().status,
            ListingStatus::Expired
        );
        assert_eq!(market.ownership_history(&asset_id).len(), 1);
    }

    #[test]
    fn insufficient_payment_and_sold_listing_replay_are_atomic() {
        let mut market = market();
        let seller = h(10);
        let buyer = h(11);
        let payment = h(12);
        let asset_id = market.register(asset(seller)).unwrap();
        let listing = market
            .list(asset_id, seller, payment, 1_000, 10, 20)
            .unwrap();
        market.deposit(buyer, payment, 999).unwrap();
        assert_eq!(
            market.buy(listing, buyer, payment, 1_000, 15),
            Err(MarketplaceError::InsufficientBalance)
        );
        assert_eq!(market.asset(&asset_id).unwrap().owner, seller);
        market.deposit(buyer, payment, 1).unwrap();
        market.buy(listing, buyer, payment, 1_000, 15).unwrap();
        assert_eq!(
            market.buy(listing, h(13), payment, 1_000, 15),
            Err(MarketplaceError::ListingInactive)
        );
        market.validate().unwrap();
    }

    #[test]
    fn arithmetic_failures_leave_payments_and_ownership_unchanged() {
        let mut overflow_market = market();
        let payment = h(12);
        overflow_market.deposit(h(10), payment, u128::MAX).unwrap();
        assert_eq!(
            overflow_market.deposit(h(11), payment, 1),
            Err(MarketplaceError::ArithmeticOverflow)
        );
        assert_eq!(overflow_market.balance(h(11), payment), 0);
        overflow_market.validate().unwrap();

        let mut nonce_market = market();
        let seller = h(20);
        let buyer = h(21);
        let mut unique = asset(seller);
        unique.ownership_nonce = u64::MAX;
        let asset_id = nonce_market.register(unique).unwrap();
        nonce_market.deposit(buyer, payment, 1_000).unwrap();
        let listing = nonce_market
            .list(asset_id, seller, payment, 1_000, 10, 20)
            .unwrap();
        assert_eq!(
            nonce_market.buy(listing, buyer, payment, 1_000, 15),
            Err(MarketplaceError::ArithmeticOverflow)
        );
        assert_eq!(nonce_market.balance(buyer, payment), 1_000);
        assert_eq!(nonce_market.balance(seller, payment), 0);
        assert_eq!(nonce_market.asset(&asset_id).unwrap().owner, seller);
        assert_eq!(
            nonce_market.listing(&listing).unwrap().status,
            ListingStatus::Active
        );
    }

    #[test]
    fn withdrawal_preserves_external_payment_accounting() {
        let mut market = market();
        let payment = h(12);
        market.deposit(h(10), payment, 5_000).unwrap();
        market.withdraw(h(10), payment, 2_000).unwrap();
        let report = market.payment_conservation(payment).unwrap();
        assert_eq!(report.external_inflows, 5_000);
        assert_eq!(report.external_outflows, 2_000);
        assert_eq!(report.internal_balances, 3_000);
        report.validate().unwrap();
    }
}
