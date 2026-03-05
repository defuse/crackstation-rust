use std::sync::Arc;

use crate::libs::PhpCountService;
use preimage::PreimageOracle;

/// Holds shared application state: hit counter and hash cracking oracle.
#[derive(Clone)]
pub struct AppState {
    pub phpcount: PhpCountService,
    pub oracle: Arc<PreimageOracle>,
}

impl AppState {
    pub fn new(phpcount: PhpCountService, oracle: PreimageOracle) -> Self {
        Self {
            phpcount,
            oracle: Arc::new(oracle),
        }
    }
}
