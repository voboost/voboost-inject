//! Fixed resident paths and bounds shared with the injector.
pub(crate) use voboost_contract::runtime_owner::OWNER_PID_NAME as PID_NAME;
pub(crate) use voboost_contract::runtime_owner::{
    LOG_DIR, MAX_NATIVE_EXECUTABLE_BYTES, ROOT_ZONE, RUN_DIR, RUN_DIR_MODE,
};

#[cfg(test)]
pub(crate) use voboost_contract::runtime_owner::STATE_DIR;
